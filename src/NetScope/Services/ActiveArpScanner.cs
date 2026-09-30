using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetScope.Interop;
using NetScope.Models;

namespace NetScope.Services;

/// <summary>
/// F9/F11/F52/F53：单发送线程 + 可配间隔（15–90ms）+ 异步收应答（由 PassiveSniffer 入映射表）。
/// 设备存在性判定统一以映射表为准：ProbeAsync 发送后轮询 isPresent 谓词（映射表是否已学到目标），
/// 不再维护独立的"已发未回"登记表——后者会跨网段累积且只认 ARP reply 一种报文。
/// 冒用冲突检测：request 以空闲地址作 sender 期间，收到任意外部报文宣告同一 IP 但 MAC 非本机
/// → 该地址实际被静默设备占用，ScanAsync 立即中断返回，由编排层换址。
/// </summary>
public class ActiveArpScanner : IDisposable
{
    private IntPtr _sendHandle;
    private CancellationTokenSource? _cts;
    private readonly ManualResetEventSlim _pauseGate = new(true);
    private Task? _task;

    public int IntervalMs { get; set; } = 15;

    /// <summary>扫描进度：当前发送目标 IP / sender IP / 已发送数 / 当前段总数 / 段索引 / 总段数。</summary>
    public event Action<IPAddress, IPAddress, int, int, int, int>? Progress;
    public event Action<string>? Error;

    // 冒用 sender 冲突检测：_watchedSender = 当前正在冒用的 sender IP；_ownMac = 当前发送/监听网卡 MAC
    private readonly object _senderLock = new();
    private IPAddress? _watchedSender;
    private IPAddress? _conflictIp;
    private MacAddress _ownMac;

    /// <summary>设置当前发送与监听网卡的 MAC（PrepareActive 时调用），用于冒用冲突判定。</summary>
    public void SetOwnMac(MacAddress mac) => _ownMac = mac;

    /// <summary>登记/清除当前正在冒用的 sender IP。每个子网段开始时清除（段间状态隔离，F52 ⑤）。</summary>
    public void SetWatchedSender(IPAddress? ip)
    {
        lock (_senderLock) { _watchedSender = ip; _conflictIp = null; }
    }

    /// <summary>由 MapperService.AddObservation 经 IpMacObserved 回调统一调用（全协议 IP-MAC 对）：
    /// 若该 IP 与当前冒用地址相同、且 MAC 非本机网卡 MAC → 该地址被静默设备占用。</summary>
    public void NoteIpMacPairSeen(IPAddress ip, MacAddress mac)
    {
        lock (_senderLock)
        {
            if (_watchedSender != null && mac != _ownMac &&
                _watchedSender.Equals(ip) && _conflictIp == null)
                _conflictIp = ip;
        }
    }

    private IPAddress? TakeConflict()
    {
        lock (_senderLock) { var c = _conflictIp; _conflictIp = null; return c; }
    }

    public ActiveArpScanner() { }

    public bool IsRunning => _task is { IsCompleted: false };

    public bool OpenSendHandle(string pcapDeviceName)
    {
        CloseSendHandle();
        NpcapManager.EnsureDllResolver();
        var err = new StringBuilder(PcapNative.PCAP_ERRBUF_SIZE);
        _sendHandle = PcapNative.pcap_open_live(pcapDeviceName, 65536, 0, 100, err);
        if (_sendHandle == IntPtr.Zero)
        {
            Error?.Invoke($"Failed to open the send channel: {err}");
            return false;
        }
        return true;
    }

    public void Pause() => _pauseGate.Reset();
    public void Resume() => _pauseGate.Set();

    /// <summary>等待当前发送任务结束（无任务立即返回）。用于停止后同步收尾；任务取消/异常路径在此吞掉，收尾由 FinalizeActive 负责。</summary>
    public void WaitCompletion(int ms)
    {
        try { _task?.Wait(ms); }
        catch { /* 取消（TaskCanceledException）或任务故障（AggregateException）时不传播 */ }
    }
    public void Stop() => _cts?.Cancel();

    /// <summary>
    /// ARP Probe：sender IP=0.0.0.0、sender MAC=本机 MAC、target=目标地址，广播。
    /// 目标存在则以普通 ARP reply（或任意外部报文）应答，由抓包线程写入映射表；
    /// 250ms 内 isPresent(target) 变 true 即返回 true。谓词判定覆盖全部协议，
    /// 比只登记 ARP reply 更可靠。暂停期间阻塞等待；取消时抛 OperationCanceledException。
    /// </summary>
    public async Task<bool> ProbeAsync(
        IPAddress target,
        MacAddress srcMac,
        Func<IPAddress, bool> isPresent,
        CancellationToken token)
    {
        if (_sendHandle == IntPtr.Zero) return false;

        var frame = BuildArpRequest(srcMac, IPAddress.Any, target); // sender IP = 0.0.0.0
        PcapNative.pcap_sendpacket(_sendHandle, frame, frame.Length);

        var deadline = DateTime.Now.AddMilliseconds(250);
        while (true)
        {
            _pauseGate.Wait(token); // 暂停期间阻塞
            token.ThrowIfCancellationRequested();
            if (isPresent(target)) return true; // 已被任意协议观察到 → 设备存在
            if (DateTime.Now >= deadline) return false;
            await Task.Delay(15, token).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// 扫描一组目标（单线程按间隔节奏发送）。返回 (已发送数, 冲突 IP)。
    /// 发送循环每轮检查冒用冲突标志：检出冲突立即中断并返回冲突 IP，
    /// 跳过尾部等待（迟到应答由抓包线程持续入表），由编排层换 sender 后续扫。
    /// 正常完成时尾部等待 1.5s 收迟到应答，返回冲突 IP = null。
    /// </summary>
    public Task<(int Sent, IPAddress? ConflictIp)> ScanAsync(
        IEnumerable<IPAddress> targets,
        MacAddress srcMac,
        IPAddress srcIp,
        int segmentIndex,
        int segmentCount,
        CancellationToken externalToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);
        var ct = _cts.Token;
        var targetList = targets.ToList();
        // 不在此清除暂停门：暂停必须跨批次保持（尾部等待/段间隙点暂停时，
        // 新批次进入后仍应停在门上，直到 Resume/Stop 显式解除）

        var task = Task.Run(() =>
        {
            int sent = 0;
            IPAddress? conflict = null;
            foreach (var ip in targetList)
            {
                conflict = TakeConflict();
                if (conflict != null) break;           // 冒用地址被证实占用，立即中断
                if (ct.IsCancellationRequested) break;
                _pauseGate.Wait(ct);

                if (_sendHandle == IntPtr.Zero) break;
                var frame = BuildArpRequest(srcMac, srcIp, ip);
                PcapNative.pcap_sendpacket(_sendHandle, frame, frame.Length);

                sent++;
                Progress?.Invoke(ip, srcIp, sent, targetList.Count, segmentIndex, segmentCount);
                if (IntervalMs > 0)
                    // Sleep 对齐到系统 tick（15.625ms）边界：睡 IntervalMs-1 留出每包开销余量，
                    // 使 Sleep 恰好落在 1 个 tick，实际间隔稳定 = IntervalMs 向上取整到 15.6 的倍数
                    Thread.Sleep(Math.Max(1, IntervalMs - 1));
            }

            if (conflict != null)
                return (sent, conflict);

            // F9：尾部等待 1.5s 收迟到应答（暂停期间同步挂起，与发送循环一致）
            var deadline = DateTime.Now.AddMilliseconds(1500);
            while (DateTime.Now < deadline && !ct.IsCancellationRequested)
            {
                _pauseGate.Wait(ct);
                Thread.Sleep(50);
            }
            return (sent, (IPAddress?)null);
        }, ct);

        _task = task;
        return task;
    }

    public static byte[] BuildArpRequest(MacAddress srcMac, IPAddress srcIp, IPAddress targetIp)
    {
        var frame = new byte[42];
        // Ethernet 头
        for (int i = 0; i < 6; i++) frame[i] = 0xFF;                 // 广播
        var mac = new[] { srcMac.B0, srcMac.B1, srcMac.B2, srcMac.B3, srcMac.B4, srcMac.B5 };
        Array.Copy(mac, 0, frame, 6, 6);
        frame[12] = 0x08; frame[13] = 0x06;                          // ARP
        // ARP 载荷
        frame[14] = 0x00; frame[15] = 0x01;                          // HTYPE Ethernet
        frame[16] = 0x08; frame[17] = 0x00;                          // PTYPE IPv4
        frame[18] = 6; frame[19] = 4;                                // HLEN/PLEN
        frame[20] = 0x00; frame[21] = 0x01;                          // OPER request
        Array.Copy(mac, 0, frame, 22, 6);                            // sender MAC
        Array.Copy(srcIp.GetAddressBytes(), 0, frame, 28, 4);        // sender IP
        // target MAC 全 0
        Array.Copy(targetIp.GetAddressBytes(), 0, frame, 38, 4);     // target IP
        return frame;
    }

    private void CloseSendHandle()
    {
        if (_sendHandle != IntPtr.Zero)
        {
            PcapNative.pcap_close(_sendHandle);
            _sendHandle = IntPtr.Zero;
        }
    }

    public void Dispose()
    {
        Stop();
        CloseSendHandle();
    }
}
