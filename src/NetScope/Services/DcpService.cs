using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetScope.Interop;
using NetScope.Models;
using static NetScope.Services.AdapterService;

namespace NetScope.Services;

/// <summary>
/// F60–F70：PROFINET DCP 设备发现服务（独立于 ARP 扫描/被动监听）。
/// 独立 pcap 句柄 + BPF ether proto 0x8892；独立设备表（MAC 主键，不进 F26 映射表）。
/// Identify 一次性任务（连发 3 次多播，收集窗口 1.5s）；Set 操作后持续复查直到值变更或 5 分钟超时。
/// </summary>
public class DcpService : IDisposable
{
    // PROFINET 多播地址
    private static readonly byte[] DcpMulticast = { 0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00 };
    private const ushort EtherTypeDcp = 0x8892;
    private const ushort FrameIdIdentifyReq = 0xFEFE;   // Identify 请求（单播 + 多播共用）
    private const ushort FrameIdIdentifyOk  = 0xFEFF;   // Identify 响应（OK）
    private const ushort FrameIdSetReq = 0xFEFD;        // Set 请求 + Set 响应（OK）共用同一 FrameID
    private const byte SvcIdentify = 0x05;
    private const byte SvcSet = 0x04;
    private const byte TypeRequest = 0x00;
    private const byte TypeResponse = 0x01;
    private const ushort ResponseDelay192 = 192; // 192 单位 = 1.5s（与 PRONETA 一致）

    private readonly PnoVendorLookup _pnoLookup;

    private IntPtr _handle;
    private Thread? _recvThread;
    private volatile bool _capturing;

    // 独立设备表（MAC 主键）
    private readonly Dictionary<MacAddress, DcpDeviceEntry> _devices = new();
    private readonly object _tableLock = new();

    private MacAddress _localMac;
    private string _pcapName = "";
    private int _xidCounter = 1;

    // Set OK 等待（Xid → TCS）
    private readonly Dictionary<int, TaskCompletionSource<List<(byte Opt, byte Sub, byte Status)>>> _pendingSetOk = new();
    private readonly object _setLock = new();

    // 持续复查
    private CancellationTokenSource? _reverifyCts;
    private Task? _reverifyTask;
    private MacAddress _reverifyTarget;
    private DcpDeviceSnapshot? _reverifyOldValues;
    private volatile bool _reverifyChanged;
    /// <summary>复查成功判定：true=值必须相对旧值变化（Set IP）；false=设备应答 Identify OK 即成功（Factory Reset——不同设备恢复出厂后不一定清零）。</summary>
    private volatile bool _reverifyRequireChange;
    private string? _reverifyTimeoutMsg;

    /// <summary>pcap 句柄与接收线程生命周期串行化（StopCapture 与重开互斥，防止复查收尾误关新任务的句柄）。</summary>
    private readonly object _captureLock = new();

    /// <summary>Identify 一次性任务的取消令牌（Stop/网卡 Down 用），使沉睡中的 Task.Delay 立即中断。</summary>
    private CancellationTokenSource? _identifyCts;
    /// <summary>F5 网卡 Down 紧急停止标记：Identify 协程被取消后跳过状态事件，保留 UI 层拔线提示文案。</summary>
    private volatile bool _emergencyStopped;

    // 状态与事件
    public RunState State { get; private set; } = RunState.Idle;
    public event Action<RunState, string>? StateChanged;
    public event Action? DeviceTableChanged;
    public event Action<string>? Error;
    /// <summary>复查结束：true=值已变成功，false=超时/取消。第二个参数为超时提示文案（null=非超时）。</summary>
    public event Action<bool, string?>? ReverificationFinished;
    /// <summary>复查开始（已收到 Set OK）：UI 提示最长 5 分钟的周期复查正在进行。</summary>
    public event Action? ReverificationStarted;
    /// <summary>新 Set 操作取消了进行中的旧复查（UI 提示旧复查被放弃）。</summary>
    public event Action? ReverificationSuperseded;
    /// <summary>复查周期倒计时 tick：参数为剩余 TimeSpan，UI 用于更新状态栏剩余时间。</summary>
    public event Action<TimeSpan>? ReverificationTick;

    public bool IsBusy => State is RunState.Scanning;
    public bool IsReverifying => _reverifyCts != null && !_reverifyCts.IsCancellationRequested;

    public DcpService(PnoVendorLookup pnoLookup) => _pnoLookup = pnoLookup;

    // ===================== 主任务：Identify =====================

    /// <summary>F60：DCP Identify 一次性任务。连发 3 次多播，收集窗口 1.5s。</summary>
    public async Task StartIdentifyAsync(AdapterInfo adapter)
    {
        if (IsBusy) return;

        var mac = GetAdapterMac(adapter.Id);
        if (mac == null)
        {
            SetState(RunState.Error, "The adapter has no MAC. DCP scan is unavailable.");
            return;
        }
        _localMac = mac.Value;

        CancelReverification(); // F66：Start 新任务先取消进行中的复查（等其收尾，避免复查线程误关本任务的抓包句柄）

        _identifyCts?.Dispose();
        _identifyCts = new CancellationTokenSource();
        _emergencyStopped = false;
        var identifyToken = _identifyCts.Token;

        lock (_tableLock) _devices.Clear();
        DeviceTableChanged?.Invoke();

        SetState(RunState.Scanning, "DCP Identify...");

        // 切到线程池，避免 UI 阻塞
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);

        try
        {
            lock (_captureLock)
            {
                if (!OpenHandle(adapter.PcapName))
                {
                    SetState(RunState.Error, "Failed to open DCP capture (Npcap not installed or insufficient privileges)");
                    return;
                }

                // 接收线程
                if (!_capturing)
                {
                    _capturing = true;
                    _recvThread = new Thread(ReceiveLoop) { IsBackground = true, Name = "DcpReceive" };
                    _recvThread.Start();
                }
            }

            // 连发 3 次 Identify 多播（500ms 间隔，与 PRONETA 一致）
            int xid = Interlocked.Increment(ref _xidCounter);
            for (int i = 0; i < 3; i++)
            {
                identifyToken.ThrowIfCancellationRequested();
                var frame = BuildIdentifyReq(_localMac, xid);
                if (_handle != IntPtr.Zero)
                    PcapNative.pcap_sendpacket(_handle, frame, frame.Length);
                if (i < 2) await Task.Delay(500, identifyToken).ConfigureAwait(false);
            }

            // 收集窗口：第 3 个 Req 后等 1.5s
            await Task.Delay(1500, identifyToken).ConfigureAwait(false);

            SetState(RunState.Completed, "DCP Identify completed");
            // 任务结束即停止监听；后续 Set/复查由 EnsureHandleOpen 按需重开
            StopCapture();
        }
        catch (OperationCanceledException)
        {
            StopCapture();
            // F5 紧急停止（网卡 Down）：状态已由 EmergencyStop 置 Stopped，
            // 不再抛状态事件，保留 UI 状态栏的拔线提示；普通 Stop 则正常转 Stopped
            if (!_emergencyStopped) SetState(RunState.Stopped, "Stopped");
        }
        catch (Exception ex)
        {
            StopCapture();
            SetState(RunState.Error, ex.Message);
        }
    }

    /// <summary>停止 DCP 全部活动（Identify + 接收线程 + Set 等待 + 复查），关闭句柄。</summary>
    public void Stop()
    {
        _emergencyStopped = false;
        _identifyCts?.Cancel(); // 中断 Identify 协程的 Delay，防止其醒来抛 Completed 覆盖 Stopped
        bool wasReverifying = IsReverifying; // CancelReverification 后 IsReverifying 即回落，先记录
        CancelReverification();
        lock (_setLock)
        {
            foreach (var tcs in _pendingSetOk.Values)
                tcs.TrySetResult(new List<(byte, byte, byte)>());
            _pendingSetOk.Clear();
        }
        StopCapture();
        // 复查期间 State 是 Completed 而非 Scanning，复查中点 Stop 也必须抛出 Stopped 状态事件
        if (State is RunState.Scanning or RunState.Completed || wasReverifying)
            SetState(RunState.Stopped, "Stopped");
    }

    /// <summary>F5 网卡 Down：紧急停止（不阻塞 UI）。Identify 协程被取消后不再抛状态事件，
    /// 保留 UI 层 "Adapter link down. DCP tasks stopped." 提示。</summary>
    public void EmergencyStop()
    {
        _emergencyStopped = true;
        _identifyCts?.Cancel();
        CancelReverification();
        lock (_setLock)
        {
            foreach (var tcs in _pendingSetOk.Values)
                tcs.TrySetResult(new List<(byte, byte, byte)>());
            _pendingSetOk.Clear();
        }
        StopCapture();
        if (State is RunState.Scanning or RunState.Completed)
            SetState(RunState.Stopped, "Stopped");
    }

    private void StopCapture()
    {
        lock (_captureLock)
        {
            _capturing = false;
            if (_handle != IntPtr.Zero)
                PcapNative.pcap_breakloop(_handle);
            _recvThread?.Join(2000);
            _recvThread = null;
            CloseHandle();
        }
    }

    // ===================== Set 操作 =====================

    /// <summary>F66：Factory Reset — 发送 (5,5) 单播 Set → 等 Set OK → 持续复查。</summary>
    public async Task<bool> FactoryResetAsync(MacAddress deviceMac)
    {
        // F66：新 Set 操作（无论结果）取消进行中的复查；若有旧复查在跑，通知 UI 徽章回 Stopped
        if (IsReverifying) ReverificationSuperseded?.Invoke();
        CancelReverification();
        if (!EnsureHandleOpen()) return false;

        var oldValues = GetSnapshot(deviceMac);
        if (oldValues == null) { StopCapture(); return false; }
        var blocks = new List<byte[]>();
        blocks.Add(BuildBlock(0x05, 0x05, new byte[] { 0x00, 0x00 })); // (5,5) Reset
        blocks.Add(BuildBlock(0x05, 0x02, Array.Empty<byte>()));         // (5,2) Commit

        var (ok, statuses) = await SendSetAndWaitOk(deviceMac, blocks).ConfigureAwait(false);
        if (!ok || statuses.Any(s => s.Status != 0))
        {
            StopCapture(); // F66：未收到 Set OK 或状态非 0 → 不进入复查，立即停止监听
            return false;
        }

        StartReverification(deviceMac, oldValues,
            "Factory reset sent, but the device has not come back online for an extended period. Please verify manually.",
            requireValuesChanged: false); // F66：设备重新上线应答即成功，不要求值清零
        return true;
    }

    /// <summary>F67：Set IP + 站名 — 差分后组帧 → 等 Set OK → 持续复查。</summary>
    public async Task<bool> SetIpAsync(
        MacAddress deviceMac,
        DcpDeviceSnapshot oldValues,
        string? newName,
        IPAddress? newIp,
        IPAddress? newMask,
        IPAddress? newGw)
    {
        // F66：新 Set 操作（无论结果）取消进行中的复查；若有旧复查在跑，通知 UI 徽章回 Stopped
        if (IsReverifying) ReverificationSuperseded?.Invoke();
        CancelReverification();
        if (!EnsureHandleOpen()) return false;

        var blocks = new List<byte[]>();

        // F65：差分——仅变化的块加入
        bool nameChanged = newName != null && newName != oldValues.NameOfStation;
        bool ipChanged = newIp != null && (!newIp.Equals(oldValues.Ip) ||
                                           (newMask != null && !newMask.Equals(oldValues.SubnetMask)) ||
                                           (newGw != null && !newGw.Equals(oldValues.Gateway)));

        if (ipChanged && newIp != null && newMask != null && newGw != null)
            blocks.Add(BuildIpBlock(newIp, newMask, newGw));
        if (nameChanged && newName != null)
            blocks.Add(BuildNameBlock(newName));

        if (blocks.Count == 0) { StopCapture(); return false; } // 全未变（防御路径，按钮已禁用）

        blocks.Add(BuildBlock(0x05, 0x02, Array.Empty<byte>())); // (5,2) Commit

        var (ok, statuses) = await SendSetAndWaitOk(deviceMac, blocks).ConfigureAwait(false);
        if (!ok || statuses.Any(s => s.Status != 0))
        {
            StopCapture(); // F67：未收到 Set OK 或状态非 0 → 不进入复查，立即停止监听
            return false;
        }

        StartReverification(deviceMac, oldValues,
            "Settings accepted, but the device has not come back online for an extended period. Please verify manually.",
            requireValuesChanged: true); // F67：需确认 IP/站名等值相对旧值已变化
        return true;
    }

    /// <summary>发送 Set Req 并等待对应 Xid 的 Set OK（1.5s 超时）。</summary>
    private async Task<(bool Ok, List<(byte Opt, byte Sub, byte Status)> Statuses)> SendSetAndWaitOk(
        MacAddress deviceMac, List<byte[]> blocks)
    {
        int xid = Interlocked.Increment(ref _xidCounter);
        var tcs = new TaskCompletionSource<List<(byte, byte, byte)>>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_setLock) _pendingSetOk[xid] = tcs;

        var frame = BuildSetReq(deviceMac, _localMac, xid, blocks);
        if (_handle != IntPtr.Zero)
            PcapNative.pcap_sendpacket(_handle, frame, frame.Length);
        else
            return (false, new List<(byte, byte, byte)>());

        // 1.5s 超时
        var winner = await Task.WhenAny(tcs.Task, Task.Delay(1500)).ConfigureAwait(false);
        lock (_setLock) _pendingSetOk.Remove(xid);

        if (winner != tcs.Task)
            return (false, new List<(byte, byte, byte)>()); // 超时

        var statuses = await tcs.Task.ConfigureAwait(false);
        return (true, statuses);
    }

    // ===================== 持续复查 =====================

    /// <summary>F66/F67：收到 Set OK 后启动持续复查。周期性单播 Identify 按 1.5s 间隔，
    /// 直到重新扫到设备（Factory Reset：应答即成功；Set IP：值已变才成功）；
    /// 5 分钟超时 → 提示；取消 → 静默。
    /// timeoutMsg 用于区分 F66（Factory Reset）与 F67（Set IP）的超时文案。</summary>
    private void StartReverification(MacAddress target, DcpDeviceSnapshot oldValues, string timeoutMsg, bool requireValuesChanged)
    {
        CancelReverification();
        _reverifyTarget = target;
        _reverifyOldValues = oldValues;
        _reverifyChanged = false;
        _reverifyRequireChange = requireValuesChanged;
        _reverifyTimeoutMsg = timeoutMsg;
        _reverifyCts = new CancellationTokenSource();
        var ct = _reverifyCts.Token;

        ReverificationStarted?.Invoke();

        _reverifyTask = Task.Run(async () =>
        {
            var deadline = DateTime.Now.AddMinutes(5);
            while (!ct.IsCancellationRequested)
            {
                var remaining = deadline - DateTime.Now;
                if (remaining > TimeSpan.Zero)
                    ReverificationTick?.Invoke(remaining);

                if (_reverifyChanged)
                {
                    ReverificationFinished?.Invoke(true, null);
                    CleanupReverification();
                    StopCapture();
                    return;
                }
                if (DateTime.Now >= deadline)
                {
                    ReverificationFinished?.Invoke(false, _reverifyTimeoutMsg);
                    CleanupReverification();
                    StopCapture();
                    return;
                }
                // 发送单播 Identify（操作需与 StopCapture 串行，但发送是非阻塞原语，不持锁）
                if (_handle != IntPtr.Zero && _capturing)
                {
                    int xid = Interlocked.Increment(ref _xidCounter);
                    var frame = BuildIdentifyReq(_localMac, xid);
                    frame[0] = _reverifyTarget.B0; frame[1] = _reverifyTarget.B1;
                    frame[2] = _reverifyTarget.B2; frame[3] = _reverifyTarget.B3;
                    frame[4] = _reverifyTarget.B4; frame[5] = _reverifyTarget.B5;
                    PcapNative.pcap_sendpacket(_handle, frame, frame.Length);
                }
                try { await Task.Delay(1500, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
            CleanupReverification();
            StopCapture();
        }, ct);
    }

    /// <summary>取消复查（状态机切换/模式切换/网卡切换/关窗时调用）。</summary>
    public void CancelReverification()
    {
        if (_reverifyCts == null) return;
        _reverifyCts.Cancel();
        // 等复查任务收尾（关句柄），避免新 Identify 立即开句柄被并发 StopCapture 误关
        try { _reverifyTask?.Wait(3000); } catch { /* ignore */ }
        _reverifyCts = null;
        _reverifyTask = null;
    }

    private void CleanupReverification()
    {
        _reverifyTarget = default;
        _reverifyOldValues = null;
        _reverifyChanged = false;
        _reverifyTimeoutMsg = null;
        // 释放令牌：复查已结束，IsReverifying 必须回落为 false，否则 UI 守卫（双击弹窗等）永久拦截
        _reverifyCts = null;
        _reverifyTask = null;
    }

    // ===================== 接收线程 =====================

    private void ReceiveLoop()
    {
        while (_capturing && _handle != IntPtr.Zero)
        {
            int rc = PcapNative.pcap_next_ex(_handle, out var hdrPtr, out var dataPtr);
            if (rc == 0) continue;
            if (rc < 0) break;
            if (hdrPtr == IntPtr.Zero || dataPtr == IntPtr.Zero) continue;

            var hdr = Marshal.PtrToStructure<PcapNative.pcap_pkthdr>(hdrPtr);
            if (hdr.caplen == 0 || hdr.caplen > 262144) continue;
            var buf = new byte[hdr.caplen];
            Marshal.Copy(dataPtr, buf, 0, (int)hdr.caplen);
            try { ProcessFrame(buf); }
            catch { /* 单帧解析异常不影响抓包循环 */ }
        }
        _capturing = false;
    }

    private void ProcessFrame(byte[] f)
    {
        if (f.Length < 26) return;
        if (f[12] != 0x88 || f[13] != 0x92) return; // EtherType

        // 过滤自己发出的帧（源 MAC == 本机 MAC）
        if (f[6] == _localMac.B0 && f[7] == _localMac.B1 && f[8] == _localMac.B2 &&
            f[9] == _localMac.B3 && f[10] == _localMac.B4 && f[11] == _localMac.B5)
            return;

        ushort frameId = (ushort)((f[14] << 8) | f[15]);
        byte svcId = f[16];
        byte svcType = f[17];
        int xid = (f[18] << 24) | (f[19] << 16) | (f[20] << 8) | f[21];

        var deviceMac = MacAddress.Parse(f.AsSpan(6, 6));

        if (svcId == SvcIdentify && svcType == TypeResponse && frameId == FrameIdIdentifyOk)
            ParseIdentifyOk(f, deviceMac);
        else if (svcId == SvcSet && svcType == TypeResponse && frameId == FrameIdSetReq)
            ParseSetOk(f, xid);
    }

    /// <summary>F61：Identify OK TLV 链解析。</summary>
    private void ParseIdentifyOk(byte[] f, MacAddress deviceMac)
    {
        int dcpLen = (f[24] << 8) | f[25];
        int offset = 26;
        int end = Math.Min(26 + dcpLen, f.Length);

        var entry = new DcpDeviceEntry { Mac = deviceMac };

        while (offset + 4 <= end)
        {
            byte option = f[offset];
            byte suboption = f[offset + 1];
            int length = (f[offset + 2] << 8) | f[offset + 3];
            int valOff = offset + 4;
            if (valOff + length > end) break;

            switch ((option, suboption))
            {
                case (0x01, 0x02): // (1,2) IP
                    if (length >= 14)
                    {
                        entry.IpBlockInfo = (ushort)((f[valOff] << 8) | f[valOff + 1]);
                        entry.Ip = new IPAddress(f[(valOff + 2)..(valOff + 6)].ToArray());
                        entry.SubnetMask = new IPAddress(f[(valOff + 6)..(valOff + 10)].ToArray());
                        entry.Gateway = new IPAddress(f[(valOff + 10)..(valOff + 14)].ToArray());
                    }
                    break;
                case (0x02, 0x01): // (2,1) Manufacturer
                    entry.Manufacturer = ExtractAscii(f, valOff, length);
                    break;
                case (0x02, 0x02): // (2,2) NameOfStation
                    entry.NameOfStation = ExtractAscii(f, valOff, length);
                    break;
                case (0x02, 0x03): // (2,3) DeviceID
                    if (length >= 4)
                    {
                        entry.VendorId = (ushort)((f[valOff] << 8) | f[valOff + 1]);
                        entry.DeviceId = (ushort)((f[valOff + 2] << 8) | f[valOff + 3]);
                    }
                    break;
            }
            // 跳过 value + padding（2 字节对齐：奇数长度补 1 字节，偶数不补）
            int totalBlock = 4 + length;
            offset += totalBlock + (length & 1);
        }

        entry.VendorName = _pnoLookup.Lookup(entry.VendorId, deviceMac);

        // F61：Identify OK 未携带 (1,2) IP 块时，视为 IP/Subnet/Gateway 全为 0.0.0.0
        // （IpBlockInfo 保持 0 表示"无 IP 设置"，IpDisplay 据此显示 0.0.0.0/0）
        if (entry.Ip == null)
        {
            entry.Ip = IPAddress.Any;
            entry.SubnetMask = IPAddress.Any;
            entry.Gateway = IPAddress.Any;
        }

        // 更新设备表
        lock (_tableLock)
        {
            if (_devices.TryGetValue(deviceMac, out var existing))
            {
                existing.Count++;
                existing.LastSeen = DateTime.Now;
                if (entry.VendorId != 0) existing.VendorId = entry.VendorId;
                if (entry.DeviceId != 0) existing.DeviceId = entry.DeviceId;
                if (entry.Manufacturer != null) existing.Manufacturer = entry.Manufacturer;
                if (entry.NameOfStation != null) existing.NameOfStation = entry.NameOfStation;
                // IP 字段已补 0.0.0.0，可直接刷新（含从有 IP 变无 IP 的回退场景）
                existing.Ip = entry.Ip;
                existing.SubnetMask = entry.SubnetMask;
                existing.Gateway = entry.Gateway;
                existing.IpBlockInfo = entry.IpBlockInfo;
                if (entry.VendorName != null) existing.VendorName = entry.VendorName;
            }
            else
            {
                entry.Count = 1;
                entry.FirstSeen = DateTime.Now;
                entry.LastSeen = entry.FirstSeen;
                _devices[deviceMac] = entry;
            }
        }

        // 复查检查
        CheckReverification(deviceMac);
        DeviceTableChanged?.Invoke();
    }

    /// <summary>F70：Set OK 解析 — (5,4) 块各 option/suboption/status。</summary>
    private void ParseSetOk(byte[] f, int xid)
    {
        int dcpLen = (f[24] << 8) | f[25];
        int offset = 26;
        int end = Math.Min(26 + dcpLen, f.Length);

        var statuses = new List<(byte, byte, byte)>();

        while (offset + 4 <= end)
        {
            byte option = f[offset];
            byte suboption = f[offset + 1];
            int length = (f[offset + 2] << 8) | f[offset + 3];
            int valOff = offset + 4;
            if (valOff + length > end) break;

            if (option == 0x05 && suboption == 0x04)
            {
                // (5,4) 块：每 3 字节一组 [option, suboption, status]
                for (int i = 0; i + 2 < length; i += 3)
                    statuses.Add((f[valOff + i], f[valOff + i + 1], f[valOff + i + 2]));
            }
            int totalBlock = 4 + length;
            offset += totalBlock + ((4 - (totalBlock % 4)) % 4);
        }

        lock (_setLock)
        {
            if (_pendingSetOk.TryGetValue(xid, out var tcs))
            {
                tcs.TrySetResult(statuses);
                _pendingSetOk.Remove(xid);
            }
        }
    }

    /// <summary>复查：收到目标设备 Identify OK 时判定成功条件。
    /// Factory Reset——设备重新上线应答即成功（值不一定清零）；Set IP——值相对旧值已变化才成功。</summary>
    private void CheckReverification(MacAddress deviceMac)
    {
        if (_reverifyOldValues == null) return;
        if (!deviceMac.Equals(_reverifyTarget)) return;

        if (!_reverifyRequireChange)
        {
            // F66：能在此收到目标 MAC 的 Identify OK，说明设备已重新上线
            _reverifyChanged = true;
            return;
        }

        lock (_tableLock)
        {
            if (!_devices.TryGetValue(deviceMac, out var entry)) return;
            var current = entry.Snapshot();
            if (!ValuesMatch(current, _reverifyOldValues))
                _reverifyChanged = true;
        }
    }

    private static bool ValuesMatch(DcpDeviceSnapshot a, DcpDeviceSnapshot b)
        => a.NameOfStation == b.NameOfStation &&
           a.Ip.Equals(b.Ip) &&
           a.SubnetMask.Equals(b.SubnetMask) &&
           a.Gateway.Equals(b.Gateway);

    // ===================== 组帧 =====================

    /// <summary>F70：Identify Req 多播帧。</summary>
    private static byte[] BuildIdentifyReq(MacAddress srcMac, int xid)
    {
        // Ethernet(14) + DCP头(12) + 全选块(4) = 30，pad 到 60
        var f = new byte[60];
        // Dst = 多播
        Buffer.BlockCopy(DcpMulticast, 0, f, 0, 6);
        // Src = 本机 MAC
        f[6] = srcMac.B0; f[7] = srcMac.B1; f[8] = srcMac.B2;
        f[9] = srcMac.B3; f[10] = srcMac.B4; f[11] = srcMac.B5;
        // EtherType
        f[12] = 0x88; f[13] = 0x92;
        // FrameID（Identify Request = 0xFEFE）
        f[14] = 0xFE; f[15] = 0xFE;
        // ServiceID
        f[16] = SvcIdentify;
        // ServiceType
        f[17] = TypeRequest;
        // Xid (big-endian)
        f[18] = (byte)(xid >> 24); f[19] = (byte)(xid >> 16);
        f[20] = (byte)(xid >> 8); f[21] = (byte)xid;
        // ResponseDelay
        f[22] = (byte)(ResponseDelay192 >> 8); f[23] = (byte)(ResponseDelay192 & 0xFF);
        // DCPDataLen = 4
        f[24] = 0x00; f[25] = 0x04;
        // 全选块: FF FF 00 00
        f[26] = 0xFF; f[27] = 0xFF; f[28] = 0x00; f[29] = 0x00;
        return f;
    }

    /// <summary>F70：Set Req 单播帧（变更块 + (5,2) 提交块）。</summary>
    private static byte[] BuildSetReq(MacAddress dstMac, MacAddress srcMac, int xid, List<byte[]> blocks)
    {
        // 组装 DCP data
        var data = new List<byte>();
        foreach (var b in blocks) data.AddRange(b);
        int dcpLen = data.Count;

        var f = new List<byte>(14 + 12 + dcpLen);
        // Ethernet
        f.Add(dstMac.B0); f.Add(dstMac.B1); f.Add(dstMac.B2);
        f.Add(dstMac.B3); f.Add(dstMac.B4); f.Add(dstMac.B5);
        f.Add(srcMac.B0); f.Add(srcMac.B1); f.Add(srcMac.B2);
        f.Add(srcMac.B3); f.Add(srcMac.B4); f.Add(srcMac.B5);
        f.Add(0x88); f.Add(0x92);
        // DCP header
        f.Add(0xFE); f.Add(0xFD); // FrameID
        f.Add(SvcSet);            // ServiceID
        f.Add(TypeRequest);       // ServiceType
        f.Add((byte)(xid >> 24)); f.Add((byte)(xid >> 16));
        f.Add((byte)(xid >> 8)); f.Add((byte)xid);
        f.Add(0x00); f.Add(0x00); // ResponseDelay = 0 (Set)
        f.Add((byte)(dcpLen >> 8)); f.Add((byte)(dcpLen & 0xFF));
        // DCP data
        f.AddRange(data);
        // Pad to 60
        while (f.Count < 60) f.Add(0);
        return f.ToArray();
    }

    /// <summary>DCP 块：option + suboption + length(big-endian) + value + padding(2 字节对齐：奇数补 1)。</summary>
    private static byte[] BuildBlock(byte option, byte suboption, byte[] value)
    {
        var block = new List<byte>(4 + value.Length + 1);
        block.Add(option);
        block.Add(suboption);
        block.Add((byte)(value.Length >> 8));
        block.Add((byte)(value.Length & 0xFF));
        block.AddRange(value);
        int pad = value.Length & 1; // 奇数补 1 字节 padding,偶数不补
        for (int i = 0; i < pad; i++) block.Add(0);
        return block.ToArray();
    }

    /// <summary>(1,2) IP 块：block_info(0x0001) + IP + mask + gw。</summary>
    private static byte[] BuildIpBlock(IPAddress ip, IPAddress mask, IPAddress gw)
    {
        var value = new byte[14];
        value[0] = 0x00; value[1] = 0x01; // block_info = set
        Buffer.BlockCopy(ip.GetAddressBytes(), 0, value, 2, 4);
        Buffer.BlockCopy(mask.GetAddressBytes(), 0, value, 6, 4);
        Buffer.BlockCopy(gw.GetAddressBytes(), 0, value, 10, 4);
        return BuildBlock(0x01, 0x02, value);
    }

    /// <summary>(2,2) NameOfStation 块：block_info(0x0001) + ASCII 站名。</summary>
    private static byte[] BuildNameBlock(string name)
    {
        var ascii = Encoding.ASCII.GetBytes(name);
        var value = new byte[2 + ascii.Length];
        value[0] = 0x00; value[1] = 0x01; // block_info = set
        Buffer.BlockCopy(ascii, 0, value, 2, ascii.Length);
        return BuildBlock(0x02, 0x02, value);
    }

    /// <summary>文本块值提取 ASCII（跳过前导保留字节/尾部 null）。</summary>
    private static string ExtractAscii(byte[] f, int offset, int length)
    {
        int start = 0;
        while (start < length && (f[offset + start] < 0x20 || f[offset + start] > 0x7E))
            start++;
        int endLen = 0;
        while (endLen < length - start && f[offset + start + endLen] >= 0x20 && f[offset + start + endLen] <= 0x7E)
            endLen++;
        return Encoding.ASCII.GetString(f, offset + start, endLen);
    }

    // ===================== 设备表快照 =====================

    /// <summary>F62：DCP 设备表 → UI 行列表（与 ResultRow 同属性名）。</summary>
    public List<DcpResultRow> Snapshot()
    {
        var rows = new List<DcpResultRow>();
        lock (_tableLock)
        {
            foreach (var entry in _devices.Values)
            {
                rows.Add(new DcpResultRow
                {
                    Ip = entry.IpDisplay,
                    MacText = entry.Mac.ToString(),
                    Vendor = entry.VendorName,
                    DeviceName = entry.Manufacturer,
                    HostName = entry.NameOfStation,
                    SourceText = "DCP",
                    Count = entry.Count,
                    Mac = entry.Mac
                });
            }
        }
        return rows.OrderBy(r => r.MacText, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>获取指定设备的当前值快照（Set 差分用）。</summary>
    public DcpDeviceSnapshot? GetSnapshot(MacAddress mac)
    {
        lock (_tableLock)
        {
            return _devices.TryGetValue(mac, out var entry) ? entry.Snapshot() : null;
        }
    }

    /// <summary>清空设备表（F59 开始即清空）。</summary>
    public void Clear()
    {
        lock (_tableLock) _devices.Clear();
        DeviceTableChanged?.Invoke();
    }

    // ===================== pcap 句柄管理 =====================

    private bool EnsureHandleOpen()
    {
        lock (_captureLock)
        {
            if (_handle != IntPtr.Zero && _capturing) return true;
            // 句柄未开（Identify 完成后被关闭或未运行过）→ 尝试重开
            if (_pcapName.Length == 0) return false;
            if (!OpenHandle(_pcapName)) return false;
            _capturing = true;
            _recvThread = new Thread(ReceiveLoop) { IsBackground = true, Name = "DcpReceive" };
            _recvThread.Start();
            return true;
        }
    }

    private bool OpenHandle(string pcapName)
    {
        if (_handle != IntPtr.Zero && _pcapName == pcapName) return true;
        CloseHandle();
        NpcapManager.EnsureDllResolver();
        var err = new StringBuilder(PcapNative.PCAP_ERRBUF_SIZE);
        _handle = PcapNative.pcap_open_live(pcapName, 65536, 1, 100, err);
        if (_handle == IntPtr.Zero)
        {
            Error?.Invoke($"Failed to open DCP capture: {err}");
            return false;
        }
        PcapNative.TrySetFilter(_handle, "ether proto 0x8892");
        _pcapName = pcapName;
        return true;
    }

    private void CloseHandle()
    {
        if (_handle != IntPtr.Zero)
        {
            PcapNative.pcap_close(_handle);
            _handle = IntPtr.Zero;
        }
    }

    // ===================== 工具 =====================

    private void SetState(RunState s, string text)
    {
        State = s;
        StateChanged?.Invoke(s, text);
    }

    private static MacAddress? GetAdapterMac(string adapterId)
    {
        var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Id == adapterId);
        var bytes = nic?.GetPhysicalAddress().GetAddressBytes();
        return bytes is { Length: 6 } ? MacAddress.Parse(bytes) : null;
    }

    public void Dispose()
    {
        _emergencyStopped = true; // 关窗释放：协程醒来不再抛状态事件
        _identifyCts?.Cancel();
        CancelReverification();
        StopCapture();
        _identifyCts?.Dispose();
        _identifyCts = null;
    }
}
