using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using NetScope.Interop;
using NetScope.Models;
using static NetScope.Services.AdapterService;

namespace NetScope.Services;

public enum ScanMode { Active, Passive }
public enum RunState { Idle, Scanning, Paused, Completed, Stopped, Error }

public class ScanProgress
{
    public double Percent;
    public string SegmentText = "";
    public string EtaText = "";
    public int ResultCount;
}

/// <summary>
/// 扫描编排（F6/F51/F7/F54 + F56 统一流程）：
/// 四个阶段唯一区别是待扫子键来源，执行完全一致——
///   构建集合（相同键去重，≤24 切片 /24，>24 按实际前缀）→ 前缀降序排序（主机数少的先扫）
///   → 逐子键与全局已扫集合做 CIDR 包含比对算待扫 IP（情况 1/2/3）→ F11 选 sender 扫描 → 立即回写。
/// 每个子键的主机 IP 列表即算即扫即弃（NF4 流式：峰值仅单个子键的主机列表，/24 ≈ 254 个）。
/// 主动扫描 = 扫描（本机段 request / 跨网段 F52 probe+request 混合）+ 全程被动监听；
/// 被动监听 = 持续抓包 + 两种模式都按 10s 周期导入系统 ARP 邻居表补漏。
/// 全程不改网卡配置。
/// </summary>
public class ScanOrchestrator
{
    /// <summary>F54：无 segments.txt 时回退的 24 个常用私有 /24 段。</summary>
    private static readonly (string Ip, int Prefix)[] BuiltinSegments =
    {
        ("192.168.0.0",24),("10.0.0.0",24),("172.16.0.0",24),("192.168.1.0",24),
        ("10.1.0.0",24),("172.20.0.0",24),("192.168.2.0",24),("10.10.0.0",24),
        ("172.16.1.0",24),("192.168.10.0",24),("10.0.1.0",24),("172.31.0.0",24),
        ("192.168.100.0",24),("10.0.2.0",24),("172.16.31.0",24),("192.168.31.0",24),
        ("10.1.1.0",24),("172.18.0.0",24),("192.168.8.0",24),("10.10.10.0",24),
        ("172.17.0.0",24),("192.168.50.0",24),("10.100.0.0",24),("192.168.254.0",24),
    };

    private const string SegmentFileName = "segments.txt";

    private readonly MapperService _mapper;
    private readonly PassiveSniffer _sniffer;
    private readonly ActiveArpScanner _scanner;

    private CancellationTokenSource? _cts;
    /// <summary>F5 网卡 Down 紧急停止标记：收尾链据此跳过重复状态事件，保留 UI 层拔线提示文案。</summary>
    private volatile bool _emergencyStopped;
    private readonly List<TimeSpan> _segmentDurations = new();

    /// <summary>全局已扫网段键集合（F56，网段级去重单位，不按单 IP 记账）。</summary>
    private readonly HashSet<(uint Network, int Prefix)> _scanned = new();
    /// <summary>按前缀分桶的已扫网络地址（供情况 3 快速枚举 a 内的真子集 C）。</summary>
    private readonly Dictionary<int, SortedSet<uint>> _subnetsByPrefix = new();

    private ScanMode _currentMode;
    private string _currentPcapName = "";
    private AdapterInfo? _currentAdapter;
    /// <summary>F14：当前正在扫描的子键（网络号/前缀），供进度文案显示。写入（编排链）与读取（发送线程）由 await 挂起间隔隔离。</summary>
    private (uint Network, int Prefix) _currentKey;
    private System.Threading.Timer? _neighborTimer;

    public RunState State { get; private set; } = RunState.Idle;
    public event Action<RunState, string>? StateChanged;
    public event Action<ScanProgress>? ProgressChanged;

    /// <summary>阶段 1.5 完毕后，由 UI 层弹出询问是否继续阶段 2/3。</summary>
    public Func<bool>? AskContinue { get; set; }

    public ScanOrchestrator(MapperService mapper, PassiveSniffer sniffer, ActiveArpScanner scanner)
    {
        _mapper = mapper;
        _sniffer = sniffer;
        _scanner = scanner;
        _scanner.Progress += OnScannerProgress;
        _scanner.Error += msg => StateChanged?.Invoke(RunState.Error, msg);
        // F53 冒用冲突检测下沉到映射表写入入口：任何协议学到的 (IP, MAC) 对都参与判定
        _mapper.IpMacObserved += (ip, mac) => _scanner.NoteIpMacPairSeen(ip, mac);
    }

    public bool IsBusy => State is RunState.Scanning or RunState.Paused;

    public void Pause()
    {
        if (State != RunState.Scanning) return;
        _scanner.Pause();
        _sniffer.Stop();
        State = RunState.Paused;
        StateChanged?.Invoke(State, "Paused");
    }

    public void Resume()
    {
        if (State != RunState.Paused) return;
        _scanner.Resume();
        if (!_sniffer.Start(_currentPcapName))
        {
            SetState(RunState.Error, "Failed to resume capture (Npcap not installed or insufficient privileges)");
            return;
        }
        State = RunState.Scanning;
        StateChanged?.Invoke(State, _currentMode == ScanMode.Passive ? "Passive listening" : "Scanning");
    }

    public void Stop()
    {
        _cts?.Cancel();
        StopNeighborTimer();
        _scanner.Resume();             // 解除暂停门：阻塞在等待上的发送/探测循环感知取消立即退出
        _scanner.WaitCompletion(1500); // 等主动任务收尾（取消路径立即退出），避免停止后立即重开撞状态
        // 被动模式无收尾任务：无论运行中还是暂停中，停止后都必须回到已停止状态
        if (_currentMode == ScanMode.Passive && State is RunState.Scanning or RunState.Paused)
        {
            _sniffer.Stop();
            SetState(RunState.Stopped, "Stopped");
        }
    }

    /// <summary>F5 Down 分支：网卡失效时立即取消任务（不阻塞 UI），主动/被动均立即转"已停止"。
    /// 主动模式的收尾链（FinalizeActive）见 _emergencyStopped 标记跳过重复状态事件，
    /// 避免其稍后抛出的 "Stopped" 把 UI 层 "Adapter link down..." 提示覆盖掉。</summary>
    public void EmergencyStop()
    {
        _emergencyStopped = true;
        _cts?.Cancel();
        StopNeighborTimer();
        _scanner.Resume();
        if (State is RunState.Scanning or RunState.Paused)
            SetState(RunState.Stopped, "Stopped");
    }

    public async Task StartAsync(
        ScanMode mode,
        AdapterInfo adapter,
        int intervalMs = 15)
    {
        if (IsBusy) return;
        _cts = new CancellationTokenSource();
        _emergencyStopped = false;
        var token = _cts.Token;
        _segmentDurations.Clear();
        _scanned.Clear();                 // F59：新任务重新建立全局已扫集合
        _subnetsByPrefix.Clear();
        _currentMode = mode;
        _currentAdapter = adapter;
        _currentPcapName = adapter.PcapName;
        SetState(RunState.Scanning, mode == ScanMode.Passive ? "Passive listening" : "Scanning");

        // 启动准备（首次加载 wpcap.dll、打开抓包/发送通道、枚举网卡）切到线程池执行，
        // 避免首次点开始时同步前缀阻塞 UI 线程数秒，进度文案延迟才出现
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);

        try
        {
            var mac = GetAdapterMac(adapter.Id);
            if (mac.HasValue) _sniffer.IgnoreMac = mac.Value;

            if (!_sniffer.IsRunning && !_sniffer.Start(adapter.PcapName))
            {
                SetState(RunState.Error, "Failed to start capture (Npcap not installed or insufficient privileges)");
                return;
            }

            // F12：两种模式启动时都立即导入一次系统 ARP 邻居表作为基线，之后 10s 周期补漏
            ImportNeighborTable();
            StartNeighborTimer();

            if (mode == ScanMode.Passive) return; // 保持监听直到 Stop

            // ===== 主动扫描 =====
            if (!PrepareActive(adapter, mac, out var amac)) return;
            _scanner.IntervalMs = intervalMs;
            uint? localIp = adapter.IPv4 != null ? ToUInt32(adapter.IPv4) : null;

            // ---- 阶段 1：本网段（子键来源 F6）----
            await RunPhase(Phase1Keys(adapter), localIp, amac, token).ConfigureAwait(false);
            if (token.IsCancellationRequested) { FinalizeActive(token); return; }

            // ---- 阶段 1.5：本网段补扫（子键来源 F51）----
            await RunPhase(Phase15Keys(adapter), localIp, amac, token).ConfigureAwait(false);
            if (token.IsCancellationRequested) { FinalizeActive(token); return; }

            // ---- F17：询问是否继续阶段 2/3 ----
            bool cont = AskContinue?.Invoke() ?? false;
            if (!cont) { FinalizeActive(token); return; }

            // ---- 阶段 2：阶段 1+1.5 发现的 IP-MAC 对衍生 /24（子键来源 F7）----
            var derived = new HashSet<(uint, int)>();
            foreach (var row in _mapper.Snapshot())
                derived.Add((NetworkOf(ToUInt32(row.Ip), 24), 24));
            await RunPhase(derived, localIp, amac, token).ConfigureAwait(false);
            if (token.IsCancellationRequested) { FinalizeActive(token); return; }

            // ---- 阶段 3：segments.txt 配置段，无文件回退内置 24 段（子键来源 F54）----
            await RunPhase(LoadPhase3Keys(), localIp, amac, token).ConfigureAwait(false);

            FinalizeActive(token);
        }
        catch (OperationCanceledException) { FinalizeActive(token); }
        catch (Exception ex)
        {
            SetState(RunState.Error, ex.Message);
        }
    }

    /// <summary>主动扫描公共准备：发送通道 + 网卡参数校验。主动扫描全程不改网卡配置。</summary>
    private bool PrepareActive(AdapterInfo adapter, MacAddress? mac, out MacAddress macOut)
    {
        macOut = default;
        if (mac == null || adapter.IPv4 == null)
        {
            SetState(RunState.Error, "The adapter has no IPv4 address or MAC. Active scan is unavailable.");
            return false;
        }
        if (!_scanner.OpenSendHandle(adapter.PcapName))
        {
            SetState(RunState.Error, "Failed to open the raw frame send channel.");
            return false;
        }
        macOut = mac.Value;
        _scanner.SetOwnMac(macOut);
        _scanner.SetWatchedSender(null);
        return true;
    }

    // ---------------- 各阶段子键来源 ----------------

    /// <summary>F6：前缀 &lt;24 只取本机所在 /24；=24 整段；25~32 按实际前缀。</summary>
    private static IEnumerable<(uint Network, int Prefix)> Phase1Keys(AdapterInfo adapter)
    {
        uint ip = ToUInt32(adapter.IPv4!);
        int p = adapter.PrefixLength;
        if (p < 24) yield return (NetworkOf(ip, 24), 24);
        else if (p == 24) yield return (NetworkOf(ip, 24), 24);
        else yield return (NetworkOf(ip, p), p);
    }

    /// <summary>F51：原始前缀 &lt;24 → 全部 /24 切片（含本机所在段，情况 1 自动跳过）；
    /// 25~32 → 扩到 /24（CIDR 情况 3 自动只扫差集）；=24 → 无待扫子键。</summary>
    private static IEnumerable<(uint Network, int Prefix)> Phase15Keys(AdapterInfo adapter)
    {
        if (adapter.IPv4 == null) yield break;
        uint ip = ToUInt32(adapter.IPv4);
        int p = adapter.PrefixLength;
        if (p < 24)
        {
            uint orig = NetworkOf(ip, p);
            foreach (var k in SliceTo24(orig, p)) yield return k;
        }
        else if (p > 24)
        {
            yield return (NetworkOf(ip, 24), 24);
        }
    }

    /// <summary>F54：读同目录 segments.txt；无文件回退内置 24 段。≤24 切片 /24，>24 按实际前缀。</summary>
    private List<(uint Network, int Prefix)> LoadPhase3Keys()
    {
        var keys = new List<(uint, int)>();
        var path = Path.Combine(AppContext.BaseDirectory, SegmentFileName);
        if (File.Exists(path))
        {
            foreach (var raw in File.ReadAllLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line[0] == '#') continue;
                var parts = line.Split('/', 2);
                if (parts.Length != 2) continue;
                if (!IPAddress.TryParse(parts[0].Trim(), out var ip)) continue;
                if (!int.TryParse(parts[1].Trim(), out var prefix) || prefix is < 1 or > 32) continue;
                uint net = NetworkOf(ToUInt32(ip), prefix);
                if (prefix <= 24)
                    foreach (var k in SliceTo24(net, prefix)) keys.Add(k);
                else
                    keys.Add((net, prefix));
            }
        }
        else
        {
            foreach (var (ipText, p) in BuiltinSegments)
                keys.Add((NetworkOf(ToUInt32(IPAddress.Parse(ipText)), p), p));
        }
        return keys;
    }

    /// <summary>把网段切成待扫子键：≤24 切 /24（受 /8 下限保护，防止超大配置内存膨胀），>24 原样。</summary>
    private static IEnumerable<(uint Network, int Prefix)> SliceTo24(uint network, int prefix)
    {
        network = NetworkOf(network, prefix);
        if (prefix >= 24) { yield return (network, prefix); yield break; }
        if (prefix < 8) yield break; // /7 及更粗将产生 >13 万 /24 切片，超出 NF4 约束，忽略
        int sliceCount = 1 << (24 - prefix);
        for (int s = 0; s < sliceCount; s++)
            yield return (network + (uint)(s * 256), 24);
    }

    // ---------------- F56 统一五步流程 ----------------

    /// <summary>构建去重 → 前缀降序排序 → 逐子键 CIDR 比对 → 扫描 → 回写。</summary>
    private async Task RunPhase(
        IEnumerable<(uint Network, int Prefix)> rawKeys,
        uint? localIp,
        MacAddress amac,
        CancellationToken ct)
    {
        // 步骤 1：构建本阶段待扫集合（相同键去重）
        var set = new HashSet<(uint, int)>();
        foreach (var k in rawKeys)
            set.Add(k);
        if (set.Count == 0) return;

        // 步骤 2：前缀从大到小（主机数少的先扫；保证小前缀段先回写，大段后扫命中情况 3 只扫差集）
        var ordered = set
            .OrderByDescending(k => k.Item2)
            .ThenBy(k => k.Item1)
            .ToList();

        int total = ordered.Count;
        for (int idx = 0; idx < total && !ct.IsCancellationRequested; idx++)
        {
            var key = ordered[idx];
            int segIndex = idx + 1;

            // 情况 1：完全相同 → 跳过（不扫描、不重复回写）
            if (_scanned.Contains(key)) continue;

            // 情况 2/3 → 待扫主机 IP（每个子键即算即扫，峰值仅单子键主机列表）
            var hosts = ComputeTargets(key);

            if (hosts.Count > 0)
            {
                var segStart = DateTime.Now;
                await ScanSubkey(key, hosts, segIndex, total, localIp, amac, ct).ConfigureAwait(false);
                _segmentDurations.Add(DateTime.Now - segStart);
            }

            // 步骤 5：扫完立即回写全局已扫集合，再处理下一个子键
            MarkScanned(key);
        }
    }

    /// <summary>F56 步骤 3：与全局已扫集合做 CIDR 包含比对，返回该子键实际待扫主机 IP（升序）。
    /// 无真子集 C → 全部主机（情况 2：a 被更大的 B 包含，sender 当时未必在 a 内，全扫）；
    /// 有 C → a 主机范围减去所有 C 覆盖区间（多 C 先合并再做差集）。</summary>
    private List<uint> ComputeTargets((uint Network, int Prefix) a)
    {
        var (first, last) = HostRange(a.Network, a.Prefix);

        List<(uint S, uint E)>? covered = null;
        for (int cp = a.Prefix + 1; cp <= 32; cp++)
        {
            if (!_subnetsByPrefix.TryGetValue(cp, out var bucket)) continue;
            // C 网络地址落在 a 的网络地址~广播地址之间；cp > a.Prefix 已保证是真子集
            uint aBroadcast = a.Network + SegmentSize(a.Prefix) - 1;
            foreach (var cnet in bucket.GetViewBetween(a.Network, aBroadcast))
            {
                var (cf, cl) = HostRange(cnet, cp);
                uint s = Math.Max(cf, first);
                uint e = Math.Min(cl, last);
                if (s <= e) (covered ??= new List<(uint, uint)>()).Add((s, e));
            }
        }

        if (covered == null) return RangeToList(first, last);

        covered.Sort((x, y) => x.S.CompareTo(y.S));
        var result = new List<uint>();
        uint cursor = first;
        foreach (var (s, e) in covered)
        {
            // 合并重叠区间并逐段产出差集
            if (s > cursor) AddRange(result, cursor, s - 1);
            if (e >= cursor) cursor = e + 1;
            if (cursor == 0) break; // 已覆盖到 uint.MaxValue
        }
        if (cursor != 0 && cursor <= last) AddRange(result, cursor, last);
        return result;
    }

    /// <summary>F11：本机 IP 在子段内 → 真实 IP + 普通 request；不在 → F52 probe/request 混合。</summary>
    private async Task ScanSubkey(
        (uint Network, int Prefix) key,
        List<uint> hosts,
        int segIndex,
        int segCount,
        uint? localIp,
        MacAddress amac,
        CancellationToken ct)
    {
        _scanner.SetWatchedSender(null); // F52 ⑤：段间状态隔离，清除上一段冒用监视与冲突标志
        _currentKey = key;               // F14：进度文案显示当前待扫描网络号/前缀

        var ipList = hosts.Select(FromUInt32).ToList();
        bool localInside = localIp.HasValue && IsInSubkey(localIp.Value, key);

        if (localInside)
        {
            // 本机真实 IP 在子段内：单轮普通 ARP request，尾部 1.5s 由扫描器内部等待
            await _scanner.ScanAsync(
                ipList, amac, FromUInt32(localIp!.Value), segIndex, segCount, ct).ConfigureAwait(false);
            return;
        }

        await HybridScan(key, ipList, segIndex, segCount, amac, ct);
    }

    /// <summary>
    /// F52 + F53：跨网段 probe/request 混合状态机。设备存在性与空闲候选统一以映射表 IsKnown 判定。
    /// 段内状态（done/freeIps/sender）均为局部变量，方法结束即释放，绝不跨段累积。
    /// </summary>
    private async Task HybridScan(
        (uint Network, int Prefix) key,
        List<IPAddress> hosts,
        int segIndex,
        int segCount,
        MacAddress amac,
        CancellationToken ct)
    {
        // F52 ③：/31、/32 主机数极少，仅 probe 探测 + 被动监听，无 request 轮
        bool probeOnly = key.Prefix >= 31;

        var done = new HashSet<uint>();     // 已发过 probe/request 的地址（不重发）
        var freeIps = new List<uint>();     // probe/request 无应答的空闲候选（仅限当前子段）
        uint? sender = null;
        int probeIdx = hosts.Count - 1;     // probe 从最大 IP 向最小 IP 下探

        while (!ct.IsCancellationRequested)
        {
            if (sender == null)
            {
                // 跳过已处理地址；映射表已认知的地址直接视为有设备，不发 probe、不等 250ms
                while (probeIdx >= 0)
                {
                    uint v = ToUInt32(hosts[probeIdx]);
                    if (!done.Contains(v) && !_mapper.IsKnown(hosts[probeIdx])) break;
                    probeIdx--;
                }
                if (probeIdx < 0) break; // 整段处理完毕

                var ip = hosts[probeIdx];
                done.Add(ToUInt32(ip));
                ReportProbe(segIndex, segCount, ip);
                bool present = await _scanner.ProbeAsync(ip, amac, x => _mapper.IsKnown(x), ct).ConfigureAwait(false);
                if (!present && !probeOnly)
                {
                    // 首个无应答地址即 sender（F52 ①）
                    sender = ToUInt32(ip);
                    freeIps.Add(sender.Value);
                }
                continue;
            }

            // Request 轮：剩余未处理且映射表未知的地址（自动排除 probe 已发现与 sender 自身）
            var targets = hosts
                .Where(h => !done.Contains(ToUInt32(h)) && !_mapper.IsKnown(h))
                .ToList();
            if (targets.Count == 0) break;

            var senderIp = FromUInt32(sender.Value);
            _scanner.SetWatchedSender(senderIp);
            var (sent, conflict) = await _scanner.ScanAsync(
                targets, amac, senderIp, segIndex, segCount, ct);
            _scanner.SetWatchedSender(null);

            foreach (var t in targets.Take(sent))
            {
                done.Add(ToUInt32(t));
                if (!_mapper.IsKnown(t)) freeIps.Add(ToUInt32(t)); // 已发未回 → 空闲候选
            }

            if (conflict != null)
            {
                // F53：冒用地址被静默设备占用（此时映射表必已含冲突 IP），
                // 从当前子段空闲候选中取地址最大者（已被动占用的经 IsKnown 过滤）继续 request
                sender = null;
                foreach (var v in freeIps)
                {
                    if (_mapper.IsKnown(FromUInt32(v))) continue;
                    if (sender == null || v > sender.Value) sender = v;
                }
                // 仍无空闲 → sender=null 回 probe 下探，边发现边找空闲地址
            }
            else
            {
                sender = null; // 本批完成；若还有未处理地址，下一轮回 probe 下探
            }
        }
    }

    private void MarkScanned((uint Network, int Prefix) key)
    {
        _scanned.Add(key);
        if (!_subnetsByPrefix.TryGetValue(key.Prefix, out var bucket))
        {
            bucket = new SortedSet<uint>();
            _subnetsByPrefix[key.Prefix] = bucket;
        }
        bucket.Add(key.Network);
    }

    // ---------------- 数值工具 ----------------

    private static bool IsInSubkey(uint ip, (uint Network, int Prefix) key)
    {
        var (f, l) = HostRange(key.Network, key.Prefix);
        return ip >= f && ip <= l;
    }

    /// <summary>网段地址总数（/32=1, /31=2, 其余 2^主机位）。</summary>
    private static uint SegmentSize(int prefix)
    {
        if (prefix >= 31) return (uint)(33 - prefix); // /32 → 1，/31 → 2
        return (uint)(1UL << (32 - prefix));
    }

    private static List<uint> RangeToList(uint first, uint last)
    {
        var list = new List<uint>((int)(last - first + 1));
        AddRange(list, first, last);
        return list;
    }

    private static void AddRange(List<uint> list, uint first, uint last)
    {
        for (uint v = first; ; v++)
        {
            list.Add(v);
            if (v == last) break; // uint.MaxValue 时靠 break 退出，避免回绕
        }
    }

    // ---------------- 主动扫描收尾与邻居表周期导入 ----------------

    private void FinalizeActive(CancellationToken ct)
    {
        _sniffer.Stop();
        StopNeighborTimer();

        // F5 紧急停止（网卡 Down）：状态已由 EmergencyStop 置为 Stopped，
        // 不再抛状态事件，保留 UI 状态栏的拔线提示；也不做结束时的邻居表导入
        if (_emergencyStopped) return;

        if (!ct.IsCancellationRequested)
        {
            ImportNeighborTable(); // F12：结束再导入一次
            SetState(RunState.Completed, "Scan completed");
        }
        else
        {
            SetState(RunState.Stopped, "Stopped");
        }
    }

    private void StartNeighborTimer()
    {
        StopNeighborTimer();
        _neighborTimer = new System.Threading.Timer(_ =>
        {
            // F12：主动扫描与被动监听进行中均 10s 周期导入（暂停时 State=Paused 不导入）
            if (State == RunState.Scanning) ImportNeighborTable();
        }, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
    }

    private void StopNeighborTimer()
    {
        _neighborTimer?.Dispose();
        _neighborTimer = null;
    }

    /// <summary>F12：读取系统 ARP 邻居表（仅当前网卡网络接口的条目），过滤组播/全零 MAC。</summary>
    public void ImportNeighborTable()
    {
        var ifIndex = _currentAdapter?.IfIndex ?? 0;
        foreach (var (ip, mac, idx) in IpHlpApi.GetArpTable())
        {
            if (ifIndex != 0 && idx != ifIndex) continue; // 不串入其他网卡的邻居
            if (IsMulticastIp(ip)) continue;              // 过滤组播/保留 IP
            if ((mac.B0 & 0x01) != 0) continue;           // 过滤组播 MAC（首字节最低位为 1）
            if (IsZeroMac(mac)) continue;                 // 过滤全零 MAC（不可达残留条目）
            _mapper.AddObservation(ip, mac, IpSource.NeighborTable);
        }
    }

    private static bool IsZeroMac(MacAddress m)
        => (m.B0 | m.B1 | m.B2 | m.B3 | m.B4 | m.B5) == 0;

    private static bool IsMulticastIp(IPAddress ip) => ip.GetAddressBytes()[0] >= 224;

    // ---------------- 进度 ----------------

    private void ReportProbe(int segIndex, int segCount, IPAddress probingIp)
    {
        ProgressChanged?.Invoke(new ScanProgress
        {
            Percent = segCount > 0 ? (double)(segIndex - 1) / segCount * 100 : 0,
            SegmentText = $"Segment {segIndex}/{segCount} · Detecting {KeyText(_currentKey)}, probing {probingIp}",
            EtaText = BuildEta(segIndex, segCount),
            ResultCount = _mapper.Count
        });
    }

    private string BuildEta(int segIndex, int segCount)
    {
        if (_segmentDurations.Count > 0 && segIndex > 1)
        {
            var avg = TimeSpan.FromTicks((long)_segmentDurations.Average(t => t.Ticks));
            var remain = avg * Math.Max(0, segCount - segIndex + 1);
            return remain.TotalMinutes >= 1 ? $"~{remain.TotalMinutes:F1} min" : $"~{remain.TotalSeconds:F0} s";
        }
        return "";
    }

    private void OnScannerProgress(IPAddress ip, IPAddress senderIp, int sent, int total, int segIndex, int segCount)
    {
        double segPercent = total > 0 ? (double)sent / total : 0;
        double overall = segCount > 0 ? (segIndex - 1 + segPercent) / segCount : 0;

        ProgressChanged?.Invoke(new ScanProgress
        {
            Percent = overall * 100,
            SegmentText = $"Segment {segIndex}/{segCount} · Detecting {KeyText(_currentKey)}, requesting {ip}, sent {sent}/{total}, sender {senderIp}",
            EtaText = BuildEta(segIndex, segCount),
            ResultCount = _mapper.Count
        });
    }

    /// <summary>F14：子键显示为"网络号/前缀"，如 192.168.1.0/24。</summary>
    private static string KeyText((uint Network, int Prefix) key)
        => $"{FromUInt32(key.Network)}/{key.Prefix}";

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
}
