using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using NetScope.Models;

namespace NetScope.Services;

/// <summary>UI 展示行（按 IP 展开）。</summary>
public class ResultRow
{
    public IPAddress Ip { get; set; } = IPAddress.Any;
    public MacAddress Mac { get; set; }
    public string MacText => Mac.ToString();
    public string? Vendor { get; set; }
    public string? DeviceName { get; set; }
    public string? HostName { get; set; }
    public string SourceText { get; set; } = "";
    /// <summary>F48：该 IP-MAC 对被观察到的次数。</summary>
    public int Count { get; set; }
    /// <summary>非 null 表示该 IP 存在多 MAC 映射（冲突），内容为各 MAC 的时间线。</summary>
    public List<(MacAddress Mac, DateTime First, DateTime Last)>? ConflictTimeline { get; set; }
}

/// <summary>MapperService 的完整内部状态，用于按网卡独立保存/恢复。</summary>
public class MapperState
{
    public ConcurrentDictionary<MacAddress, MacRecord> ByMac { get; set; } = new();
    public ConcurrentDictionary<IPAddress, HashSet<MacAddress>> IpToMacs { get; set; } = new();
    public LinkedList<MacAddress> Lru { get; set; } = new();
}

/// <summary>
/// F26–F28：以 MAC 为主键的映射表 + IP 冲突检测；F48 每 IP-MAC 对观察计数。
/// </summary>
public class MapperService
{
    private const int MaxMacs = 10_000;      // NF4
    private const int MaxMacsPerIp = 16;     // F27

    private readonly ConcurrentDictionary<MacAddress, MacRecord> _byMac = new();
    private readonly ConcurrentDictionary<IPAddress, HashSet<MacAddress>> _ipToMacs = new();
    private readonly LinkedList<MacAddress> _lru = new();
    private readonly object _lruLock = new();

    private readonly OuiLookup _oui;
    private readonly ReverseDnsService _dns;

    /// <summary>有新数据或更新时触发（参数为受影响 IP，null 表示全量刷新）。</summary>
    public event Action<IPAddress?>? Changed;
    /// <summary>每次学到（含已存在仅更新时间）的 (IP, MAC) 对均触发，供冒用冲突检测统一消费。</summary>
    public event Action<IPAddress, MacAddress>? IpMacObserved;

    public MapperService(OuiLookup oui, ReverseDnsService dns)
    {
        _oui = oui;
        _dns = dns;
        _dns.HostResolved += OnHostResolved;
    }

    public void AddObservation(IPAddress ip, MacAddress mac, IpSource source)
    {
        var now = DateTime.Now;
        var rec = _byMac.GetOrAdd(mac, m =>
        {
            TouchLru(m);
            return new MacRecord(m) { Vendor = _oui.LookupVendor(m) };
        });
        TouchLru(mac);

        lock (rec)
        {
            rec.LastSeen = now;
            var entry = rec.Ips.FirstOrDefault(e => e.Ip.Equals(ip));
            if (entry == null)
            {
                entry = new IpEntry(ip, source);
                rec.Ips.Add(entry);
                _dns.Enqueue(ip); // F30：新 IP 异步反向 DNS
            }
            else
            {
                // (IP, MAC) 映射已存在：只更新时间与计数，不覆盖原有的来源通道记录（F26 来源不覆盖；F48 计数 +1）
                entry.LastSeen = now;
                entry.Count++;
            }
        }

        // IP → MAC 集合（冲突检测）
        var set = _ipToMacs.GetOrAdd(ip, _ => new HashSet<MacAddress>());
        lock (set)
        {
            if (!set.Contains(mac) && set.Count < MaxMacsPerIp)
                set.Add(mac);
        }

        EvictIfNeeded();
        Changed?.Invoke(ip);
        IpMacObserved?.Invoke(ip, mac);
    }

    public void SetLldpSystemName(MacAddress mac, string name)
    {
        if (!_byMac.TryGetValue(mac, out var rec)) return;
        lock (rec)
        {
            rec.LldpSystemName = name;
            rec.DeviceName ??= name; // LLDP 名字优先，但不覆盖已有
            if (string.IsNullOrEmpty(rec.DeviceName)) rec.DeviceName = name;
        }
        Changed?.Invoke(null);
    }

    private void OnHostResolved(IPAddress ip, string? hostName)
    {
        if (hostName == null) return;
        // 经 IP→MAC 反查精确定位记录，避免每个 DNS 结果遍历全表（大表下 O(n) 锁竞争）
        if (!_ipToMacs.TryGetValue(ip, out var macs)) return;
        MacAddress[] snapshot;
        lock (macs) snapshot = macs.ToArray();
        foreach (var mac in snapshot)
        {
            if (!_byMac.TryGetValue(mac, out var rec)) continue;
            lock (rec)
            {
                var entry = rec.Ips.FirstOrDefault(e => e.Ip.Equals(ip));
                if (entry == null) continue;
                entry.HostName = hostName;
                // F30：无其他名字来源时作设备名；同时匹配主机名规则库
                var label = _oui.LookupByHostName(hostName);
                if (rec.LldpSystemName == null)
                {
                    if (label != null && (rec.DeviceName == null || rec.DeviceName == rec.Vendor))
                        rec.DeviceName = label;
                    rec.DeviceName ??= hostName;
                }
            }
        }
        Changed?.Invoke(ip);
    }

    /// <summary>该 IP 是否已由任何协议（ARP/IPv4/RARP/LLDP/邻居表）观察到。
    /// 主动扫描以此统一判定设备存在性与候选空闲地址，替代独立的"已发未回"登记表。</summary>
    public bool IsKnown(IPAddress ip) => _ipToMacs.ContainsKey(ip);

    /// <summary>该 IP 当前是否映射到多个 MAC（冲突）。</summary>
    public bool IsIpConflicted(IPAddress ip)
        => _ipToMacs.TryGetValue(ip, out var set) && set.Count >= 2;

    public List<ResultRow> Snapshot()
    {
        var rows = new List<ResultRow>();
        foreach (var (_, rec) in _byMac)
        {
            lock (rec)
            {
                foreach (var e in rec.Ips)
                {
                    rows.Add(new ResultRow
                    {
                        Ip = e.Ip,
                        Mac = rec.Mac,
                        Vendor = rec.Vendor,
                        DeviceName = rec.DeviceName,
                        HostName = e.HostName,
                        SourceText = SourceToText(e.Source),
                        Count = e.Count,
                        ConflictTimeline = IsIpConflicted(e.Ip) ? BuildTimeline(e.Ip) : null
                    });
                }
            }
        }
        return rows.OrderBy(r => BitConverter.ToUInt32(r.Ip.GetAddressBytes().Reverse().ToArray(), 0)).ToList();
    }

    public List<(MacAddress, DateTime, DateTime)>? BuildTimeline(IPAddress ip)
    {
        if (!_ipToMacs.TryGetValue(ip, out var set)) return null;
        MacAddress[] macs;
        lock (set) macs = set.ToArray();
        var list = new List<(MacAddress, DateTime, DateTime)>();
        foreach (var m in macs)
        {
            if (!_byMac.TryGetValue(m, out var rec)) continue;
            lock (rec)
            {
                var e = rec.Ips.FirstOrDefault(x => x.Ip.Equals(ip));
                if (e != null) list.Add((m, e.FirstSeen, e.LastSeen));
            }
        }
        return list;
    }

    public int Count => _byMac.Count;

    public void Clear()
    {
        _byMac.Clear();
        _ipToMacs.Clear();
        lock (_lruLock) _lru.Clear();
        Changed?.Invoke(null);
    }

    /// <summary>导出完整状态（深拷贝 HashSet），供按网卡切换时保存。</summary>
    public MapperState ExportState()
    {
        var byMac = new ConcurrentDictionary<MacAddress, MacRecord>();
        foreach (var kvp in _byMac) byMac[kvp.Key] = kvp.Value;

        var ipToMacs = new ConcurrentDictionary<IPAddress, HashSet<MacAddress>>();
        foreach (var kvp in _ipToMacs)
        {
            HashSet<MacAddress> copy;
            lock (kvp.Value) copy = new HashSet<MacAddress>(kvp.Value);
            ipToMacs[kvp.Key] = copy;
        }

        var lru = new LinkedList<MacAddress>();
        lock (_lruLock) foreach (var m in _lru) lru.AddLast(m);

        return new MapperState { ByMac = byMac, IpToMacs = ipToMacs, Lru = lru };
    }

    /// <summary>恢复完整状态（深拷贝 HashSet，避免与快照共享引用）。</summary>
    public void ImportState(MapperState state)
    {
        _byMac.Clear();
        foreach (var kvp in state.ByMac) _byMac[kvp.Key] = kvp.Value;

        _ipToMacs.Clear();
        foreach (var kvp in state.IpToMacs)
            _ipToMacs[kvp.Key] = new HashSet<MacAddress>(kvp.Value);

        lock (_lruLock)
        {
            _lru.Clear();
            foreach (var m in state.Lru) _lru.AddLast(m);
        }
        Changed?.Invoke(null);
    }

    public static string SourceToText(IpSource s) => s switch
    {
        IpSource.ArpReply => "ARP Reply",
        IpSource.Ipv4Packet => "IPv4",
        IpSource.Lldp => "LLDP",
        IpSource.ArpProbe => "ARP Probe",
        IpSource.GratuitousArp => "Gratuitous ARP",
        IpSource.NeighborTable => "Neighbor Table",
        IpSource.Rarp => "RARP",
        IpSource.ArpRequest => "ARP Request",
        _ => s.ToString()
    };

    private void TouchLru(MacAddress mac)
    {
        lock (_lruLock)
        {
            var node = _lru.Find(mac);
            if (node != null) _lru.Remove(node);
            _lru.AddFirst(mac);
        }
    }

    private void EvictIfNeeded()
    {
        while (_byMac.Count > MaxMacs)
        {
            MacAddress victim;
            lock (_lruLock)
            {
                if (_lru.Last == null) break;
                victim = _lru.Last.Value;
                _lru.RemoveLast();
            }
            if (_byMac.TryRemove(victim, out var rec))
            {
                lock (rec)
                    foreach (var e in rec.Ips)
                        if (_ipToMacs.TryGetValue(e.Ip, out var set))
                            lock (set) { set.Remove(victim); if (set.Count == 0) _ipToMacs.TryRemove(e.Ip, out _); }
            }
        }
    }
}
