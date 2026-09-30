using System;
using System.Collections.Generic;
using System.Net;

namespace NetScope.Models;

public class MacRecord
{
    public MacAddress Mac { get; }
    public List<IpEntry> Ips { get; } = new();
    public string? Vendor { get; set; }
    public string? DeviceName { get; set; }
    public string? LldpSystemName { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public bool IsConflict => Ips.Count >= 2; // 同一MAC多IP不算冲突；冲突在IP级别检测

    public MacRecord(MacAddress mac)
    {
        Mac = mac;
        FirstSeen = DateTime.Now;
        LastSeen = DateTime.Now;
    }

    public bool HasIp(IPAddress ip)
    {
        foreach (var e in Ips)
            if (e.Ip.Equals(ip)) return true;
        return false;
    }
}
