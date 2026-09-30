using System;
using System.Net;

namespace NetScope.Models;

public class IpEntry
{
    public IPAddress Ip { get; }
    public IpSource Source { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public string? HostName { get; set; }
    /// <summary>F48：该 (IP, MAC) 对被观察到的次数（新对初始 1，再次观察累加，邻居表导入每条也算）。</summary>
    public int Count { get; set; } = 1;

    public IpEntry(IPAddress ip, IpSource source)
    {
        Ip = ip;
        Source = source;
        FirstSeen = DateTime.Now;
        LastSeen = DateTime.Now;
    }
}
