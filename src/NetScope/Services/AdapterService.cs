using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetScope.Services;

public class AdapterInfo
{
    public string Id { get; set; } = "";            // GUID（与 \Device\NPF_{GUID} 对应）
    public string Name { get; set; } = "";          // "以太网"
    public string Description { get; set; } = "";
    public IPAddress? IPv4 { get; set; }
    public int PrefixLength { get; set; }
    public IPAddress? Gateway { get; set; }
    public bool IsDhcp { get; set; }
    public bool IsUp { get; set; }
    public NetworkInterfaceType InterfaceType { get; set; }
    public uint IfIndex { get; set; }               // Windows 接口索引（用于过滤对应网卡的 ARP 邻居表）
    public string PcapName => $"\\Device\\NPF_{Id}";

    public string DisplayText =>
        IPv4 != null
            ? $"{Name}  ({IPv4}/{PrefixLength})"
            : $"{Name}  (No IPv4)";
}

/// <summary>
/// F1–F4：网卡枚举、过滤伪接口、默认选中"以太网"。
/// </summary>
public static class AdapterService
{
    private static readonly string[] PseudoKeywords =
    {
        "npcap", "wfp", "wan miniport", "virtualbox", "vmware", "hyper-v",
        "vethernet", "loopback", "pseudo", "teredo", "isatap", "6to4",
        "bluetooth", "tailscale", "zerotier", "wireguard", "openvpn", "tap-windows"
    };

    public static List<AdapterInfo> Enumerate()
    {
        var list = new List<AdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var desc = (nic.Description + " " + nic.Name).ToLowerInvariant();
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            if (PseudoKeywords.Any(k => desc.Contains(k))) continue;

            var props = nic.GetIPProperties();
            var uni = props.UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
            var gw = props.GatewayAddresses
                .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork);

            list.Add(new AdapterInfo
            {
                Id = nic.Id,
                Name = nic.Name,
                Description = nic.Description,
                IPv4 = uni?.Address,
                PrefixLength = uni?.PrefixLength ?? 0,
                Gateway = gw?.Address,
                IsDhcp = props.GetIPv4Properties()?.IsDhcpEnabled ?? false,
                IsUp = nic.OperationalStatus == OperationalStatus.Up,
                InterfaceType = nic.NetworkInterfaceType,
                IfIndex = (uint)(props.GetIPv4Properties()?.Index ?? 0)
            });
        }
        return list;
    }

    /// <summary>F4：默认选中名为"以太网"或"Ethernet"的网卡，否则第一张 Up 的。</summary>
    public static AdapterInfo? PickDefault(List<AdapterInfo> list)
    {
        return list.FirstOrDefault(a => a.Name is "以太网" or "Ethernet")
               ?? list.FirstOrDefault(a => a.IsUp && a.IPv4 != null)
               ?? list.FirstOrDefault();
    }

    public static IPAddress GetNetworkAddress(IPAddress ip, int prefix)
        => FromUInt32(NetworkOf(ToUInt32(ip), prefix));

    /// <summary>IPv4 → 主机序 uint（192.168.0.1 = 0xC0A80001）。</summary>
    public static uint ToUInt32(IPAddress ip)
        => BitConverter.ToUInt32(ip.GetAddressBytes().Reverse().ToArray(), 0);

    /// <summary>主机序 uint → IPv4。</summary>
    public static IPAddress FromUInt32(uint v)
        => new(BitConverter.GetBytes(v).Reverse().ToArray());

    /// <summary>前缀掩码（/24 = 0xFFFFFF00）。</summary>
    public static uint PrefixMask(int prefix)
        => prefix <= 0 ? 0u : prefix >= 32 ? 0xFFFFFFFFu : 0xFFFFFFFFu << (32 - prefix);

    /// <summary>网络地址（主机位清零）。</summary>
    public static uint NetworkOf(uint ip, int prefix) => ip & PrefixMask(prefix);

    /// <summary>
    /// 子网主机地址闭区间 [first, last]（用于统一 CIDR 比对与扫描）：
    /// /32 → 单地址；/31 → 网络地址+对端（RFC 3021 点对点）；其余 → 去网络号与广播。
    /// </summary>
    public static (uint First, uint Last) HostRange(uint network, int prefix)
    {
        if (prefix == 32) return (network, network);
        if (prefix == 31) return (network, network + 1);
        if (prefix <= 0) return (network + 1, uint.MaxValue - 1);
        ulong size = 1UL << (32 - prefix);
        return (network + 1, network + (uint)size - 2);
    }

    public static IEnumerable<IPAddress> EnumerateHosts(IPAddress network, int prefix)
    {
        uint net = ToUInt32(network);
        var (first, last) = HostRange(net, prefix);
        for (uint i = first; i <= last; i++)
        {
            if (i == uint.MaxValue) { yield return FromUInt32(i); yield break; }
            yield return FromUInt32(i);
        }
    }
}
