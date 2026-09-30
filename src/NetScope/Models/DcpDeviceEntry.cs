using System;
using System.Net;

namespace NetScope.Models;

/// <summary>
/// F61/F62：DCP 设备表条目（独立于 F26 映射表）。以 MAC 为主键，
/// 记录 Identify OK 解析出的各 TLV 字段。Count = 本轮收到该设备 Identify OK 的帧数。
/// </summary>
public class DcpDeviceEntry
{
    public MacAddress Mac { get; set; }

    // (2,3) DeviceID
    public ushort VendorId { get; set; }
    public ushort DeviceId { get; set; }

    // (2,1) Manufacturer — 完整 ASCII
    public string? Manufacturer { get; set; }

    // (2,2) NameOfStation
    public string? NameOfStation { get; set; }

    // (1,2) IP 参数
    public IPAddress? Ip { get; set; }
    public IPAddress? SubnetMask { get; set; }
    public IPAddress? Gateway { get; set; }
    /// <summary>IP 块的 block_info（0 = 无 IP 设置，1 = 有 IP 设置）。</summary>
    public ushort IpBlockInfo { get; set; }

    // 厂商名（PNO VendorID 查表优先，OUI 兜底）
    public string? VendorName { get; set; }

    /// <summary>F62 Count：本轮收到该设备 Identify OK 的帧数。</summary>
    public int Count { get; set; }

    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }

    /// <summary>是否已学习到 IP（IP 块存在且 block_info != 0）。</summary>
    public bool HasIp => Ip != null && IpBlockInfo != 0 && !Ip.Equals(IPAddress.Any);

    /// <summary>F62：IPv4 列显示 IP/前缀；无 IP 设备显示 0.0.0.0/0；IP 块缺失留空。</summary>
    public string IpDisplay
    {
        get
        {
            if (Ip == null) return "";
            var ip = HasIp ? Ip : IPAddress.Any;
            int prefix = MaskToPrefix(SubnetMask);
            if (!HasIp) prefix = 0;
            return $"{ip}/{prefix}";
        }
    }

    /// <summary>掩码 → 前缀长度（如 255.255.255.0 → 24）。掩码为 null 返回 0。</summary>
    public static int MaskToPrefix(IPAddress? mask)
    {
        if (mask == null) return 0;
        var bytes = mask.GetAddressBytes();
        if (bytes.Length != 4) return 0;
        uint m = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        int prefix = 0;
        while (m != 0) { prefix++; m <<= 1; }
        return prefix;
    }

    /// <summary>当前值快照（用于 Set 差分比较）。</summary>
    public DcpDeviceSnapshot Snapshot() => new()
    {
        NameOfStation = NameOfStation ?? "",
        Ip = HasIp ? Ip! : IPAddress.Any,
        SubnetMask = SubnetMask ?? IPAddress.Any,
        Gateway = Gateway ?? IPAddress.Any
    };
}

/// <summary>设备当前值的可变快照，用于 Set IP 表单编辑与差分比较。</summary>
public class DcpDeviceSnapshot
{
    public string NameOfStation { get; set; } = "";
    public IPAddress Ip { get; set; } = IPAddress.Any;
    public IPAddress SubnetMask { get; set; } = IPAddress.Any;
    public IPAddress Gateway { get; set; } = IPAddress.Any;
}

/// <summary>
/// F62：DCP 模式下结果表的 UI 行（与 ResultRow 同属性名，DataGrid 绑定兼容）。
/// Ip 为字符串（"IP/前缀"、"0.0.0.0/0" 或空），不同于 ResultRow.Ip 的 IPAddress。
/// </summary>
public class DcpResultRow
{
    public string Ip { get; set; } = "";
    public string MacText { get; set; } = "";
    public string? Vendor { get; set; }
    public string? DeviceName { get; set; }   // (2,1) Manufacturer
    public string? HostName { get; set; }     // (2,2) NameOfStation
    public string SourceText { get; set; } = "DCP";
    public int Count { get; set; }
    /// <summary>设备 MAC（双击操作时回查内部设备表）。</summary>
    public MacAddress Mac { get; set; }
}
