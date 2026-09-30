using System;
using System.Net;
using NetScope.Models;

namespace NetScope.Services;

/// <summary>
/// 按 EtherType 分派解析二层帧。
/// 主动扫描与被动监听两种模式均处理 IPv4 / ARP / RARP / LLDP 全部报文，不做网段过滤。
/// </summary>
public static class PacketParser
{
    public const ushort EtherTypeIPv4 = 0x0800;
    public const ushort EtherTypeArp = 0x0806;
    public const ushort EtherTypeRarp = 0x8035;
    public const ushort EtherTypeLldp = 0x88CC;

    public static void Parse(
        ReadOnlySpan<byte> frame,
        MapperService mapper,
        MacAddress? ignoreMac = null)
    {
        if (frame.Length < 14) return;

        var srcMac = MacAddress.Parse(frame.Slice(6, 6));
        if (ignoreMac.HasValue && srcMac == ignoreMac.Value) return;
        ushort ethType = ReadUInt16BE(frame.Slice(12, 2));
        int offset = 14;

        while (ethType is 0x8100 or 0x88A8 or 0x9100)
        {
            if (frame.Length < offset + 4) return;
            ethType = ReadUInt16BE(frame.Slice(offset + 2, 2));
            offset += 4;
        }

        switch (ethType)
        {
            case EtherTypeIPv4:
                ParseIPv4(frame.Slice(offset), srcMac, mapper);
                break;
            case EtherTypeArp:
                ParseArp(frame.Slice(offset), srcMac, mapper);
                break;
            case EtherTypeRarp:
                ParseRarp(frame.Slice(offset), srcMac, mapper);
                break;
            case EtherTypeLldp:
                ParseLldp(frame.Slice(offset), srcMac, mapper);
                break;
        }
    }

    private static void ParseIPv4(ReadOnlySpan<byte> pkt, MacAddress srcMac, MapperService mapper)
    {
        if (pkt.Length < 20) return;
        var srcIp = new IPAddress(pkt.Slice(12, 4).ToArray());
        if (IsSaneIp(srcIp))
            mapper.AddObservation(srcIp, srcMac, IpSource.Ipv4Packet);
    }

    private static void ParseArp(
        ReadOnlySpan<byte> pkt,
        MacAddress frameSrcMac,
        MapperService mapper)
    {
        if (pkt.Length < 28) return;
        ushort oper = ReadUInt16BE(pkt.Slice(6, 2));
        var senderMac = MacAddress.Parse(pkt.Slice(8, 6));
        var senderIp = new IPAddress(pkt.Slice(14, 4).ToArray());
        var targetIp = new IPAddress(pkt.Slice(24, 4).ToArray());

        // ARP 探针（F21②）：sender=0.0.0.0 → 取 target IP（不限制 target 所在网段）
        if (senderIp.Equals(IPAddress.Any))
        {
            if (IsSaneIp(targetIp))
                mapper.AddObservation(targetIp, senderMac, IpSource.ArpProbe);
            return;
        }

        if (!IsSaneIp(senderIp)) return;

        if (senderIp.Equals(targetIp))
        {
            // 免费 ARP（F21③，对方主动发送，不要求 sender IP 在当前网段）
            mapper.AddObservation(senderIp, senderMac, IpSource.GratuitousArp);
            return;
        }

        if (oper == 2)
        {
            // ARP reply（可能是切换段后延迟到达的，不按网段过滤）
            mapper.AddObservation(senderIp, senderMac, IpSource.ArpReply);
            return;
        }

        // 被动模式下 ARP request 也记录（暴露发送方）；本机发出的 request 已被 IgnoreMac 在帧级过滤
        mapper.AddObservation(senderIp, senderMac, IpSource.ArpRequest);
    }

    private static void ParseRarp(ReadOnlySpan<byte> pkt, MacAddress srcMac, MapperService mapper)
    {
        if (pkt.Length < 28) return;
        var senderMac = MacAddress.Parse(pkt.Slice(8, 6));
        var senderIp = new IPAddress(pkt.Slice(14, 4).ToArray());
        if (IsSaneIp(senderIp))
            mapper.AddObservation(senderIp, senderMac, IpSource.Rarp);
    }

    private static void ParseLldp(ReadOnlySpan<byte> pkt, MacAddress srcMac, MapperService mapper)
    {
        int pos = 0;
        string? sysName = null;
        IPAddress? mgmtIp = null;

        while (pos + 2 <= pkt.Length)
        {
            ushort hdr = ReadUInt16BE(pkt.Slice(pos, 2));
            int type = (hdr >> 9) & 0x7F;
            int len = hdr & 0x1FF;
            pos += 2;
            if (type == 0 && len == 0) break;
            if (pos + len > pkt.Length) break;

            var value = pkt.Slice(pos, len);
            if (type == 5)
                sysName = System.Text.Encoding.UTF8.GetString(value).Trim('\0', ' ', '\r', '\n');
            else if (type == 8 && len >= 5)
            {
                int addrLen = value[0];
                if (addrLen == 5 && value[1] == 1 && len >= 1 + addrLen)
                    mgmtIp = new IPAddress(value.Slice(2, 4).ToArray());
            }
            pos += len;
        }

        if (sysName != null)
            mapper.SetLldpSystemName(srcMac, sysName);
        if (mgmtIp != null && IsSaneIp(mgmtIp))
            mapper.AddObservation(mgmtIp, srcMac, IpSource.Lldp);
    }

    private static bool IsSaneIp(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (b[0] == 0 || b[0] == 127) return false;
        // 169.254 APIPA 段放行：阶段3 专门扫描 APIPA 设备，其 reply/免费ARP/常规流量均需入表
        if (b[0] >= 224) return false;
        return true;
    }

    private static ushort ReadUInt16BE(ReadOnlySpan<byte> s) => (ushort)((s[0] << 8) | s[1]);
}
