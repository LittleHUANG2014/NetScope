namespace NetScope.Models;

public enum IpSource
{
    ArpReply,    // ARP 应答
    Ipv4Packet,  // IPv4 数据包源地址
    Lldp,        // LLDP 管理地址
    ArpProbe,    // ARP Probe (sender=0.0.0.0)
    GratuitousArp, // 免费 ARP (sender IP == target IP)
    NeighborTable, // 扫描后读取系统 ARP 邻居表
    Rarp,        // RARP
    ArpRequest,  // ARP 请求（其他主机的 sender 信息）
}
