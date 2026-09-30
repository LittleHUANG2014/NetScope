using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetScope.Interop;

namespace NetScope.Services;

/// <summary>
/// F19/F24/F25：Npcap 混杂模式被动监听。抓包线程与 UI 解耦（事件入队，UI 定时刷新）。
/// 主动扫描与被动监听共用同一解析链，均处理 IPv4/ARP/RARP/LLDP 全部报文。
/// </summary>
public class PassiveSniffer : IDisposable
{
    private readonly MapperService _mapper;
    private IntPtr _handle;
    private Thread? _thread;
    private volatile bool _running;
    private string _deviceName = "";

    public bool IsRunning => _running;
    public long PacketCount { get; private set; }
    /// <summary>恢复/设置抓包计数（按网卡切换时使用）。</summary>
    public void SetPacketCount(long count) => PacketCount = count;
    /// <summary>本机 MAC，用于过滤自己发出的帧（主动扫描时避免自记录）。</summary>
    public Models.MacAddress? IgnoreMac { get; set; }
    public event Action<string>? Error;

    public PassiveSniffer(MapperService mapper) => _mapper = mapper;

    public bool Start(string pcapDeviceName)
    {
        if (_running) return true;
        NpcapManager.EnsureDllResolver();
        var err = new StringBuilder(PcapNative.PCAP_ERRBUF_SIZE);
        _handle = PcapNative.pcap_open_live(pcapDeviceName, 65536, 1, 100, err);
        if (_handle == IntPtr.Zero)
        {
            Error?.Invoke($"Failed to open the adapter for capture: {err}");
            return false;
        }
        _deviceName = pcapDeviceName;
        _running = true;
        _thread = new Thread(Loop) { IsBackground = true, Name = "PassiveSniffer" };
        _thread.Start();
        return true;
    }

    private void Loop()
    {
        var err = new StringBuilder(PcapNative.PCAP_ERRBUF_SIZE);
        while (_running)
        {
            int rc = PcapNative.pcap_next_ex(_handle, out var hdrPtr, out var dataPtr);
            if (rc == 0) continue;                    // 超时，检查退出标志
            if (rc < 0) break;                        // 错误或被 breakloop
            if (hdrPtr == IntPtr.Zero || dataPtr == IntPtr.Zero) continue;

            var hdr = Marshal.PtrToStructure<PcapNative.pcap_pkthdr>(hdrPtr);
            if (hdr.caplen == 0 || hdr.caplen > 262144) continue;
            var buf = new byte[hdr.caplen];
            Marshal.Copy(dataPtr, buf, 0, (int)hdr.caplen);
            PacketCount++;
            try
            {
                PacketParser.Parse(buf, _mapper, IgnoreMac);
            }
            catch { /* 单帧解析异常不影响抓包循环（NF2） */ }
        }
        _running = false;
    }

    public void Stop()
    {
        if (!_running) return;
        _running = false;
        if (_handle != IntPtr.Zero)
            PcapNative.pcap_breakloop(_handle);
        _thread?.Join(2000);
        if (_handle != IntPtr.Zero)
        {
            PcapNative.pcap_close(_handle);
            _handle = IntPtr.Zero;
        }
    }

    public void Dispose() => Stop();
}
