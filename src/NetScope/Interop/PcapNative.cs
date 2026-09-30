using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace NetScope.Interop;

/// <summary>
/// wpcap.dll (Npcap) 最小 P/Invoke 集。
/// </summary>
public static class PcapNative
{
    private const string Lib = "wpcap.dll";

    public const int PCAP_ERRBUF_SIZE = 256;

    [StructLayout(LayoutKind.Sequential)]
    public struct pcap_pkthdr
    {
        public IntPtr ts;       // struct timeval { long tv_sec; long tv_usec; }
        public uint caplen;
        public uint len;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct pcap_if
    {
        public IntPtr next;
        public IntPtr name;
        public IntPtr description;
        public IntPtr addresses;
        public uint flags;
    }

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int pcap_findalldevs(out IntPtr alldevsp, StringBuilder errbuf);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_freealldevs(IntPtr alldevsp);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr pcap_open_live(string device, int snaplen, int promisc, int to_ms, StringBuilder errbuf);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_next_ex(IntPtr p, out IntPtr pktHeader, out IntPtr pktData);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_sendpacket(IntPtr p, byte[] buf, int size);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_breakloop(IntPtr p);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_close(IntPtr p);

    // ---- BPF 过滤器（F68：DCP 独立句柄过滤 ether proto 0x8892）----

    [StructLayout(LayoutKind.Sequential)]
    public struct bpf_insn
    {
        public ushort code;
        public byte jt;
        public byte jf;
        public uint k;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct bpf_program
    {
        public uint bf_len;
        public IntPtr bf_insns;
    }

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int pcap_compile(IntPtr p, out bpf_program fp, string str, int optimize, uint netmask);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_setfilter(IntPtr p, ref bpf_program fp);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_freecode(ref bpf_program fp);

    /// <summary>设置 BPF 过滤器（如 "ether proto 0x8892"）。失败返回 false。</summary>
    public static bool TrySetFilter(IntPtr handle, string filter)
    {
        try
        {
            if (pcap_compile(handle, out var prog, filter, 1, 0) != 0) return false;
            int rc = pcap_setfilter(handle, ref prog);
            pcap_freecode(ref prog);
            return rc == 0;
        }
        catch { return false; }
    }

    public static List<(string Name, string Desc)> FindAllDevs()
    {
        var list = new List<(string, string)>();
        var err = new StringBuilder(PCAP_ERRBUF_SIZE);
        if (pcap_findalldevs(out var alldevs, err) != 0 || alldevs == IntPtr.Zero)
            return list;
        try
        {
            var cur = alldevs;
            while (cur != IntPtr.Zero)
            {
                var dev = Marshal.PtrToStructure<pcap_if>(cur);
                var name = dev.name != IntPtr.Zero ? Marshal.PtrToStringAnsi(dev.name) ?? "" : "";
                var desc = dev.description != IntPtr.Zero ? Marshal.PtrToStringAnsi(dev.description) ?? "" : "";
                list.Add((name, desc));
                cur = dev.next;
            }
        }
        finally
        {
            pcap_freealldevs(alldevs);
        }
        return list;
    }
}
