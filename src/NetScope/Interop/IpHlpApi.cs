using System;
using System.Net;
using System.Runtime.InteropServices;
using NetScope.Models;

namespace NetScope.Interop;

/// <summary>iphlpapi.dll：GetIpNetTable（ARP 邻居表兜底导入）。</summary>
public static class IpHlpApi
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_IPNETROW
    {
        public uint dwIndex;
        public uint dwPhysAddrLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] bPhysAddr;
        public uint dwAddr;
        public uint dwType;
    }

    [DllImport("iphlpapi.dll")]
    public static extern int GetIpNetTable(IntPtr pIpNetTable, ref uint pdwSize, bool bOrder);

    /// <summary>接口增删/Up/Down/参数变更通知回调（MIB_NOTIFICATION_TYPE）。</summary>
    public delegate void IpInterfaceChangeCallback(IntPtr callerContext, IntPtr row, int notificationType);

    /// <summary>注册接口变更通知（family=0 即 AF_UNSPEC，双栈均通知；initialNotification=false 不补发初始通知）。</summary>
    [DllImport("iphlpapi.dll")]
    public static extern uint NotifyIpInterfaceChange(
        byte family, IpInterfaceChangeCallback callback, IntPtr callerContext,
        bool initialNotification, out IntPtr notificationHandle);

    [DllImport("iphlpapi.dll")]
    public static extern uint CancelMibChangeNotify2(IntPtr notificationHandle);

    public static List<(IPAddress Ip, MacAddress Mac, uint IfIndex)> GetArpTable()
    {
        var result = new List<(IPAddress, MacAddress, uint)>();
        uint size = 0;
        GetIpNetTable(IntPtr.Zero, ref size, false);
        if (size == 0) return result;
        var buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (GetIpNetTable(buf, ref size, false) != 0) return result;
            int count = Marshal.ReadInt32(buf);
            var rowPtr = buf + 4;
            var rowSize = Marshal.SizeOf<MIB_IPNETROW>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_IPNETROW>(rowPtr);
                if (row.dwPhysAddrLen == 6 && row.dwAddr != 0)
                {
                    var mac = new MacAddress(row.bPhysAddr[0], row.bPhysAddr[1], row.bPhysAddr[2],
                                             row.bPhysAddr[3], row.bPhysAddr[4], row.bPhysAddr[5]);
                    var ip = new IPAddress(BitConverter.GetBytes(row.dwAddr));
                    result.Add((ip, mac, row.dwIndex));
                }
                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
        return result;
    }
}
