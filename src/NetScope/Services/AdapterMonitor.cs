using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using NetScope.Interop;

namespace NetScope.Services;

/// <summary>
/// F5：网卡热插拔监控。
/// 事件源：iphlpapi NotifyIpInterfaceChange（按接口通知 Up/Down/增删，不受其他网卡在线或静态 IP 影响）；
/// NetworkChange 仅作辅助触发——NetworkAvailabilityChanged 只在整机"有网↔无网"切换时触发（多网卡时拔网线不触发），
/// NetworkAddressChanged 只在地址增删时触发（静态 IP 拔线地址不消失、不触发），两者均不可靠。
/// 所有触发统一经防抖后重新枚举 + 与基线 diff 判定 Up/Down/移除。
/// </summary>
public class AdapterMonitor : IDisposable
{
    private readonly System.Threading.Timer _debounce;
    private const int DebounceMs = 1200; // DHCP 就绪延迟

    /// <summary>物理网卡 Down→Up（已延迟刷新）。参数为 AdapterInfo.Id（GUID）。</summary>
    public event Action<string>? AdapterUp;
    /// <summary>物理网卡 Up→Down。参数为 AdapterInfo.Id。</summary>
    public event Action<string>? AdapterDown;
    /// <summary>网卡硬件移除（枚举中消失）。参数为 AdapterInfo.Id。</summary>
    public event Action<string>? AdapterRemoved;
    /// <summary>新增网卡且当前为 Down（无链路）：静默加入下拉列表，不切卡不弹窗。参数为 AdapterInfo.Id。</summary>
    public event Action<string>? AdapterAdded;

    /// <summary>基线：已枚举到过的网卡 Id → 当时是否 Up（含 Down 的网卡，以便其被移除时也能识别）。</summary>
    private readonly System.Collections.Generic.Dictionary<string, bool> _known = new();
    private readonly object _lock = new();

    private readonly IpHlpApi.IpInterfaceChangeCallback _notifyCallback;
    private IntPtr _notifyHandle;

    public AdapterMonitor()
    {
        _debounce = new System.Threading.Timer(OnDebounce, null, Timeout.Infinite, Timeout.Infinite);
        _notifyCallback = OnIpInterfaceChanged;
        // 返回值非 0 表示注册失败，仍保留 NetworkChange 辅助触发兜底
        IpHlpApi.NotifyIpInterfaceChange(0, _notifyCallback, IntPtr.Zero, false, out _notifyHandle);
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged += OnNetworkChanged;
    }

    public void InitBaseline()
    {
        lock (_lock)
        {
            _known.Clear();
            foreach (var a in AdapterService.Enumerate())
                _known[a.Id] = a.IsUp;
        }
    }

    private void OnIpInterfaceChanged(IntPtr callerContext, IntPtr row, int notificationType)
        => _debounce.Change(DebounceMs, Timeout.Infinite);

    private void OnNetworkChanged(object? sender, EventArgs e)
        => _debounce.Change(DebounceMs, Timeout.Infinite);

    private void OnDebounce(object? state)
    {
        var current = AdapterService.Enumerate();
        lock (_lock)
        {
            // 硬件移除：基线中存在但本次枚举不到的网卡
            var currentIds = new System.Collections.Generic.HashSet<string>(current.Select(a => a.Id));
            foreach (var id in _known.Keys.ToList())
            {
                if (currentIds.Contains(id)) continue;
                _known.Remove(id);
                AdapterRemoved?.Invoke(id);
            }
            // Up/Down 跳变与新出现网卡
            foreach (var a in current)
            {
                if (!_known.TryGetValue(a.Id, out var wasUp))
                {
                    _known[a.Id] = a.IsUp;
                    // 新增网卡：已是 Up 走 Up 分支（空闲时切卡+弹窗）；Down 则仅静默入列表
                    if (a.IsUp) AdapterUp?.Invoke(a.Id);
                    else AdapterAdded?.Invoke(a.Id);
                }
                else if (wasUp != a.IsUp)
                {
                    _known[a.Id] = a.IsUp;
                    if (a.IsUp) AdapterUp?.Invoke(a.Id);
                    else AdapterDown?.Invoke(a.Id);
                }
            }
        }
    }

    public void Dispose()
    {
        if (_notifyHandle != IntPtr.Zero)
        {
            IpHlpApi.CancelMibChangeNotify2(_notifyHandle);
            _notifyHandle = IntPtr.Zero;
        }
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkChanged;
        _debounce.Dispose();
    }
}
