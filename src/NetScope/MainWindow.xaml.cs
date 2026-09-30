using System;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using NetScope.Models;
using NetScope.Services;
using WF = System.Windows.Forms;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
using MessageBoxResult = System.Windows.MessageBoxResult;
using Color = System.Windows.Media.Color;
using Brushes = System.Windows.Media.Brushes;

namespace NetScope;

public partial class MainWindow : Window
{
    private readonly OuiLookup _oui = new();
    private readonly ReverseDnsService _dns = new();
    private readonly MapperService _mapper;
    private readonly PassiveSniffer _sniffer;
    private readonly ActiveArpScanner _scanner;
    private readonly ScanOrchestrator _orch;
    private readonly AdapterMonitor _monitor = new();
    private readonly PnoVendorLookup _pnoLookup;
    private readonly DcpService _dcp;
    private bool _dcpMode;

    private readonly DispatcherTimer _refreshTimer;
    private bool _dirty;

    private WF.NotifyIcon? _tray;
    private bool _closePending;
    private bool _loadingAdapters;
    private readonly System.Collections.Generic.HashSet<string> _alertedConflicts = new();

    /// <summary>按网卡独立保存的扫描结果与抓包计数。</summary>
    private readonly System.Collections.Generic.Dictionary<string, AdapterSessionState> _adapterStates = new();
    private string? _lastAdapterId;

    /// <summary>软件启动时记录的各网卡原始配置，用于"恢复原配置"。</summary>
    private readonly System.Collections.Generic.Dictionary<string, OriginalNicConfig> _originalConfigs = new();

    /// <summary>记录每台网卡 Apply/Join 是否实际改过 IP（设备 IP 已非启动时的初始值）。</summary>
    private readonly System.Collections.Generic.HashSet<string> _ipChangedAdapters = new();

    /// <summary>手动设置输入框基线快照（填充/改址成功后的值），用于脏检查。</summary>
    private string _manualBaseline = "";

    private bool _suppressManualTextChanged;

    private sealed class AdapterSessionState
    {
        public MapperState MapperState { get; set; } = new();
        public long PacketCount { get; set; }
    }

    public MainWindow()
    {
        InitializeComponent();

        _oui.Load();
        _mapper = new MapperService(_oui, _dns);
        _sniffer = new PassiveSniffer(_mapper);
        _scanner = new ActiveArpScanner();
        _orch = new ScanOrchestrator(_mapper, _sniffer, _scanner);
        _pnoLookup = new PnoVendorLookup(_oui);
        _dcp = new DcpService(_pnoLookup);
        _orch.AskContinue = () => Dispatcher.Invoke(() =>
        {
            var r = MessageBox.Show(
                "Local subnet and its re-scan completed. Continue with a deep scan?\n\nClick Yes to continue.",
                "Continue scanning further subnets?",
                MessageBoxButton.YesNo, MessageBoxImage.Question);
            return r == MessageBoxResult.Yes;
        });

        _mapper.Changed += _ => _dirty = true;
        _orch.StateChanged += OnOrchStateChanged;
        _orch.ProgressChanged += OnProgress;
        _sniffer.Error += msg => SetStatus(msg);
        _dcp.StateChanged += OnOrchStateChanged;
        _dcp.DeviceTableChanged += () => _dirty = true;
        _dcp.ReverificationFinished += OnReverificationFinished;
        _dcp.ReverificationStarted += OnReverificationStarted;
        _dcp.ReverificationSuperseded += OnReverificationSuperseded;
        _dcp.ReverificationTick += OnReverificationTick;
        _dcp.Error += msg => SetStatus(msg);
        _monitor.AdapterUp += OnAdapterUp;
        _monitor.AdapterDown += OnAdapterDown;
        _monitor.AdapterRemoved += OnAdapterRemoved;
        _monitor.AdapterAdded += OnAdapterAdded;

        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _refreshTimer.Tick += (_, _) => { if (_dirty) RefreshGrid(); UpdateFooter(); };
        _refreshTimer.Start();

        Loaded += OnLoaded;
        Closing += OnClosing;
        Closed += OnClosed;

        // 标题栏显示版本号（来自程序集元数据）
        var asm = System.Reflection.Assembly.GetExecutingAssembly().GetName();
        if (asm.Version != null)
            Title = $"NetScope Network Discovery Tool v{asm.Version.Major}.{asm.Version.Minor}.{asm.Version.Build}";
    }

    /// <summary>
    /// 界面缩放不使用固定常量：按屏幕工作区与设计基准（1140×680）换算整数百分比比例，
    /// 比例不保留小数（向下取整防止窗口超出屏幕），文字/控件随比例同步缩放。
    /// </summary>
    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        var wa = SystemParameters.WorkArea;
        int pctW = (int)(wa.Width * 100 / 1140.0);
        int pctH = (int)(wa.Height * 100 / 680.0);
        // 内容与窗口整体缩放：分辨率比例 × 0.75（文字/控件/外框同步缩小）
        double scale = Math.Min(pctW, pctH) / 100.0 * 0.75;
        Width = 1140 * scale;
        Height = 680 * scale;
        Left = (wa.Width - Width) / 2;
        Top = (wa.Height - Height) / 2;
        LayoutRoot.LayoutTransform = new ScaleTransform(scale, scale);
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        InitTray();
        if (!NpcapManager.IsInstalled)
        {
            var r = MessageBox.Show(
                "Npcap capture driver not detected. Passive listening and active ARP scanning both depend on it.\n\n" +
                "Click \"Yes\" to launch the official installer (visible setup with license agreement); click \"No\" to exit.",
                "Npcap Required", MessageBoxButton.YesNo, MessageBoxImage.Information);
            if (r == MessageBoxResult.Yes && NpcapManager.LaunchInteractiveInstall(out var msg))
            {
                SetStatus("Npcap installing. Please restart this application when done.");
                Close();
                return;
            }
            if (!NpcapManager.IsInstalled)
            {
                Close();
                return;
            }
        }
        NpcapManager.EnsureDllResolver();
        RefreshAdapters();
        // 记录软件启动时各网卡的原始配置，供"恢复原配置"使用
        foreach (var cfg in IpConfigService.CaptureOriginalConfigs())
            _originalConfigs[cfg.AdapterId] = cfg;
        PopulateManualFields();
        _monitor.InitBaseline();
        UpdateIntervalSliderEnabled(); // 初始默认 Passive：滑块禁用
        SetStatus("Ready. Use this tool only on authorized networks.");
    }

    // ---------------- 网卡管理 ----------------

    private void RefreshAdapters(string? selectId = null)
    {
        _loadingAdapters = true;
        try
        {
            var list = AdapterService.Enumerate();
            CmbAdapter.Items.Clear();
            foreach (var a in list) CmbAdapter.Items.Add(a);
            CmbAdapter.DisplayMemberPath = nameof(AdapterInfo.DisplayText);

            var target = selectId != null
                ? list.FirstOrDefault(a => a.Id == selectId)
                : AdapterService.PickDefault(list);
            // F3：指定的网卡已消失 → 回退 F4 默认选中
            target ??= AdapterService.PickDefault(list);
            if (target != null) CmbAdapter.SelectedItem = target;
        }
        catch (Exception ex)
        {
            // 网卡枚举在网络重置瞬间可能失败，不影响后续操作
            SetStatus($"Failed to refresh adapters: {ex.Message}");
        }
        finally
        {
            _loadingAdapters = false;
        }
        _lastAdapterId = CurrentAdapter?.Id;
        PopulateManualFields();
        UpdateAdapterInfo();
    }

    private AdapterInfo? CurrentAdapter => CmbAdapter.SelectedItem as AdapterInfo;

    private void UpdateAdapterInfo()
    {
        var a = CurrentAdapter;
        TxtAdapterInfo.Text = a == null
            ? ""
            : $"{a.Description}  |  Gateway {(a.Gateway?.ToString() ?? "-")}  |  {(a.IsDhcp ? "DHCP" : "Static")}";
        BtnJoinSubnet.IsEnabled = a?.IPv4 != null && DgResults.SelectedItem != null;
    }

    /// <summary>用当前网卡的原始配置填充手动设置输入框。</summary>
    private void PopulateManualFields()
    {
        var a = CurrentAdapter;
        if (a == null) return;

        // 已改过 IP 的网卡：保持输入框显示当前（最新）配置，不被刷新重置；原始配置仍在后台记录
        if (_ipChangedAdapters.Contains(a.Id))
        {
            UpdateManualButtons();
            return;
        }

        _suppressManualTextChanged = true;
        try
        {
            if (_originalConfigs.TryGetValue(a.Id, out var cfg))
            {
                TxtSetIp.Text = cfg.Ip?.ToString() ?? "";
                TxtSetMask.Text = cfg.Mask;
                TxtSetGw.Text = cfg.Gateway?.ToString() ?? "";
                TxtSetDns.Text = cfg.Dns;
            }
            else
            {
                // 启动时未记录到的网卡（热插拔），用当前配置填充
                TxtSetIp.Text = a.IPv4?.ToString() ?? "";
                TxtSetMask.Text = a.PrefixLength > 0 ? IpConfigService.PrefixToMask(a.PrefixLength) : "255.255.255.0";
                TxtSetGw.Text = a.Gateway?.ToString() ?? "";
                TxtSetDns.Text = "";
            }
        }
        finally
        {
            _suppressManualTextChanged = false;
        }
        CaptureManualBaseline();
        UpdateManualButtons();
    }

    /// <summary>记录当前输入框值为基线（填充或改址成功后调用）。</summary>
    private void CaptureManualBaseline()
        => _manualBaseline = $"{TxtSetIp.Text}|{TxtSetMask.Text}|{TxtSetGw.Text}|{TxtSetDns.Text}";

    /// <summary>输入框内容变化：相对基线有修改时 Apply 可用。</summary>
    private void ManualField_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!IsLoaded || _suppressManualTextChanged) return;
        UpdateManualButtons();
    }

    /// <summary>
    /// Manual Settings 按钮状态：输入与基线一致（未修改）时 Apply/Restore 均禁用；
    /// 有修改时 Apply 可用；Apply/Join 实际改过 IP 后 Restore 才可用。
    /// </summary>
    private void UpdateManualButtons()
    {
        var a = CurrentAdapter;
        bool dirty = $"{TxtSetIp.Text}|{TxtSetMask.Text}|{TxtSetGw.Text}|{TxtSetDns.Text}" != _manualBaseline;
        BtnApplyIp.IsEnabled = a != null && dirty;
        BtnRestoreDhcp.IsEnabled = a != null && _ipChangedAdapters.Contains(a.Id);
    }

    /// <summary>Apply/Join 改址成功后：标记该网卡已改址，输入框刷新为最新配置并重建基线。</summary>
    private void MarkIpChanged(AdapterInfo a, string ip, string mask, string gw, string dns)
    {
        _ipChangedAdapters.Add(a.Id);
        _suppressManualTextChanged = true;
        try
        {
            TxtSetIp.Text = ip;
            TxtSetMask.Text = mask;
            TxtSetGw.Text = gw;
            TxtSetDns.Text = dns;
        }
        finally
        {
            _suppressManualTextChanged = false;
        }
        CaptureManualBaseline();
        UpdateManualButtons();
    }

    private void CmbAdapter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loadingAdapters) return;

        // F66/F67：切换网卡 → 取消 DCP 复查
        _dcp.CancelReverification();
        if (_dcpMode)
        {
            _dcp.Stop();
            _dcp.Clear();
            _dcpMode = false;
        }

        // 保存上一个网卡的结果与计数（仅当确有切换且非扫描中）
        if (_lastAdapterId != null && !_orch.IsBusy)
        {
            _adapterStates[_lastAdapterId] = new AdapterSessionState
            {
                MapperState = _mapper.ExportState(),
                PacketCount = _sniffer.PacketCount
            };
        }

        var newAdapter = CurrentAdapter;
        _lastAdapterId = newAdapter?.Id;

        // 恢复新网卡的结果与计数；无记录则清空
        if (newAdapter != null && !_orch.IsBusy)
        {
            if (_adapterStates.TryGetValue(newAdapter.Id, out var state))
            {
                _mapper.ImportState(state.MapperState);
                _sniffer.SetPacketCount(state.PacketCount);
            }
            else
            {
                _mapper.Clear();
                _sniffer.SetPacketCount(0);
            }
            _dirty = true;
            RefreshGrid();
            UpdateFooter();
        }

        PopulateManualFields();
        UpdateAdapterInfo();
    }

    private void BtnRefreshAdapter_Click(object sender, RoutedEventArgs e)
        => RefreshAdapters(CurrentAdapter?.Id); // F3：刷新后当前网卡仍在则保持选中

    // ---------------- 扫描控制 ----------------

    private async void BtnStart_Click(object sender, RoutedEventArgs e)
    {
        var adapter = CurrentAdapter;
        if (adapter == null) { SetStatus("Select an adapter first."); return; }

        bool dcpChecked = CbDcp.IsChecked == true;
        var mode = RbActive.IsChecked == true ? ScanMode.Active : ScanMode.Passive;

        // F59：开始即清空——清当前网卡会话数据（映射、抓包计数、已扫集合在编排层重建、冲突告警）
        _mapper.Clear();
        _alertedConflicts.Clear();
        _sniffer.SetPacketCount(0);
        _adapterStates.Remove(adapter.Id);
        _dcp.Clear();
        _dcpMode = dcpChecked;
        _dirty = true;
        RefreshGrid();
        UpdateFooter();

        SetInputsEnabled(false);
        BtnStart.IsEnabled = false;
        BtnPause.IsEnabled = !dcpChecked; // F63：DCP 模式禁用 Pause
        BtnStop.IsEnabled = true;
        PbOverall.IsIndeterminate = false;
        PbOverall.Value = 0;
        TxtProgress.Text = "";
        TxtEta.Text = "";

        if (dcpChecked)
            await _dcp.StartIdentifyAsync(adapter);
        else
            await _orch.StartAsync(mode, adapter, (int)SliderInterval.Value);

        // 被动模式持续运行，其余模式结束后回到可输入状态
        bool stillRunning = dcpChecked
            ? _dcp.State == RunState.Scanning
            : _orch.State == RunState.Scanning;
        if (!stillRunning)
        {
            SetInputsEnabled(true);
            BtnStart.IsEnabled = true; BtnPause.IsEnabled = false; BtnStop.IsEnabled = false;
        }
    }

    private void BtnPause_Click(object sender, RoutedEventArgs e)
    {
        if (_orch.State == RunState.Scanning)
        {
            _orch.Pause();
            BtnPause.Content = "Resume";
        }
        else if (_orch.State == RunState.Paused)
        {
            _orch.Resume();
            BtnPause.Content = "Pause";
        }
    }

    private void BtnStop_Click(object sender, RoutedEventArgs e)
    {
        if (_dcpMode)
        {
            _dcp.Stop(); // 同时取消进行中的复查（ReverificationFinished 回调会恢复输入）
            // UI 兜底：复查期 State=Completed 时服务层可能不抛 Stopped 事件，这里直接兜底徽章与状态栏
            SetBadge("Stopped", BadgeGrey);
            SetStatus("Stopped");
        }
        else
        {
            _orch.Stop();
            _sniffer.Stop();
        }
        SetInputsEnabled(true);
        BtnStart.IsEnabled = true; BtnPause.IsEnabled = false; BtnStop.IsEnabled = false;
        BtnPause.Content = "Pause";
        PbOverall.IsIndeterminate = false;
        PbOverall.Value = 0;
        TxtProgress.Text = "";
        TxtEta.Text = "";
    }

    /// <summary>F9/F63：Send Interval 仅在"空闲 + Active 模式 + 未勾选 DCP"时可用；
    /// Passive 只监听不发包，DCP 为固定时序一次性任务，均禁用滑块。</summary>
    private void UpdateIntervalSliderEnabled(bool inputsEnabled = true)
    {
        SliderInterval.IsEnabled = inputsEnabled
            && RbActive.IsChecked == true
            && CbDcp.IsChecked != true;
    }

    private void SetInputsEnabled(bool enabled)
    {
        // 顶部网卡区：标签 + 选择控件（TxtAdapterInfo 为信息展示，保持不变）
        LblAdapter.IsEnabled = enabled;
        CmbAdapter.IsEnabled = enabled;
        BtnRefreshAdapter.IsEnabled = enabled;
        // 发现选项 / 设备通信：GroupBox 级联禁用，内部标签、输入框、按钮一并变灰
        GrpDiscovery.IsEnabled = enabled;
        GrpComm.IsEnabled = enabled;
        // 结果区
        BtnClear.IsEnabled = enabled;
        BtnJoinSubnet.IsEnabled = enabled && CurrentAdapter?.IPv4 != null && DgResults.SelectedItem != null;
        // F24：DCP 复选框仅在 Active 模式 + 空闲态可用
        CbDcp.IsEnabled = enabled && RbActive.IsChecked == true;
        // F9/F63：任务结束恢复输入后，滑块仍需按模式/DCP 勾选状态重新判定（Passive 保持禁用）
        UpdateIntervalSliderEnabled(enabled);
    }

    // F49 徽章配色（与 OnOrchStateChanged 中各 RunState 一一对应）
    private static readonly SolidColorBrush BadgeBlue = new(Color.FromRgb(0xDE, 0xEC, 0xF9));
    private static readonly SolidColorBrush BadgeYellow = new(Color.FromRgb(0xFF, 0xF4, 0xCE));
    private static readonly SolidColorBrush BadgeGreen = new(Color.FromRgb(0xD9, 0xF0, 0xDC));
    private static readonly SolidColorBrush BadgeRed = new(Color.FromRgb(0xFD, 0xE7, 0xE9));
    private static readonly SolidColorBrush BadgeGrey = new(Color.FromRgb(0xE5, 0xE5, 0xE5));

    /// <summary>F49：设置徽章固定词与底色（必须在 UI 线程调用）。</summary>
    private void SetBadge(string word, SolidColorBrush bg)
    {
        TxtState.Text = word;
        BadgeState.Background = bg;
    }

    private void OnOrchStateChanged(RunState state, string text)
    {
        Dispatcher.Invoke(() =>
        {
            // F49：徽章只显示固定状态词（Active=Scanning / Passive=Listening / DCP=Identifying），
            // 详细句子（完成/错误原因等）只进底部状态栏
            switch (state)
            {
                case RunState.Scanning:
                    SetBadge(_dcpMode ? "Identifying"
                        : RbPassive.IsChecked == true ? "Listening" : "Scanning", BadgeBlue);
                    break;
                case RunState.Paused: SetBadge("Paused", BadgeYellow); break;
                case RunState.Completed: SetBadge("Completed", BadgeGreen); break;
                case RunState.Stopped: SetBadge("Stopped", BadgeGrey); break;
                case RunState.Error: SetBadge("Error", BadgeRed); break;
                default: SetBadge("Idle", BadgeGrey); break;
            }
            SetStatus(text, isError: state == RunState.Error);
            // DCP 扫描中：显示 indeterminate 进度条 + 进行中文案
            if (_dcpMode && state == RunState.Scanning)
            {
                PbOverall.IsIndeterminate = true;
                TxtProgress.Text = "DCP Identify in progress...";
                TxtEta.Text = "";
            }
            if (state is RunState.Completed or RunState.Stopped or RunState.Error)
            {
                SetInputsEnabled(true);
                BtnStart.IsEnabled = true; BtnPause.IsEnabled = false; BtnStop.IsEnabled = false;
                BtnPause.Content = "Pause";
                PbOverall.IsIndeterminate = false;
                PbOverall.Value = 0;
                TxtProgress.Text = "";
                TxtEta.Text = "";
            }
        });
    }

    private void OnProgress(ScanProgress p)
    {
        // 异步投递：发送线程每包都触发进度，同步 Invoke 会把 UI 等待时间叠加进发送间隔
        Dispatcher.BeginInvoke(() =>
        {
            // 状态守卫：Stop/Completed 后排队的回调直接丢弃，防止把进度值写回去
            if (_dcpMode || _orch.State != RunState.Scanning) return;
            PbOverall.Value = Math.Clamp(p.Percent, 0, 100);
            TxtProgress.Text = p.SegmentText;
            TxtEta.Text = p.EtaText;
        });
    }

    // ---------------- 结果表 ----------------

    private void RefreshGrid()
    {
        _dirty = false;
        if (_dcpMode)
        {
            var dcpRows = _dcp.Snapshot();
            DgResults.ItemsSource = dcpRows;
            TxtResultHeader.Text = $"Results: {dcpRows.Count}";
            return;
        }

        var rows = _mapper.Snapshot();
        DgResults.ItemsSource = rows;
        TxtResultHeader.Text = $"Results: {rows.Count}";

        // 冲突告警（默认开启，每 IP 只提示一次）
        foreach (var row in rows.Where(r => r.ConflictTimeline != null))
        {
            var key = row.Ip.ToString();
            if (_alertedConflicts.Add(key))
                SetStatus($"⚠ IP conflict: {row.Ip} maps to {row.ConflictTimeline?.Count ?? 2} MACs");
        }
    }

    private void DgResults_LoadingRow(object sender, DataGridRowEventArgs e)
    {
        if (e.Row.Item is not ResultRow row) return;
        if (row.ConflictTimeline != null)
        {
            e.Row.Foreground = Brushes.Red;
            var lines = row.ConflictTimeline
                .Select(t => $"{t.Mac}  {t.First:HH:mm:ss} ~ {t.Last:HH:mm:ss}");
            e.Row.ToolTip = "Conflict details:\n" + string.Join("\n", lines);
        }
    }

    private void BtnClear_Click(object sender, RoutedEventArgs e)
    {
        _mapper.Clear();
        _alertedConflicts.Clear();
        _sniffer.SetPacketCount(0); // 抓包计数一并清零
        _dcp.Clear();
        _dcpMode = false;
        // 同步清掉当前网卡的保存会话，避免切网卡后再切回来"复活"旧条目
        if (_lastAdapterId != null && _adapterStates.TryGetValue(_lastAdapterId, out var st))
        {
            st.MapperState = new MapperState();
            st.PacketCount = 0;
        }
        _dirty = true;
        RefreshGrid();
        UpdateFooter();
    }

    /// <summary>切换主动/被动模式：清空所有接口的 IP-MAC 映射条目与抓包计数（等同全部"清空结果"）。</summary>
    private void RbScanMode_Checked(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return; // XAML 初始默认勾选不触发

        // F24：切到 Passive 自动取消 DCP 勾选并禁用；切到 Active 启用复选框（不自动勾选）
        _dcp.CancelReverification();
        if (_dcpMode)
        {
            _dcp.Stop();
            _dcp.Clear();
            _dcpMode = false;
        }
        CbDcp.IsEnabled = RbActive.IsChecked == true;
        if (RbPassive.IsChecked == true) CbDcp.IsChecked = false;

        _adapterStates.Clear();
        _mapper.Clear();
        _alertedConflicts.Clear();
        _sniffer.SetPacketCount(0);
        _dirty = true;
        RefreshGrid();
        UpdateFooter();
        // F49：模式切换后无任务，徽章回到 Idle（切换发生在空闲态，F13 运行中禁止切换）
        SetBadge("Idle", BadgeGrey);
        // F9/F63：切到 Passive 滑块禁用，切到 Active（且未勾 DCP）恢复
        UpdateIntervalSliderEnabled();
        SetStatus($"Switched to {(RbActive.IsChecked == true ? "Active Scan" : "Passive Listen")} mode. Results on all adapters cleared.");
    }

    /// <summary>F24：DCP 复选框状态变更。</summary>
    private void CbDcp_CheckedChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        // F63：DCP 为一次性任务（固定时序），发送间隔滑块不适用——勾选即禁用，取消恢复
        UpdateIntervalSliderEnabled();
        if (CbDcp.IsChecked == true)
            SetStatus("PROFINET DCP mode enabled. Click Start to discover DCP devices.");
    }

    // ---------------- DCP 双击弹窗（F64） ----------------

    private void DgResults_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        // F64：非运行态双击结果表行弹出设备操作窗（仅 DCP 模式）；DCP 复查期间同样禁止
        if (_orch.IsBusy || _dcp.IsBusy || _dcp.IsReverifying) return;
        if (!_dcpMode) return;

        if (DgResults.SelectedItem is not DcpResultRow row) return;
        var snapshot = _dcp.GetSnapshot(row.Mac);
        if (snapshot == null) return;

        var dialog = new DcpDeviceDialog(_dcp, row.Mac, snapshot) { Owner = this };
        dialog.ShowDialog();
    }

    private void DgResults_SelectionChanged(object sender, SelectionChangedEventArgs e)
        => BtnJoinSubnet.IsEnabled = !_orch.IsBusy && CurrentAdapter?.IPv4 != null && DgResults.SelectedItem != null;

    private void UpdateFooter()
    {
        TxtPacketCount.Text = $"Captured {_sniffer.PacketCount} frames";
    }

    // ---------------- 改址 ----------------

    private async void BtnJoinSubnet_Click(object sender, RoutedEventArgs e)
    {
        if (_orch.IsBusy || _dcp.IsBusy) return; // 运行或暂停期间禁止改址
        var adapter = CurrentAdapter;
        if (adapter == null) return;

        // F69：DCP 模式下 Device Access 同样可用——从 DcpResultRow 获取设备 IP
        IPAddress? deviceIpAddr = null;
        var usedIps = new HashSet<IPAddress>();

        if (DgResults.SelectedItem is ResultRow arpRow)
        {
            deviceIpAddr = arpRow.Ip;
            usedIps = new HashSet<IPAddress>(_mapper.Snapshot().Select(r => r.Ip));
        }
        else if (DgResults.SelectedItem is DcpResultRow dcpRow)
        {
            var snap = _dcp.GetSnapshot(dcpRow.Mac);
            deviceIpAddr = snap?.Ip;
            foreach (var d in _dcp.Snapshot())
                if (IPAddress.TryParse(d.Ip.Split('/')[0], out var ip)) usedIps.Add(ip);
        }
        else return;

        if (deviceIpAddr == null || deviceIpAddr.Equals(IPAddress.Any))
        {
            SetStatus("No device IP to join.");
            return;
        }

        var deviceIp = deviceIpAddr.GetAddressBytes();

        // 从 .2 开始递增，避开已发现的 IP 和设备自身 IP，直到找到可用地址
        IPAddress? target = null;
        for (byte last = 2; last <= 254; last++)
        {
            var candidate = new IPAddress(new[] { deviceIp[0], deviceIp[1], deviceIp[2], last });
            if (usedIps.Contains(candidate)) continue;
            if (candidate.Equals(deviceIpAddr)) continue;
            target = candidate;
            break;
        }
        if (target == null) { SetStatus("No free host address in this subnet (.2-.254 all in use)."); return; }

        var r = MessageBox.Show(
            $"Temporarily change local adapter \"{adapter.Name}\" to {target}/24 to join the device subnet.\nThe network will be briefly interrupted. Continue?",
            "Join Device Subnet", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (r != MessageBoxResult.Yes) return;

        var (ok, err) = await IpConfigService.SetStaticAsync(adapter.Name, target, "255.255.255.0", adapter.Gateway);
        if (ok)
            MarkIpChanged(adapter, target.ToString(), "255.255.255.0", adapter.Gateway?.ToString() ?? "", TxtSetDns.Text.Trim());
        SetStatus(ok ? $"Address changed to {target}" : $"Failed to change address: {err}");
        RefreshAdapters(adapter.Id);
    }

    private async void BtnApplyIp_Click(object sender, RoutedEventArgs e)
    {
        var adapter = CurrentAdapter;
        if (adapter == null) { SetStatus("Select an adapter first."); return; }

        var ipText = TxtSetIp.Text.Trim();
        if (string.IsNullOrEmpty(ipText))
        {
            SetStatus("IP address is empty.");
            return;
        }

        if (!IPAddress.TryParse(ipText, out var ip)) { SetStatus("Invalid IP format."); return; }
        if (!IPAddress.TryParse(TxtSetMask.Text.Trim(), out var mask)) { SetStatus("Invalid mask format."); return; }
        IPAddress? gw = null;
        if (!string.IsNullOrWhiteSpace(TxtSetGw.Text) &&
            !IPAddress.TryParse(TxtSetGw.Text.Trim(), out gw)) { SetStatus("Invalid gateway format."); return; }

        var r = MessageBox.Show($"Apply network settings {ip}/{mask} to \"{adapter.Name}\"? The network will be briefly interrupted.",
            "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (r != MessageBoxResult.Yes) return;

        var (ok, err) = await IpConfigService.SetStaticAsync(adapter.Name, ip, mask.ToString(), gw);
        string dns = TxtSetDns.Text.Trim();
        if (ok && !string.IsNullOrWhiteSpace(dns))
        {
            await IpConfigService.SetDnsAsync(adapter.Name, dns);
        }
        if (ok)
            MarkIpChanged(adapter, ipText, mask.ToString(), gw?.ToString() ?? "", dns);
        SetStatus(ok ? "Network settings applied." : $"Apply failed: {err}");
        RefreshAdapters(adapter.Id);
    }

    private async void BtnRestoreDhcp_Click(object sender, RoutedEventArgs e)
    {
        var adapter = CurrentAdapter;
        if (adapter == null) { SetStatus("Select an adapter first."); return; }
        await RestoreOriginalConfig(adapter);
    }

    private async Task RestoreOriginalConfig(AdapterInfo adapter)
    {
        if (_originalConfigs.TryGetValue(adapter.Id, out var cfg))
        {
            var desc = cfg.IsDhcp ? "DHCP" : $"{cfg.Ip}/{cfg.Mask}";
            var r = MessageBox.Show($"Restore adapter \"{adapter.Name}\" to the original configuration captured at startup ({desc})?",
                "Restore Original Config", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (r != MessageBoxResult.Yes) return;
            var (ok, err) = await IpConfigService.RestoreOriginalAsync(cfg);
            SetStatus(ok ? "Original configuration restored." : $"Restore failed: {err}");
            if (ok)
                _ipChangedAdapters.Remove(adapter.Id);
        }
        else
        {
            // 未记录到原配置，退化为恢复 DHCP
            var r = MessageBox.Show($"No original configuration was recorded for \"{adapter.Name}\"; it will be restored to DHCP.",
                "Restore Original Config", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (r != MessageBoxResult.Yes) return;
            var (ok, err) = await IpConfigService.SetDhcpAsync(adapter.Name);
            SetStatus(ok ? "DHCP restored." : $"Restore failed: {err}");
            if (ok)
                _ipChangedAdapters.Remove(adapter.Id);
        }
        // 标志清除后 PopulateManualFields 会将输入框恢复为原始配置
        RefreshAdapters(adapter.Id);
    }

    // ---------------- 热插拔（F5） ----------------

    private void OnAdapterUp(string adapterId)
    {
        Dispatcher.Invoke(() =>
        {
            if (_orch.IsBusy)
            {
                // 任务运行中不切卡、不弹窗，仅静默刷新列表
                RefreshAdapters(CurrentAdapter?.Id);
                return;
            }
            // 空闲时切换到刚 Up 的网卡 + 自动从托盘弹出（F5/F45）
            RefreshAdapters(adapterId);
            ShowFromTray();
            SetStatus("Link up detected. Switched to the new adapter.");
        });
    }

    /// <summary>网口 Up→Down：仅当该网卡正用于 Active/Passive/DCP 任务时才停止任务；其余情况仅刷新信息。</summary>
    private void OnAdapterDown(string adapterId)
    {
        Dispatcher.Invoke(() =>
        {
            var current = CurrentAdapter;
            if (current?.Id == adapterId)
            {
                if (_dcpMode && (_dcp.IsBusy || _dcp.IsReverifying))
                {
                    _dcp.EmergencyStop();
                    SetStatus("Adapter link down. DCP tasks stopped.");
                }
                else if (_orch.IsBusy)
                {
                    _orch.EmergencyStop(); // 立即停止扫描与监听（主动扫描全程不改网卡配置，无需恢复）
                    _sniffer.Stop();
                    SetStatus("Adapter link down. Tasks stopped.");
                }
            }
            RefreshAdapters(current?.Id);
        });
    }

    /// <summary>新增网卡且为 Down：静默加入下拉列表，保持当前选中，不切卡不弹窗。</summary>
    private void OnAdapterAdded(string adapterId)
    {
        Dispatcher.Invoke(() => RefreshAdapters(CurrentAdapter?.Id));
    }

    /// <summary>网卡硬件移除：下拉列表删除该网卡；若其正用于 Active/Passive/DCP 任务则一并停止。</summary>
    private void OnAdapterRemoved(string adapterId)
    {
        Dispatcher.Invoke(() =>
        {
            var current = CurrentAdapter;
            bool inUse = current?.Id == adapterId;
            if (inUse)
            {
                if (_dcpMode && (_dcp.IsBusy || _dcp.IsReverifying))
                    _dcp.EmergencyStop();
                else if (_orch.IsBusy)
                {
                    _orch.EmergencyStop();
                    _sniffer.Stop();
                }
            }

            // 硬件已消失：丢弃其会话状态与改址标记
            _adapterStates.Remove(adapterId);
            _ipChangedAdapters.Remove(adapterId);

            // 重新枚举后该网卡从下拉列表消失；若被移除的是当前选中项则回退默认选中
            RefreshAdapters(inUse ? null : current?.Id);

            if (inUse)
            {
                var newAdapter = CurrentAdapter;
                _lastAdapterId = newAdapter?.Id;
                if (!_orch.IsBusy && newAdapter != null &&
                    _adapterStates.TryGetValue(newAdapter.Id, out var state))
                {
                    _mapper.ImportState(state.MapperState);
                    _sniffer.SetPacketCount(state.PacketCount);
                }
                else
                {
                    _mapper.Clear();
                    _sniffer.SetPacketCount(0);
                }
                if (_dcpMode) _dcp.Clear();
                _dirty = true;
                RefreshGrid();
                UpdateFooter();
            }
            SetStatus("Adapter removed from the system. Adapter list refreshed.");
        });
    }

    // ---------------- 托盘（F43–F45） ----------------

    private void InitTray()
    {
        // F43：托盘图标从主程序 exe 提取（ApplicationIcon 已嵌入，单文件分发兼容），失败回退系统默认
        System.Drawing.Icon trayIcon;
        try { trayIcon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath!) ?? System.Drawing.SystemIcons.Application; }
        catch { trayIcon = System.Drawing.SystemIcons.Application; }
        _tray = new WF.NotifyIcon
        {
            Icon = trayIcon,
            Text = "NetScope Network Discovery Tool",
            Visible = true
        };
        var menu = new WF.ContextMenuStrip();
        menu.Items.Add("Show/Hide", null, (_, _) => ToggleWindow());
        menu.Items.Add("Exit", null, (_, _) => Close());
        _tray.ContextMenuStrip = menu;
        _tray.MouseClick += (_, e) => { if (e.Button == WF.MouseButtons.Left) ToggleWindow(); };
    }

    private void ToggleWindow()
    {
        if (IsVisible && WindowState != WindowState.Minimized) Hide();
        else ShowFromTray();
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
        Topmost = true; Topmost = false;
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_closePending) return; // 停止流程已走完，放行

        // F18：DCP 任务运行中或复查中 → 先停止再退出
        if (_dcpMode && (_dcp.IsBusy || _dcp.IsReverifying))
        {
            e.Cancel = true;
            _closePending = true;
            SetStatus("Stopping DCP tasks and exiting...");
            _dcp.Stop();
            Task.Run(async () =>
            {
                await Task.Delay(1500);
                Dispatcher.Invoke(Close);
            });
            return;
        }

        // F18：扫描/监听运行中关窗（关闭按钮与托盘"退出"行为一致）→ 先停止并等待收尾
        if (_orch.IsBusy)
        {
            e.Cancel = true;
            _closePending = true;
            SetStatus("Stopping scan and exiting...");
            _orch.Stop();
            _sniffer.Stop();
            Task.Run(async () =>
            {
                await Task.Delay(1500); // 等待扫描任务 finally 收尾
                Dispatcher.Invoke(Close); // 再次触发 Closing，直接放行
            });
            return;
        }

        // 空闲：直接退出（不再最小化到托盘）
    }

    /// <summary>最小化按钮 → 收进系统托盘（点托盘图标恢复）。</summary>
    private void Window_StateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Minimized) Hide();
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        _refreshTimer.Stop();
        _monitor.Dispose();
        _sniffer.Dispose();
        _scanner.Dispose();
        _dcp.Dispose();
        if (_tray != null) { _tray.Visible = false; _tray.Dispose(); }
    }

    /// <summary>F66/F67：Set OK 收到、周期复查开始——徽章 Verifying（蓝），状态栏提示最长等待 5 分钟。</summary>
    private void OnReverificationStarted()
    {
        // BeginInvoke：复查任务线程不阻塞等 UI，避免与 CancelReverification 的 Wait 互等死锁
        Dispatcher.BeginInvoke(() =>
        {
            SetBadge("Verifying", BadgeBlue);
            SetStatus("Verifying device settings (up to 5 minutes)...");
            // F64：复查期间锁定界面——禁止 Start、模式切换、DCP 勾选、双击 Set 另一台设备，只允许 Stop
            SetInputsEnabled(false);
            BtnStart.IsEnabled = false;
            BtnStop.IsEnabled = true;
        });
    }

    /// <summary>F66/F67：复查周期倒计时 tick——更新状态栏剩余时间。</summary>
    private void OnReverificationTick(TimeSpan remaining)
    {
        // BeginInvoke：任务线程不阻塞等 UI，避免与 CancelReverification 的 Wait 互等死锁
        Dispatcher.BeginInvoke(() =>
        {
            // 取消/停止后可能还有排队中的 tick，复查已结束则丢弃，避免覆盖拔线/停止提示
            if (!_dcp.IsReverifying) return;
            int totalMinutes = (int)remaining.TotalMinutes;
            int seconds = remaining.Seconds;
            SetStatus($"Verifying device settings (up to 5 minutes)... {totalMinutes} min {seconds:D2} s remaining");
        });
    }

    /// <summary>F66/F67：新 Set 操作取消了进行中的旧复查——徽章回 Stopped，状态栏提示旧设备未确认。</summary>
    private void OnReverificationSuperseded()
    {
        Dispatcher.BeginInvoke(() =>
        {
            SetBadge("Stopped", BadgeGrey);
            SetStatus("Previous device re-verification cancelled by new operation.");
            SetInputsEnabled(true);
            BtnStart.IsEnabled = true; BtnPause.IsEnabled = false; BtnStop.IsEnabled = false;
            BtnPause.Content = "Pause";
        });
    }

    /// <summary>F66/F67：持续复查结束——成功或超时弹窗，弹窗关闭后才恢复界面。</summary>
    private void OnReverificationFinished(bool success, string? timeoutMsg)
    {
        // BeginInvoke：任务线程不阻塞等 UI（弹窗是模态泵消息，不会被 Wait 死锁）
        Dispatcher.BeginInvoke(() =>
        {
            if (success)
            {
                const string okMsg = "Device came back online. Operation confirmed.";
                SetBadge("Completed", BadgeGreen);
                MessageBox.Show(this, okMsg, "DCP Re-verification",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                SetStatus(okMsg);
            }
            else if (timeoutMsg != null)
            {
                SetBadge("Error", BadgeRed);
                MessageBox.Show(this, timeoutMsg, "DCP Re-verification",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                SetStatus(timeoutMsg, isError: true);
            }
            // 弹窗已关闭（或取消路径无弹窗），此时恢复输入与按钮
            SetInputsEnabled(true);
            BtnStart.IsEnabled = true; BtnPause.IsEnabled = false; BtnStop.IsEnabled = false;
            BtnPause.Content = "Pause";
        });
    }

    private void SetStatus(string text, bool isError = false) => Dispatcher.Invoke(() =>
    {
        TxtStatusBar.Text = text;
        TxtStatusBar.Foreground = isError ? System.Windows.Media.Brushes.Red : System.Windows.Media.Brushes.Black;
    });

    private void SliderInterval_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (TxtInterval != null) TxtInterval.Text = $"{(int)SliderInterval.Value} ms";
    }
}
