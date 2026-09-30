using System;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using NetScope.Models;
using NetScope.Services;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
using TextBox = System.Windows.Controls.TextBox;
using Button = System.Windows.Controls.Button;

namespace NetScope;

/// <summary>
/// F64/F65：DCP 设备操作弹窗（双击结果表行触发）。
/// Factory Reset / Set IP Parameters 两个选项；Set IP 表单逐项校验 + 差分按钮态。
/// 成功收到 Set OK 后关闭弹窗，持续复查由 DcpService 后台运行、MainWindow 接收事件。
/// </summary>
public class DcpDeviceDialog : Window
{
    private readonly DcpService _dcp;
    private readonly MacAddress _mac;
    private readonly DcpDeviceSnapshot _old;

    private readonly TextBox _txtName;
    private readonly TextBox _txtIp;
    private readonly TextBox _txtMask;
    private readonly TextBox _txtGw;
    private readonly Button _btnFactoryReset;
    private readonly Button _btnSetIp;
    private readonly TextBlock _txtStatus;

    public DcpDeviceDialog(DcpService dcp, MacAddress mac, DcpDeviceSnapshot oldValues)
    {
        _dcp = dcp;
        _mac = mac;
        _old = oldValues;

        Title = "DCP Device Operations";
        Width = 480;
        Height = 380;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.NoResize;

        var panel = new StackPanel { Margin = new Thickness(16) };

        // 设备信息
        panel.Children.Add(new TextBlock
        {
            Text = $"MAC: {mac}",
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 8)
        });
        panel.Children.Add(new TextBlock
        {
            Text = $"Current Name: {oldValues.NameOfStation}\n" +
                   $"Current IP: {oldValues.Ip}/{DcpDeviceEntry.MaskToPrefix(oldValues.SubnetMask)}\n" +
                   $"Current Gateway: {oldValues.Gateway}",
            Foreground = System.Windows.Media.Brushes.Gray,
            Margin = new Thickness(0, 0, 0, 12)
        });

        // Factory Reset 按钮
        _btnFactoryReset = new Button
        {
            Content = "Factory Reset",
            Padding = new Thickness(12, 5, 12, 5),
            Margin = new Thickness(0, 0, 0, 12),
            HorizontalAlignment = System.Windows.HorizontalAlignment.Left
        };
        _btnFactoryReset.Click += BtnFactoryReset_Click;
        panel.Children.Add(_btnFactoryReset);

        // Set IP 表单
        panel.Children.Add(new TextBlock
        {
            Text = "Set IP Parameters",
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 4, 0, 4)
        });

        var grid = new Grid { Margin = new Thickness(0, 0, 0, 8) };
        for (int i = 0; i < 4; i++)
        {
            grid.RowDefinitions.Add(new RowDefinition());
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        }

        _txtName = AddField(grid, 0, "Name of station", oldValues.NameOfStation);
        _txtIp = AddField(grid, 1, "IP", oldValues.Ip.ToString());
        _txtMask = AddField(grid, 2, "Subnet (mask)", oldValues.SubnetMask.ToString());
        _txtGw = AddField(grid, 3, "Gateway", oldValues.Gateway.ToString());

        foreach (var t in new[] { _txtName, _txtIp, _txtMask, _txtGw })
            t.TextChanged += (_, _) => UpdateSetButtonState();

        panel.Children.Add(grid);

        // Set IP 按钮
        _btnSetIp = new Button
        {
            Content = "Apply Set",
            Padding = new Thickness(12, 5, 12, 5),
            Margin = new Thickness(0, 0, 0, 8),
            HorizontalAlignment = System.Windows.HorizontalAlignment.Left,
            IsEnabled = false
        };
        _btnSetIp.Click += BtnSetIp_Click;
        panel.Children.Add(_btnSetIp);

        // 状态
        _txtStatus = new TextBlock
        {
            Foreground = System.Windows.Media.Brushes.Gray,
            Margin = new Thickness(0, 4, 0, 0),
            TextWrapping = TextWrapping.Wrap
        };
        panel.Children.Add(_txtStatus);

        Content = panel;
        Loaded += (_, _) => UpdateSetButtonState();
    }

    private static TextBox AddField(Grid grid, int row, string label, string value)
    {
        var lbl = new TextBlock { Text = label, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 4) };
        Grid.SetRow(lbl, row); Grid.SetColumn(lbl, 0);
        grid.Children.Add(lbl);
        var txt = new TextBox { Text = value, Margin = new Thickness(0, 0, 0, 4), MinWidth = 280 };
        Grid.SetRow(txt, row); Grid.SetColumn(txt, 1);
        grid.Children.Add(txt);
        return txt;
    }

    /// <summary>F65：差分——全部未变时 Set 按钮灰色。</summary>
    private void UpdateSetButtonState()
    {
        bool nameChanged = _txtName.Text.Trim() != _old.NameOfStation;
        bool ipChanged = _txtIp.Text.Trim() != _old.Ip.ToString();
        bool maskChanged = _txtMask.Text.Trim() != _old.SubnetMask.ToString();
        bool gwChanged = _txtGw.Text.Trim() != _old.Gateway.ToString();
        _btnSetIp.IsEnabled = nameChanged || ipChanged || maskChanged || gwChanged;
    }

    private async void BtnFactoryReset_Click(object sender, RoutedEventArgs e)
    {
        _btnFactoryReset.IsEnabled = false;
        _btnSetIp.IsEnabled = false;
        _txtStatus.Foreground = System.Windows.Media.Brushes.Gray;
        _txtStatus.Text = "Sending Factory Reset...";

        bool ok = await _dcp.FactoryResetAsync(_mac).ConfigureAwait(true);
        if (ok)
        {
            _txtStatus.Text = "Factory Reset sent. Waiting for device to come back online...";
            Close();
        }
        else
        {
            _txtStatus.Text = "Factory Reset failed (no Set OK or error status).";
            _txtStatus.Foreground = System.Windows.Media.Brushes.Red;
            _btnFactoryReset.IsEnabled = true;
            UpdateSetButtonState();
        }
    }

    private async void BtnSetIp_Click(object sender, RoutedEventArgs e)
    {
        // F64：逐项校验合法性
        if (!IPAddress.TryParse(_txtIp.Text.Trim(), out var ip))
        {
            MessageBox.Show("Invalid IP address format.", "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (!IPAddress.TryParse(_txtMask.Text.Trim(), out var mask))
        {
            MessageBox.Show("Invalid subnet mask format.", "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        IPAddress? gw = null;
        if (!string.IsNullOrWhiteSpace(_txtGw.Text) &&
            !IPAddress.TryParse(_txtGw.Text.Trim(), out gw))
        {
            MessageBox.Show("Invalid gateway format.", "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        gw ??= IPAddress.Any;

        string newName = _txtName.Text.Trim();

        _btnFactoryReset.IsEnabled = false;
        _btnSetIp.IsEnabled = false;
        _txtStatus.Foreground = System.Windows.Media.Brushes.Gray;
        _txtStatus.Text = "Sending Set IP...";

        bool ok = await _dcp.SetIpAsync(_mac, _old, newName, ip, mask, gw).ConfigureAwait(true);
        if (ok)
        {
            _txtStatus.Text = "Set IP sent. Waiting for device to come back online...";
            Close();
        }
        else
        {
            _txtStatus.Text = "Set IP failed (no Set OK or error status).";
            _txtStatus.Foreground = System.Windows.Media.Brushes.Red;
            _btnFactoryReset.IsEnabled = true;
            UpdateSetButtonState();
        }
    }
}
