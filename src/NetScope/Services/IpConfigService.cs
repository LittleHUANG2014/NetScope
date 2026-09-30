using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetScope.Services;

/// <summary>软件启动时记录的网卡原始配置，用于"恢复原配置"。</summary>
public class OriginalNicConfig
{
    public string AdapterId = "";
    public string AdapterName = "";
    public bool IsDhcp;
    public IPAddress? Ip;
    public string Mask = "255.255.255.0";
    public IPAddress? Gateway;
    public string Dns = "";
}

/// <summary>
/// F31–F35：netsh 手动改址 / 恢复 DHCP、错误友好化（仅供"设备通信"面板手动操作使用）。
/// </summary>
public static class IpConfigService
{
    public static string PrefixToMask(int prefix)
    {
        if (prefix <= 0) return "255.255.255.0";
        uint mask = prefix == 32 ? 0xFFFFFFFF : 0xFFFFFFFF << (32 - prefix);
        return new IPAddress(BitConverter.GetBytes(mask).Reverse().ToArray()).ToString();
    }

    /// <summary>静态改址。返回 (成功, 友好错误信息)。</summary>
    public static async Task<(bool Ok, string Error)> SetStaticAsync(
        string adapterName, IPAddress ip, string mask, IPAddress? gateway = null)
    {
        var args = gateway != null
            ? $"interface ip set address name=\"{adapterName}\" static {ip} {mask} {gateway} 1"
            : $"interface ip set address name=\"{adapterName}\" static {ip} {mask}";
        return await RunNetsh(args);
    }

    /// <summary>F33：恢复 DHCP（IP + DNS）。</summary>
    public static async Task<(bool Ok, string Error)> SetDhcpAsync(string adapterName)
    {
        var r1 = await RunNetsh($"interface ip set address name=\"{adapterName}\" dhcp");
        var r2 = await RunNetsh($"interface ip set dnsservers name=\"{adapterName}\" dhcp");
        if (r1.Ok && r2.Ok) return (true, "");
        if (r1.Ok) return (false, $"IP restored to DHCP, but DNS restore failed: {r2.Error} (partially completed)");
        return (false, r1.Error);
    }

    /// <summary>设置静态 DNS 服务器。</summary>
    public static async Task<(bool Ok, string Error)> SetDnsAsync(string adapterName, string dns)
    {
        return await RunNetsh($"interface ip set dnsservers name=\"{adapterName}\" static {dns}");
    }

    /// <summary>采集软件启动时所有网卡的原始配置（IP/掩码/网关/DNS/DHCP）。</summary>
    public static List<OriginalNicConfig> CaptureOriginalConfigs()
    {
        var list = new List<OriginalNicConfig>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var props = nic.GetIPProperties();
            var uni = props.UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var gw = props.GatewayAddresses
                .FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var dns = props.DnsAddresses
                .FirstOrDefault(d => d.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

            list.Add(new OriginalNicConfig
            {
                AdapterId = nic.Id,
                AdapterName = nic.Name,
                IsDhcp = props.GetIPv4Properties()?.IsDhcpEnabled ?? false,
                Ip = uni?.Address,
                Mask = uni != null ? PrefixToMask(uni.PrefixLength) : "255.255.255.0",
                Gateway = gw?.Address,
                Dns = dns?.ToString() ?? ""
            });
        }
        return list;
    }

    /// <summary>恢复到软件启动时的原始配置（DHCP 或静态）。</summary>
    public static async Task<(bool Ok, string Error)> RestoreOriginalAsync(OriginalNicConfig cfg)
    {
        if (cfg.IsDhcp)
        {
            var r = await SetDhcpAsync(cfg.AdapterName);
            if (!r.Ok) return r;
            if (!string.IsNullOrEmpty(cfg.Dns))
                await RunNetsh($"interface ip set dnsservers name=\"{cfg.AdapterName}\" static {cfg.Dns}");
            return (true, "");
        }
        if (cfg.Ip == null) return await SetDhcpAsync(cfg.AdapterName);
        var r1 = await SetStaticAsync(cfg.AdapterName, cfg.Ip, cfg.Mask, cfg.Gateway);
        if (!r1.Ok) return r1;
        if (!string.IsNullOrEmpty(cfg.Dns))
            await RunNetsh($"interface ip set dnsservers name=\"{cfg.AdapterName}\" static {cfg.Dns}");
        return (true, "");
    }

    private static async Task<(bool Ok, string Error)> RunNetsh(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("netsh", args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.GetEncoding("GB18030"),
                StandardErrorEncoding = Encoding.GetEncoding("GB18030")
            };
            using var p = Process.Start(psi)!;

            // 并发读取 stdout/stderr，避免缓冲区满导致死锁
            var outTask = p.StandardOutput.ReadToEndAsync();
            var errTask = p.StandardError.ReadToEndAsync();

            // 10 秒超时，防止 netsh 挂起
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var waitTask = p.WaitForExitAsync(cts.Token);
            var completed = await Task.WhenAny(waitTask, Task.Delay(Timeout.Infinite, cts.Token));
            if (completed != waitTask)
            {
                try { p.Kill(); } catch { }
                return (false, "netsh timed out (10s). The adapter may be busy.");
            }

            var output = await outTask;
            var error = await errTask;
            if (p.ExitCode == 0) return (true, "");

            // 边界：netsh 对已开 DHCP 的接口返回非 0，但实际是成功状态
            if (output.Contains("DHCP is already enabled", StringComparison.OrdinalIgnoreCase) ||
                error.Contains("DHCP is already enabled", StringComparison.OrdinalIgnoreCase))
                return (true, "");

            return (false, FriendlyError(output + error));
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>F34：netsh 错误友好化。</summary>
    private static string FriendlyError(string raw)
    {
        if (raw.Contains("requires elevation", StringComparison.OrdinalIgnoreCase) ||
            raw.Contains("请求的操作需要提升"))
            return "Insufficient privileges. Run as administrator.";
        if (raw.Contains("DHCP", StringComparison.OrdinalIgnoreCase) &&
            raw.Contains("not available", StringComparison.OrdinalIgnoreCase))
            return "This adapter does not support DHCP (possibly a virtual adapter). Configure a static address manually.";
        if (raw.Contains("找不到", StringComparison.OrdinalIgnoreCase) ||
            raw.Contains("not found", StringComparison.OrdinalIgnoreCase))
            return "The adapter does not exist or has been removed.";
        if (raw.Contains("parameter is incorrect", StringComparison.OrdinalIgnoreCase) ||
            raw.Contains("参数错误"))
            return "Invalid parameters. Check the IP/mask/gateway format.";
        var firstLine = raw.Split('\n')[0].Trim();
        return string.IsNullOrEmpty(firstLine) ? "netsh failed." : firstLine;
    }
}
