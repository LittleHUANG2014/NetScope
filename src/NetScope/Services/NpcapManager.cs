using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace NetScope.Services;

/// <summary>
/// F36–F42：Npcap 驱动检测与生命周期。
/// 已安装 → 直接加载；未安装 → 免费版引导交互安装（F39）；禁止 NetScan 式驱动自管理（F40）。
/// </summary>
public static class NpcapManager
{
    private static readonly string NpcapDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap");
    private static readonly string WpcapPath = Path.Combine(NpcapDir, "wpcap.dll");

    public static bool IsInstalled => File.Exists(WpcapPath);

    public static bool IsAdmin
    {
        get
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    private static bool _resolverRegistered;

    /// <summary>优先从 System32\Npcap 加载 wpcap.dll（F37）。</summary>
    public static void EnsureDllResolver()
    {
        if (_resolverRegistered) return;
        _resolverRegistered = true;
        NativeLibrary.SetDllImportResolver(typeof(Interop.PcapNative).Assembly, (name, asm, path) =>
        {
            if (name.StartsWith("wpcap", StringComparison.OrdinalIgnoreCase) && File.Exists(WpcapPath))
                return NativeLibrary.Load(WpcapPath);
            return IntPtr.Zero;
        });
    }

    /// <summary>驱动服务是否运行（sc query npcap）。</summary>
    public static bool IsServiceRunning()
    {
        try
        {
            var psi = new ProcessStartInfo("sc", "query npcap")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return false;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            return output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    /// <summary>
    /// F39 引导安装：从嵌入资源释放 npcap 安装包到 %TEMP%，交互模式调起（用户可见许可协议）。
    /// 返回 true 表示安装包已启动。
    /// </summary>
    public static bool LaunchInteractiveInstall(out string message)
    {
        message = "";
        const string resName = "NetScope.Assets.npcap-installer.exe";
        var asm = Assembly.GetExecutingAssembly();
        using var stream = asm.GetManifestResourceStream(resName);
        if (stream == null)
        {
            message = "The installer is not embedded. Install Npcap manually (https://npcap.com).";
            return false;
        }
        var temp = Path.Combine(Path.GetTempPath(), "npcap-installer.exe");
        using (var fs = File.Create(temp))
            stream.CopyTo(fs);
        try
        {
            Process.Start(new ProcessStartInfo(temp) { UseShellExecute = true, Verb = "runas" });
            return true;
        }
        catch (Exception ex)
        {
            message = $"Failed to launch the installer: {ex.Message}";
            return false;
        }
    }
}
