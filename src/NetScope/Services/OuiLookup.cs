using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using NetScope.Models;

namespace NetScope.Services;

/// <summary>
/// F28 + F30：OUI 离线厂商库（5.4 万条，36/28/24 位前缀）与 identify.tsv 规则库。
/// </summary>
public class OuiLookup
{
    private readonly Dictionary<string, string> _oui = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(string Key, string Label)> _hostRules = new();
    private readonly List<(string Key, string Label)> _vendorRules = new();

    public void Load()
    {
        var asm = Assembly.GetExecutingAssembly();
        // 外置文件优先：程序同目录存在 oui.tsv 则以外置文件为准，否则用内嵌资源
        using (var reader = OpenExternalOrEmbedded(asm, "oui.tsv", "NetScope.data.oui.tsv"))
            LoadOui(reader);
        // identify.tsv 仅内嵌
        using (var reader = OpenEmbedded(asm, "NetScope.data.identify.tsv"))
            LoadRules(reader);
    }

    /// <summary>程序同目录存在指定文件则打开外置文件，否则打开内嵌资源。</summary>
    private static StreamReader OpenExternalOrEmbedded(Assembly asm, string fileName, string resName)
    {
        var path = Path.Combine(AppContext.BaseDirectory, fileName);
        if (File.Exists(path))
        {
            try { return new StreamReader(path); }
            catch { /* 外置文件打开失败时回退内嵌资源 */ }
        }
        return OpenEmbedded(asm, resName);
    }

    private static StreamReader OpenEmbedded(Assembly asm, string resName)
    {
        var stream = asm.GetManifestResourceStream(resName);
        return stream != null ? new StreamReader(stream) : StreamReader.Null;
    }

    private void LoadOui(StreamReader reader)
    {
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (line.Length == 0 || line[0] == '#') continue;
            var tab = line.IndexOf('\t');
            if (tab <= 0) continue;
            _oui[line[..tab].Trim()] = line[(tab + 1)..].Trim();
        }
    }

    private void LoadRules(StreamReader reader)
    {
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (line.Length == 0 || line[0] == '#') continue;
            var parts = line.Split('\t');
            if (parts.Length < 3) continue;
            var rule = (parts[1].Trim(), parts[2].Trim());
            if (parts[0] == "host") _hostRules.Add(rule);
            else if (parts[0] == "vendor") _vendorRules.Add(rule);
        }
    }

    /// <summary>36 → 28 → 24 位前缀依次匹配。</summary>
    public string? LookupVendor(MacAddress mac)
    {
        if (mac.IsRandomLocal()) return "Randomized MAC (privacy)";
        var hex = $"{mac.B0:X2}{mac.B1:X2}{mac.B2:X2}{mac.B3:X2}{mac.B4:X2}{mac.B5:X2}";
        foreach (var len in new[] { 9, 7, 6 })
            if (_oui.TryGetValue(hex[..len], out var v))
                return v;
        return null;
    }

    /// <summary>主机名子串匹配（不区分大小写），如 iphone → iPhone。</summary>
    public string? LookupByHostName(string hostName)
    {
        foreach (var (key, label) in _hostRules)
            if (hostName.Contains(key, StringComparison.OrdinalIgnoreCase))
                return label;
        return null;
    }

    /// <summary>厂商名词边界匹配 → 中文设备标签。</summary>
    public string? LookupByVendor(string vendorName)
    {
        foreach (var (key, label) in _vendorRules)
            if (ContainsWordBoundary(vendorName, key))
                return label;
        return null;
    }

    private static bool ContainsWordBoundary(string text, string key)
    {
        int idx = 0;
        while ((idx = text.IndexOf(key, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            bool leftOk = idx == 0 || !char.IsLetterOrDigit(text[idx - 1]);
            int end = idx + key.Length;
            bool rightOk = end >= text.Length || !char.IsLetterOrDigit(text[end]);
            if (leftOk && rightOk) return true;
            idx = end;
        }
        return false;
    }
}
