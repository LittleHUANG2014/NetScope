using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using NetScope.Models;

namespace NetScope.Services;

/// <summary>
/// F58/F62：PNO Man_ID_Table 厂商映射（VendorID → 厂商名）。
/// 启动时优先读取程序同目录的 man_id.tsv，存在则以外置文件为准；否则用内嵌资源。
/// DCP (2,3) VendorID 查此表优先，查不到再用 OuiLookup 兜底。
/// </summary>
public class PnoVendorLookup
{
    private readonly Dictionary<ushort, string> _byVendorId = new();
    private readonly OuiLookup _oui;

    public PnoVendorLookup(OuiLookup oui)
    {
        _oui = oui;
        Load();
    }

    private void Load()
    {
        try
        {
            // 外置文件优先：程序同目录存在 man_id.tsv 则以外置文件为准，否则用内嵌资源
            var path = Path.Combine(AppContext.BaseDirectory, "man_id.tsv");
            StreamReader reader;
            if (File.Exists(path))
            {
                try { reader = new StreamReader(path); }
                catch { reader = OpenEmbedded(); }
            }
            else reader = OpenEmbedded();

            using (reader)
            {
                // tsv 用 UTF-8(无 BOM)写入，可保留 ö/ü/é 等非 ASCII 厂商名
                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.Length == 0) continue;
                    int sep = line.IndexOf('\t');
                    if (sep <= 0) continue;
                    var idStr = line.AsSpan(0, sep);
                    if (!ushort.TryParse(idStr, out var id)) continue;
                    var name = line.AsSpan(sep + 1).Trim();
                    if (!name.IsEmpty)
                        _byVendorId[id] = name.ToString();
                }
            }
        }
        catch { /* 加载失败时退化为纯 OUI 兜底 */ }
    }

    private static StreamReader OpenEmbedded()
    {
        var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("NetScope.data.man_id.tsv");
        return stream != null ? new StreamReader(stream) : StreamReader.Null;
    }

    /// <summary>F62：DCP 厂商名解析——VendorID 优先查 PNO 表，查不到用 OUI 库兜底。</summary>
    public string? Lookup(ushort vendorId, MacAddress mac)
    {
        if (_byVendorId.TryGetValue(vendorId, out var name))
            return name;
        return _oui.LookupVendor(mac);
    }
}
