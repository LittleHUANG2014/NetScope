using System;
using System.Globalization;

namespace NetScope.Models;

public readonly record struct MacAddress(byte B0, byte B1, byte B2, byte B3, byte B4, byte B5)
{
    public override string ToString()
        => $"{B0:X2}:{B1:X2}:{B2:X2}:{B3:X2}:{B4:X2}:{B5:X2}";

    public static MacAddress Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 6) throw new ArgumentException("MAC requires 6 bytes");
        return new MacAddress(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    }

    public static bool TryParse(string s, out MacAddress mac)
    {
        mac = default;
        if (string.IsNullOrWhiteSpace(s)) return false;
        var parts = s.Split([':', '-'], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 6) return false;
        var b = new byte[6];
        for (int i = 0; i < 6; i++)
            if (!byte.TryParse(parts[i], NumberStyles.HexNumber, null, out b[i])) return false;
        mac = new MacAddress(b[0], b[1], b[2], b[3], b[4], b[5]);
        return true;
    }

    public bool IsRandomLocal() => (B0 & 0x02) != 0;

    public ReadOnlySpan<byte> AsSpan() => new[] { B0, B1, B2, B3, B4, B5 };

    public uint Oui24 => ((uint)B0 << 16) | ((uint)B1 << 8) | B2;
    public uint Oui28 => (Oui24 << 4) | (uint)(B3 >> 4);
    public uint Oui36 => (Oui24 << 12) | ((uint)B3 << 4) | (uint)(B4 >> 4);
}
