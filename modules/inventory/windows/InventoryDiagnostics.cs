using System.ComponentModel;
using System.Security;
using System.Text;
using System.Text.Json;

namespace OneControl.Agent.Core;

internal sealed record InventoryIssue(string Section, string Code);

internal sealed class InventoryDiagnostics
{
    private readonly List<InventoryIssue> issues = [];
    public IReadOnlyList<InventoryIssue> Issues => issues;
    public bool Partial => issues.Count > 0;

    public void Report(string section, string code)
    {
        var issue = new InventoryIssue(section, code);
        if (issues.Count < 20 && !issues.Contains(issue)) issues.Add(issue);
    }

    public T Capture<T>(string section, Func<T> read, T unavailable)
    {
        try { return read(); }
        catch (Exception error) when (error is UnauthorizedAccessException or SecurityException or
            IOException or InvalidDataException or JsonException or Win32Exception or InvalidOperationException or NotSupportedException)
        {
            Report(section, error is UnauthorizedAccessException or SecurityException ? "access_denied" : "unavailable");
            return unavailable;
        }
    }

    public List<T> Bound<T>(IEnumerable<T> source, string section, int countLimit, int byteLimit)
    {
        var result = new List<T>();
        var bytes = 2; // JSON array brackets; include commas and escaped UTF-8, not string.Length.
        foreach (var value in source)
        {
            var cost = JsonSerializer.SerializeToUtf8Bytes(value, Protocol.Json).Length + (result.Count > 0 ? 1 : 0);
            if (result.Count >= countLimit || cost > byteLimit - bytes)
            {
                Report(section, "collection_limit");
                break;
            }
            result.Add(value);
            bytes += cost;
        }
        return result;
    }

    public static string? Text(object? value, int maximumLength)
    {
        if (value is not string source || string.IsNullOrWhiteSpace(source)) return null;
        var result = new StringBuilder(Math.Min(source.Length, maximumLength));
        foreach (var rune in source.EnumerateRunes())
        {
            if (Rune.IsControl(rune)) continue;
            if (result.Length + rune.Utf16SequenceLength > maximumLength) break;
            result.Append(rune.ToString());
        }
        return result.ToString().Trim() is { Length: > 0 } text ? text : null;
    }
}
