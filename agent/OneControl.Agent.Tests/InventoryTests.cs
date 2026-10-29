using System.Text.Json;
using OneControl.Agent.Core;
using Xunit;

namespace OneControl.Agent.Tests;

public sealed class InventoryTests
{
    [Fact]
    public void UnreadableObservationsDoNotDiscardOtherInventoryOrExposeExceptionDetails()
    {
        var diagnostics = new InventoryDiagnostics();
        Assert.Null(diagnostics.Capture<bool?>("windows.restart", () => throw new UnauthorizedAccessException("private-path-and-value"), null));
        Assert.Equal(42, diagnostics.Capture("healthy", () => 42, 0));
        Assert.True(diagnostics.Partial);
        Assert.Equal(new InventoryIssue("windows.restart", "access_denied"), Assert.Single(diagnostics.Issues));
        Assert.DoesNotContain("private-path", JsonSerializer.Serialize(diagnostics.Issues, Protocol.Json));
        Assert.Throws<ArgumentException>(() => diagnostics.Capture<int>("programming-error", () => throw new ArgumentException(), 0));
    }

    [Fact]
    public void CollectionLimitsCountEscapedUtf8AndStopReadingAtTheLimit()
    {
        var diagnostics = new InventoryDiagnostics();
        var visited = 0;
        IEnumerable<string> Values()
        {
            while (true) { visited++; yield return "\\\"\u4e00\U0001f680"; }
        }
        var values = diagnostics.Bound(Values(), "applications", 500, 1024);
        Assert.True(JsonSerializer.SerializeToUtf8Bytes(values, Protocol.Json).Length <= 1024);
        Assert.Equal(values.Count + 1, visited);
        Assert.Equal(new InventoryIssue("applications", "collection_limit"), Assert.Single(diagnostics.Issues));
        Assert.Empty(diagnostics.Bound(new[] { new string('x', 300) }, "applications", 100, 30));
    }

    [Fact]
    public void RegistryTextIsBoundedWithoutSplittingUnicodeOrExpandingNonTextValues()
    {
        Assert.Equal("AB\U0001f680", InventoryDiagnostics.Text("\n AB\U0001f680CD\t", 5));
        Assert.Null(InventoryDiagnostics.Text(new[] { "unsupported-registry-kind" }, 64));
        Assert.Null(InventoryDiagnostics.Text("\r\n\t", 64));
    }

    [Fact]
    public void WindowsInventoryContainsSaneNativeHardwareWithinTheHeartbeatBudget()
    {
        var report = Inventory.Collect();
        Assert.True(JsonSerializer.SerializeToUtf8Bytes(report, Protocol.Json).Length < Inventory.MaximumBytes);
        Assert.Equal(Environment.MachineName, report["hostname"]);
        var hardware = Assert.IsType<HardwareSnapshot>(report["hardware"]);
        Assert.True(hardware.LogicalProcessors > 0);
        Assert.NotNull(hardware.Memory);
        Assert.True(hardware.Memory.TotalBytes > 0);
        Assert.True(hardware.Memory.AvailableBytes <= hardware.Memory.TotalBytes);
        Assert.True(hardware.UptimeSeconds >= 0);
        Assert.Contains(hardware.Disks, value => value.SystemVolume && value.TotalBytes > 0 && value.FreeBytes >= 0);
    }
}
