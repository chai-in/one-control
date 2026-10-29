using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace OneControl.Agent.Core;

public static class Inventory
{
    public const int MaximumBytes = 192 * 1024;
    private const int ApplicationLimit = 500;

    public static Dictionary<string, object?> Collect(string? state = null)
    {
        var elapsed = Stopwatch.StartNew();
        var diagnostics = new InventoryDiagnostics();
        var version = diagnostics.Capture<(string?, string?)>("windows.version", () =>
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return (InventoryDiagnostics.Text(key?.GetValue("DisplayVersion"), 64),
                InventoryDiagnostics.Text(key?.GetValue("CurrentBuildNumber"), 32));
        }, (null, null));
        var reboot = diagnostics.Capture<bool?>("windows.restart", () => RebootPending(), null);
        var apps = diagnostics.Bound(Applications(diagnostics), "applications", ApplicationLimit, 128 * 1024);
        var report = new Dictionary<string, object?>
        {
            ["hostname"] = Environment.MachineName,
            ["osVersion"] = Environment.OSVersion.VersionString,
            ["displayVersion"] = version.Item1,
            ["build"] = version.Item2,
            ["architecture"] = RuntimeInformation.OSArchitecture.ToString(),
            ["agentVersion"] = typeof(Inventory).Assembly.GetName().Version?.ToString(),
            ["agentRecoveryReady"] = diagnostics.Capture<bool?>("agent.recovery", () => AgentServiceControl.RecoveryAvailable(), null),
            ["rebootPending"] = reboot,
            ["hardware"] = HardwareInventory.Collect(diagnostics),
            ["applications"] = apps,
            ["collectedAt"] = DateTimeOffset.UtcNow,
            ["interactiveSessionAvailable"] = diagnostics.Capture<bool?>("user.session", () => SessionBroker.HasInteractiveSession, null)
        };
        report["collection"] = Metadata(diagnostics, elapsed.ElapsedMilliseconds);
        // Keep a valid heartbeat even if a future collector accidentally exceeds its budget.
        // Dropping outbound observations never modifies installed apps or local provisioning state.
        if (JsonSerializer.SerializeToUtf8Bytes(report, Protocol.Json).Length > MaximumBytes)
        {
            diagnostics.Report("inventory", "payload_limit");
            report.Remove("hardware");
            report.Remove("applications");
            report["collection"] = Metadata(diagnostics, elapsed.ElapsedMilliseconds);
        }
        return report;
    }

    private static object Metadata(InventoryDiagnostics diagnostics, long durationMs) => new
    {
        schemaVersion = 2,
        status = diagnostics.Partial ? "partial" : "complete",
        applicationScope = "machine_registry_32_and_64_bit",
        applicationLimit = ApplicationLimit,
        issues = diagnostics.Issues,
        durationMs
    };

    private static bool RebootPending()
    {
        using var update = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired");
        using var cbs = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending");
        using var session = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager");
        return update is not null || cbs is not null ||
            session?.GetValue("PendingFileRenameOperations", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string[] { Length: > 0 };
    }

    private static IEnumerable<Dictionary<string, string?>> Applications(InventoryDiagnostics diagnostics)
    {
        var visited = 0;
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var hive = diagnostics.Capture<RegistryKey?>("applications", () => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view), null);
            using var uninstall = diagnostics.Capture("applications", () => hive?.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"), null);
            var names = diagnostics.Capture("applications", () => uninstall?.GetSubKeyNames() ?? [], []);
            foreach (var name in names)
            {
                if (++visited > 2048) { diagnostics.Report("applications", "collection_limit"); yield break; }
                var observation = diagnostics.Capture<Dictionary<string, string?>?>("applications", () =>
                {
                    using var app = uninstall!.OpenSubKey(name);
                    var displayName = InventoryDiagnostics.Text(app?.GetValue("DisplayName", null, RegistryValueOptions.DoNotExpandEnvironmentNames), 192);
                    if (displayName is null) return null;
                    return new()
                    {
                        ["name"] = displayName,
                        ["version"] = InventoryDiagnostics.Text(app?.GetValue("DisplayVersion", null, RegistryValueOptions.DoNotExpandEnvironmentNames), 64),
                        ["publisher"] = InventoryDiagnostics.Text(app?.GetValue("Publisher", null, RegistryValueOptions.DoNotExpandEnvironmentNames), 128)
                    };
                }, null);
                if (observation is not null) yield return observation;
            }
        }
    }
}
