using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OneControl.Agent.Core;

internal sealed class WindowsAgentUpdate(string state, AgentUpdateStore store) : IAgentUpdatePlatform
{
    private string SettingsPath => Path.Combine(state, "agent.json");
    private static string InstallRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OneControl", "Agent");
    private static string Candidate(Version version, string module) => Path.Combine(InstallRoot, "versions", $"{version.Major}.{version.Minor}.{version.Build}", module, $"OneControl.Agent.{module}.exe");
    private ReleaseManifest Verify(AgentUpdatePlan plan, AgentSettings settings, DateTimeOffset now) =>
        ReleaseInstaller.Verify(plan.Lease.Release ?? throw new InvalidDataException("Signed agent release missing"), File.ReadAllText(settings.ReleasePublicKeyFile), settings, now);
    private static Version VersionOf(string path) => Version.Parse(FileVersionInfo.GetVersionInfo(path).FileVersion ?? throw new InvalidDataException("File version unavailable"));
    internal static Version PayloadVersion(ReleaseManifest manifest)
    {
        if (manifest.PackageId != "one-control-agent" || !Version.TryParse(manifest.Version, out var version) || version.Build < 0 || version.Revision >= 0 ||
            version.Major > 255 || version.Minor > 255 || version.Build > 65535)
            throw new InvalidDataException("Agent payload requires a three-part Windows version");
        return new(version.Major, version.Minor, version.Build, 0);
    }
    public async Task<AgentUpdatePlan> InstallAsync(AgentUpdatePlan plan, CancellationToken ct)
    {
        var settings = AgentSettings.Load(SettingsPath);
        var manifest = Verify(plan, settings, DateTimeOffset.UtcNow);
        var version = PayloadVersion(manifest);
        var previous = AgentServiceControl.Executable();
        var previousVersion = VersionOf(previous);
        if (version <= previousVersion) throw new ExecutionPreconditionException("Agent version must increase");
        Inspect(previous, Publisher(previous), previousVersion);
        if (Directory.Exists(Path.GetDirectoryName(Candidate(version, "Service"))))
            throw new ExecutionPreconditionException("Candidate payload already exists; reconcile instead of reinstalling");
        var destination = Path.Combine(state, "recovery", plan.Lease.Id + ".msi");
        await ReleaseArtifact.DownloadAsync(manifest, destination, ct);
        ValidatePayload(destination, manifest.Version);
        MaintenanceWindow.EnsureOpen(plan.Lease.EndsAt, ct);
        Verify(plan, settings, DateTimeOffset.UtcNow);
        plan = plan with
        {
            Phase = AgentUpdatePhase.Installing,
            PreviousExecutable = previous,
            PreviousBroker = settings.BrokerPath,
            PreviousSha256 = Digest(previous)
        };
        store.Save(plan);
        var code = await ProcessRunner.RunAsync(Path.Combine(Environment.SystemDirectory, "msiexec.exe"),
            ["/i", destination, "/qn", "/norestart", "REBOOT=ReallySuppress"], TimeSpan.FromMinutes(20), ct);
        if (code is not (0 or 3010)) throw new ExecutionIndeterminateException("Agent payload installer did not return success");
        Inspect(Candidate(version, "Service"), manifest.PublisherThumbprint, version);
        Inspect(Candidate(version, "Broker"), manifest.PublisherThumbprint, version);
        if (Digest(previous) != plan.PreviousSha256) throw new InvalidDataException("Last-known-good agent was changed by payload installation");
        return plan with { Phase = AgentUpdatePhase.Ready };
    }
    public async Task ActivateAsync(AgentUpdatePlan plan, CancellationToken ct)
    {
        var settings = AgentSettings.Load(SettingsPath);
        var manifest = Verify(plan, settings, DateTimeOffset.UtcNow);
        var version = PayloadVersion(manifest);
        Inspect(Candidate(version, "Service"), manifest.PublisherThumbprint, version);
        Inspect(Candidate(version, "Broker"), manifest.PublisherThumbprint, version);
        if (!string.Equals(AgentServiceControl.Executable(), plan.PreviousExecutable, StringComparison.OrdinalIgnoreCase) || Digest(plan.PreviousExecutable!) != plan.PreviousSha256)
            throw new InvalidDataException("Active agent changed before activation");
        await AgentServiceControl.StopAsync(ct);
        settings = AgentSettings.Load(SettingsPath); // preserve the latest durable credential after the old process stops
        await AgentSettings.SaveAsync(SettingsPath, settings with { BrokerPath = Candidate(version, "Broker") }, ct);
        AgentServiceControl.Configure(Candidate(version, "Service"));
        await AgentServiceControl.StartAsync(ct);
    }
    public async Task<bool> HealthyAsync(AgentUpdatePlan plan, CancellationToken ct)
    {
        var settings = AgentSettings.Load(SettingsPath);
        var manifest = Verify(plan, settings, plan.RequestedAt);
        var version = PayloadVersion(manifest);
        return await WaitForHealthAsync(settings.DeviceId, Candidate(version, "Service"), version, plan.ActivatedAt!.Value, ct);
    }
    public async Task<bool> RollbackAsync(AgentUpdatePlan plan, CancellationToken ct)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(ct);
        bounded.CancelAfter(TimeSpan.FromMinutes(5));
        var previous = plan.PreviousExecutable ?? throw new InvalidDataException("Recovery executable missing");
        ProtectedPaths.ValidateFile(previous);
        if (Digest(previous) != plan.PreviousSha256) throw new InvalidDataException("Last-known-good bytes changed");
        var version = VersionOf(previous);
        Inspect(previous, Publisher(previous), version);
        var settings = AgentSettings.Load(SettingsPath);
        var manifest = Verify(plan, settings, plan.RequestedAt);
        var active = AgentServiceControl.Executable();
        if (!string.Equals(active, previous, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(active, Candidate(PayloadVersion(manifest), "Service"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Unexpected active service; manual reconciliation required");
        if (string.Equals(active, previous, StringComparison.OrdinalIgnoreCase) && AgentServiceControl.ProcessId() != 0)
            return await WaitForHealthAsync(settings.DeviceId, previous, version, plan.ActivatedAt ?? plan.RequestedAt, bounded.Token);
        await AgentServiceControl.StopAsync(bounded.Token);
        ProtectedPaths.ValidateFile(plan.PreviousBroker!);
        settings = AgentSettings.Load(SettingsPath);
        await AgentSettings.SaveAsync(SettingsPath, settings with { BrokerPath = plan.PreviousBroker! }, bounded.Token);
        AgentServiceControl.Configure(previous);
        var since = DateTimeOffset.UtcNow;
        await AgentServiceControl.StartAsync(bounded.Token);
        return await WaitForHealthAsync(settings.DeviceId, previous, version, since, bounded.Token);
    }
    private async Task<bool> WaitForHealthAsync(Guid deviceId, string executable, Version version, DateTimeOffset since, CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow.AddMinutes(3);
        do
        {
            ct.ThrowIfCancellationRequested();
            var health = ProtectedJson.Read<AgentHealth>(Path.Combine(state, "health.json"));
            if (AgentHealth.Matches(health, deviceId, AgentServiceControl.ProcessId(), executable, version, since)) return true;
            await Task.Delay(2000, ct);
        } while (DateTimeOffset.UtcNow < deadline);
        return false;
    }
    private static string Digest(string path) { using var file = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(file)); }
    private static string Publisher(string path)
    {
#pragma warning disable SYSLIB0057
        using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
        return certificate.Thumbprint;
    }
    private static void Inspect(string path, string thumbprint, Version version)
    {
        ProtectedPaths.ValidateFile(path);
        ReleaseInstaller.VerifyAuthenticode(path, thumbprint);
        if (VersionOf(path) != version) throw new InvalidDataException("Agent payload version mismatch");
    }
    private static void ValidatePayload(string path, string version)
    {
        var com = new List<object>();
        try
        {
            dynamic installer = Activator.CreateInstance(Type.GetTypeFromProgID("WindowsInstaller.Installer")!)!; com.Add(installer);
            dynamic database = installer.OpenDatabase(path, 0); com.Add(database);
            foreach (var table in new[] { "CustomAction", "ServiceControl", "ServiceInstall" })
            {
                dynamic present = database.OpenView($"SELECT `Name` FROM `_Tables` WHERE `Name`='{table}'"); com.Add(present); present.Execute();
                object? row = present.Fetch();
                if (row is null) continue;
                com.Add(row);
                dynamic entries = database.OpenView($"SELECT * FROM `{table}`"); com.Add(entries); entries.Execute();
                object? entry = entries.Fetch();
                if (entry is not null) { com.Add(entry); throw new InvalidDataException("Agent MSI must stage files without custom actions or service operations"); }
            }
            foreach (var (property, expected) in new[] { ("ONE_CONTROL_PAYLOAD_KIND", "stage_only"), ("ONE_CONTROL_PAYLOAD_VERSION", version) })
            {
                dynamic view = database.OpenView($"SELECT `Value` FROM `Property` WHERE `Property`='{property}'"); com.Add(view); view.Execute();
                dynamic? record = view.Fetch();
                if (record is null) throw new InvalidDataException("Agent payload marker missing");
                com.Add(record);
                if ((string)record.StringData[1] != expected) throw new InvalidDataException("Agent payload marker mismatch");
            }
        }
        finally { foreach (var item in com.AsEnumerable().Reverse()) Marshal.FinalReleaseComObject(item); }
    }
}
