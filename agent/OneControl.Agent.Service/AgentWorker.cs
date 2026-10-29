using System.Net;
using System.ComponentModel;
using OneControl.Agent.Core;

namespace OneControl.Agent.Service;

public sealed class AgentWorker : BackgroundService
{
    private readonly ILogger<AgentWorker> logger;
    private readonly string state;
    private readonly Func<AgentSettings, ControlPlaneClient> clientFactory;
    public AgentWorker(ILogger<AgentWorker> logger) : this(logger,
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OneControl", "Agent"),
        settings => new(settings.ControlPlane, settings.Credential)) { }
    internal AgentWorker(ILogger<AgentWorker> logger, string protectedFixtureState, Func<AgentSettings, ControlPlaneClient> clientFactory)
    {
        this.logger = logger;
        state = protectedFixtureState;
        this.clientFactory = clientFactory;
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settingsPath = Path.Combine(state, "agent.json");
        var settings = AgentSettings.Load(settingsPath);
        using var journal = new Journal(Path.Combine(state, "journal.db"));
        var failures = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                settings = await CredentialRotation.RecoverOrRotateAsync(settingsPath, stoppingToken);
                using var api = clientFactory(settings);
                foreach (var (lease, pending) in journal.Pending())
                {
                    if (new AgentUpdateStore(state).Owns(lease.Id)) continue;
                    var receipt = pending ?? new JobReceipt("indeterminate", new() { ["reason"] = "service_restarted_during_execution" });
                    journal.Finish(lease.Id, receipt);
                    try { await api.ReportAsync(lease, receipt, stoppingToken); journal.Acknowledge(lease.Id); }
                    catch (HttpRequestException error) when (error.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.NotFound)
                    { journal.Acknowledge(lease.Id); logger.LogWarning("Job {JobId} requires coordinator reconciliation", lease.Id); }
                }
                await api.SendAsync("v1/agent/heartbeat", new { inventory = Inventory.Collect(state) }, stoppingToken);
                AgentHealth.Record(state, settings.DeviceId);
                var claimed = await api.ClaimAsync(stoppingToken);
                if (claimed is not null) await ExecuteJobAsync(claimed, settings, journal, api, state, stoppingToken);
                failures = 0;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error)
            {
                failures = Math.Min(failures + 1, 8);
                logger.LogWarning("Agent operation failed: {ErrorType}; backing off", error.GetType().Name);
            }
            var seconds = Math.Min(300, 15 * (1 << failures)) + Random.Shared.Next(0, 10);
            try { await Task.Delay(TimeSpan.FromSeconds(seconds), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
    private async Task ExecuteJobAsync(Lease lease, AgentSettings settings, Journal journal,
        ControlPlaneClient api, string state, CancellationToken stoppingToken)
    {
        journal.Begin(lease);
        using var execution = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        using var renewStop = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var renewal = RenewAsync(api, lease, execution, renewStop.Token);
        JobReceipt receipt;
        try
        {
            MaintenanceWindow.EnsureOpen(lease.EndsAt, execution.Token);
            if (lease.Command.Kind == "package.install" && lease.Release is not null &&
                ReleaseInstaller.Verify(lease.Release, await File.ReadAllTextAsync(settings.ReleasePublicKeyFile, execution.Token), settings, DateTimeOffset.UtcNow).PackageId == "one-control-agent")
            {
                AgentRecovery.Request(state, lease, settings, journal);
                return; // independent SYSTEM recovery owns renewal, restart, health verification and the terminal receipt
            }
            receipt = lease.Command.Kind switch
            {
                "inventory.scan" => new("succeeded", Inventory.Collect(state)),
                "windows.scan" or "windows.install" => await WindowsUpdates.ExecuteAsync(lease.Command, lease.EndsAt, execution.Token),
                "winget.upgrade" or "store.upgrade" => await SessionBroker.ExecuteAsync(settings.BrokerPath, lease.Command, lease.EndsAt, execution.Token),
                "package.install" => await ReleaseInstaller.InstallAsync(lease, settings, journal, Path.Combine(state, "staging"), execution.Token),
                _ => new("failed", new() { ["reason"] = "unsupported_command" })
            };
        }
        catch (Exception error)
        {
            var result = new Dictionary<string, object?> { ["reason"] = error.GetType().Name, ["hresult"] = error.HResult };
            if (error is Win32Exception native)
            {
                result["nativeErrorCode"] = native.NativeErrorCode;
                if (native.Data["operation"] is string operation) result["operation"] = operation;
            }
            receipt = new(Protocol.IsMutation(lease.Command) && error is not ExecutionPreconditionException ? "indeterminate" : "failed",
                result);
        }
        finally { await renewStop.CancelAsync(); await renewal; }
        journal.Finish(lease.Id, receipt);
        await api.ReportAsync(lease, receipt, stoppingToken);
        journal.Acknowledge(lease.Id);
    }
    private async Task RenewAsync(ControlPlaneClient api, Lease lease, CancellationTokenSource execution, CancellationToken ct)
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
            while (await timer.WaitForNextTickAsync(ct)) await api.RenewAsync(lease, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception) { logger.LogWarning("Lease lost for job {JobId}", lease.Id); await execution.CancelAsync(); }
    }
}
