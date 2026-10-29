using System.Net;

namespace OneControl.Agent.Core;

public static class AgentRecovery
{
    public static void Request(string state, Lease lease, AgentSettings settings, Journal journal)
    {
        if (!AgentServiceControl.RecoveryAvailable()) throw new ExecutionPreconditionException("Independent recovery service must be running");
        var manifest = ReleaseInstaller.Verify(lease.Release ?? throw new InvalidDataException("Signed agent release missing"),
            File.ReadAllText(settings.ReleasePublicKeyFile), settings, DateTimeOffset.UtcNow);
        WindowsAgentUpdate.PayloadVersion(manifest);
        MaintenanceWindow.EnsureOpen(lease.EndsAt, CancellationToken.None);
        var store = new AgentUpdateStore(state);
        if (store.Read() is { Phase: not AgentUpdatePhase.Completed }) throw new ExecutionPreconditionException("Agent recovery is outstanding");
        journal.ReserveSequence(manifest.PackageId, manifest.Sequence);
        store.Enqueue(lease);
    }

    public static Task RunOnceAsync(string state, CancellationToken ct) =>
        RunOnceAsync(state, settings => new(settings.ControlPlane, settings.Credential), ct);

    internal static async Task RunOnceAsync(string state, Func<AgentSettings, ControlPlaneClient> clientFactory, CancellationToken ct)
    {
        var store = new AgentUpdateStore(state);
        var plan = store.Read();
        if (plan is null || plan.Phase == AgentUpdatePhase.Completed) return;
        using var ownership = new FileStream(Path.Combine(state, "recovery", "owner.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        ProtectedPaths.ValidateFile(ownership.Name, confidential: true);
        using var journal = new Journal(Path.Combine(state, "journal.db"));
        if (plan.Phase != AgentUpdatePhase.Reporting)
        {
            using var execution = CancellationTokenSource.CreateLinkedTokenSource(ct);
            using var renewStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            using var api = Client(state, clientFactory);
            try
            {
                // Local rollback after interrupted activation must not depend on the network or an unexpired lease.
                if (plan.Phase is not (AgentUpdatePhase.Activating or AgentUpdatePhase.Verifying or AgentUpdatePhase.RollingBack or AgentUpdatePhase.Installing))
                    await api.RenewAsync(plan.Lease, ct);
            }
            catch (HttpRequestException error) when (error.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.NotFound or HttpStatusCode.Unauthorized)
            {
                plan = plan with { Phase = AgentUpdatePhase.Reporting, Receipt = new("indeterminate", new() { ["reason"] = "recovery_lease_lost" }) };
                store.Save(plan);
            }
            if (plan.Phase != AgentUpdatePhase.Reporting)
            {
                var renewal = RenewAsync(state, plan.Lease, clientFactory, execution, renewStop.Token);
                try { plan = await new AgentUpdateRunner(store, new WindowsAgentUpdate(state, store)).RunAsync(plan, execution.Token); }
                finally { await renewStop.CancelAsync(); await renewal; }
            }
        }
        if (plan is not { Phase: AgentUpdatePhase.Reporting, Receipt: not null }) return;
        journal.Finish(plan.Lease.Id, plan.Receipt);
        try { using var api = Client(state, clientFactory); await api.ReportAsync(plan.Lease, plan.Receipt, ct); }
        catch (HttpRequestException error) when (error.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.NotFound)
        {
            // Coordinator quarantine remains authoritative; retain the local receipt for IT reconciliation.
        }
        journal.Acknowledge(plan.Lease.Id);
        store.Save(plan with { Phase = AgentUpdatePhase.Completed });
    }
    private static ControlPlaneClient Client(string state, Func<AgentSettings, ControlPlaneClient> clientFactory)
    {
        var settings = AgentSettings.Load(Path.Combine(state, "agent.json"));
        return clientFactory(settings);
    }
    private static async Task RenewAsync(string state, Lease lease, Func<AgentSettings, ControlPlaneClient> clientFactory, CancellationTokenSource execution, CancellationToken ct)
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
            while (await timer.WaitForNextTickAsync(ct)) { using var api = Client(state, clientFactory); await api.RenewAsync(lease, ct); }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch { await execution.CancelAsync(); }
    }
}
