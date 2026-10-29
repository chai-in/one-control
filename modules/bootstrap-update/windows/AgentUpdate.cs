namespace OneControl.Agent.Core;

public enum AgentUpdatePhase { Requested, Installing, Ready, Activating, Verifying, RollingBack, Reporting, Completed }
public sealed record AgentUpdatePlan(Lease Lease, DateTimeOffset RequestedAt, AgentUpdatePhase Phase = AgentUpdatePhase.Requested,
    string? PreviousExecutable = null, string? PreviousBroker = null, string? PreviousSha256 = null,
    DateTimeOffset? ActivatedAt = null, JobReceipt? Receipt = null);

public sealed class AgentUpdateStore
{
    private readonly string path;
    public AgentUpdateStore(string state)
    {
        var directory = Path.Combine(state, "recovery");
        ProtectedJson.EnsurePrivateDirectory(directory);
        path = Path.Combine(directory, "active.json");
    }
    public AgentUpdatePlan? Read() => ProtectedJson.Read<AgentUpdatePlan>(path);
    public void Save(AgentUpdatePlan plan) => ProtectedJson.Write(path, plan);
    public bool Owns(Guid id) => Read() is { } plan && plan.Lease.Id == id && plan.Phase != AgentUpdatePhase.Completed;
    public void Enqueue(Lease lease)
    {
        if (Read() is { Phase: not AgentUpdatePhase.Completed }) throw new ExecutionPreconditionException("An agent recovery operation is outstanding");
        Save(new(lease, DateTimeOffset.UtcNow));
    }
}

internal interface IAgentUpdatePlatform
{
    Task<AgentUpdatePlan> InstallAsync(AgentUpdatePlan plan, CancellationToken ct);
    Task ActivateAsync(AgentUpdatePlan plan, CancellationToken ct);
    Task<bool> HealthyAsync(AgentUpdatePlan plan, CancellationToken ct);
    Task<bool> RollbackAsync(AgentUpdatePlan plan, CancellationToken ct);
}

// Persist intent before every side effect. An interrupted installer is quarantined, never re-executed.
internal sealed class AgentUpdateRunner(AgentUpdateStore store, IAgentUpdatePlatform platform)
{
    public async Task<AgentUpdatePlan> RunAsync(AgentUpdatePlan plan, CancellationToken ct)
    {
        try
        {
            if (plan.Phase == AgentUpdatePhase.Requested)
            {
                MaintenanceWindow.EnsureOpen(plan.Lease.EndsAt, ct);
                plan = await platform.InstallAsync(plan, ct); // platform checkpoints Installing before starting MSI
                store.Save(plan);
            }
            else if (plan.Phase == AgentUpdatePhase.Installing)
                return Finish(plan, "indeterminate", "recovery_restarted_during_installer");
            else if (plan.Phase is AgentUpdatePhase.Activating or AgentUpdatePhase.Verifying or AgentUpdatePhase.RollingBack)
                return await RollbackAsync(plan, "recovery_restarted_during_activation", ct);

            if (plan.Phase == AgentUpdatePhase.Ready)
            {
                MaintenanceWindow.EnsureOpen(plan.Lease.EndsAt, ct);
                plan = plan with { Phase = AgentUpdatePhase.Activating, ActivatedAt = DateTimeOffset.UtcNow };
                store.Save(plan);
                await platform.ActivateAsync(plan, ct);
                plan = plan with { Phase = AgentUpdatePhase.Verifying };
                store.Save(plan);
                if (!await platform.HealthyAsync(plan, ct)) return await RollbackAsync(plan, "candidate_health_failed", ct);
                return Finish(plan, "succeeded", "authenticated_candidate_health");
            }
            return plan;
        }
        catch (Exception error)
        {
            // Reload the durable checkpoint if a platform operation failed after persisting intent.
            plan = store.Read() ?? plan;
            if (plan.Phase is AgentUpdatePhase.Activating or AgentUpdatePhase.Verifying or AgentUpdatePhase.RollingBack)
                return await RollbackAsync(plan, error.GetType().Name, CancellationToken.None);
            return Finish(plan, plan.Phase == AgentUpdatePhase.Installing ? "indeterminate" : "failed", error.GetType().Name);
        }
    }
    private async Task<AgentUpdatePlan> RollbackAsync(AgentUpdatePlan plan, string reason, CancellationToken ct)
    {
        plan = plan with { Phase = AgentUpdatePhase.RollingBack };
        store.Save(plan);
        bool recovered;
        // Lease loss cancels forward progress, but must not prevent bounded local restoration.
        // The platform independently bounds rollback even when the caller's token is cancelled.
        try { recovered = await platform.RollbackAsync(plan, CancellationToken.None); }
        catch { recovered = false; }
        return Finish(plan, recovered ? "failed" : "indeterminate", reason, recovered);
    }
    private AgentUpdatePlan Finish(AgentUpdatePlan plan, string state, string reason, bool? rollback = null)
    {
        var result = new Dictionary<string, object?> { ["reason"] = reason, ["provider"] = "independent_agent_recovery" };
        if (rollback is not null) result["rollbackVerified"] = rollback;
        plan = plan with { Phase = AgentUpdatePhase.Reporting, Receipt = new(state, result) };
        store.Save(plan);
        return plan;
    }
}
