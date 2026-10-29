namespace OneControl.Agent.Core;

public sealed class ExecutionPreconditionException(string message) : Exception(message);

public static class MaintenanceWindow
{
    public static void EnsureOpen(DateTimeOffset endsAt, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (DateTimeOffset.UtcNow >= endsAt) throw new ExecutionPreconditionException("Maintenance window ended before provider start");
    }
}
