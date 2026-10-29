namespace OneControl.Agent.Core;

public sealed record AgentHealth(Guid DeviceId, int ProcessId, string Executable, string Version, DateTimeOffset AuthenticatedAt)
{
    public static void Record(string state, Guid deviceId) => ProtectedJson.Write(Path.Combine(state, "health.json"),
        new AgentHealth(deviceId, Environment.ProcessId, Environment.ProcessPath ?? throw new InvalidOperationException("Executable unavailable"),
            typeof(AgentHealth).Assembly.GetName().Version!.ToString(), DateTimeOffset.UtcNow));

    public static bool Matches(AgentHealth? health, Guid deviceId, int processId, string executable, Version version, DateTimeOffset since) =>
        health is not null && health.DeviceId == deviceId && health.ProcessId == processId &&
        string.Equals(health.Executable, executable, StringComparison.OrdinalIgnoreCase) &&
        System.Version.TryParse(health.Version, out var actual) && actual == version && health.AuthenticatedAt >= since;
}
