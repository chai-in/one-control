namespace OneControl.Agent.Core;

public sealed class DatabaseCommitUnknownException : Exception
{
    public DatabaseCommitUnknownException() : base("Database commit outcome is unknown; inspect current state before further action") { }
    public string DatabaseOutcome => "unknown";
    public bool RetryAllowed => false;
}
