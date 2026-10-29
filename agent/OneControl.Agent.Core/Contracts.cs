using System.Text.Json;

namespace OneControl.Agent.Core;

public sealed record UpdateIdentity(Guid Id, int Revision);
public sealed record Command(string Kind, string? PackageId = null, string? Version = null,
    Guid? ReleaseId = null, UpdateIdentity[]? Updates = null);
public sealed record SignedEnvelope(string Payload, string Signature);
public sealed record Lease(Guid Id, string LeaseToken, DateTimeOffset LeaseExpiresAt,
    Command Command, SignedEnvelope? Release, DateTimeOffset EndsAt);
public sealed record JobReceipt(string State, Dictionary<string, object?> Result);
public sealed record BrokerTask(Command Command, DateTimeOffset EndsAt);
public sealed record ReleaseManifest(int SchemaVersion, string PackageId, long Sequence, string Version,
    string ArtifactUrl, string Sha256, long Size, string PublisherThumbprint, DateTimeOffset ExpiresAt);
public static class Protocol
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 16
    };
    public static bool IsMutation(Command command) => command.Kind is not ("inventory.scan" or "windows.scan");
    public static bool IsUserCommand(Command command) => command.Kind is "winget.upgrade" or "store.upgrade";
}
