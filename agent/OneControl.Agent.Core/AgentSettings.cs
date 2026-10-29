using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OneControl.Agent.Core;

public sealed record AgentSettings(Uri ControlPlane, Guid DeviceId, string ProtectedCredential,
    string[] ArtifactHosts, string[] AllowedPackages, string ReleasePublicKeyFile, string BrokerPath,
    string? PendingProtectedCredential = null, DateTimeOffset? CredentialCreatedAt = null,
    DateTimeOffset? PendingCredentialCreatedAt = null)
{
    [JsonIgnore]
    public string Credential => Encoding.UTF8.GetString(ProtectedData.Unprotect(
        Convert.FromBase64String(ProtectedCredential), null, DataProtectionScope.LocalMachine));

    public static string ProtectCredential(string value) => Convert.ToBase64String(
        ProtectedData.Protect(Encoding.UTF8.GetBytes(value), null, DataProtectionScope.LocalMachine));

    public static AgentSettings Load(string path)
    {
        ProtectedPaths.ValidateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!, privateLeaf: true);
        ProtectedPaths.ValidateFile(path, confidential: true);
        var settings = JsonSerializer.Deserialize<AgentSettings>(File.ReadAllText(path), Protocol.Json)
            ?? throw new InvalidDataException("Invalid agent settings");
        ValidateOrigin(settings.ControlPlane);
        if (!Path.IsPathFullyQualified(settings.ReleasePublicKeyFile) || !Path.IsPathFullyQualified(settings.BrokerPath))
            throw new InvalidDataException("Trusted files must use absolute paths");
        ProtectedPaths.ValidateFile(settings.ReleasePublicKeyFile);
        ProtectedPaths.ValidateFile(settings.BrokerPath);
        return settings.CredentialCreatedAt is null ? settings with { CredentialCreatedAt = File.GetLastWriteTimeUtc(path) } : settings;
    }
    public static void ValidateOrigin(Uri uri)
    {
        if (uri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new InvalidDataException("Control plane requires an HTTPS origin");
        if (uri.AbsolutePath != "/") throw new InvalidDataException("Control plane must be an origin without a path");
    }
    public static async Task SaveAsync(string path, AgentSettings settings, CancellationToken ct)
    {
        ProtectedPaths.ValidateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!, privateLeaf: true);
        if (File.Exists(path)) ProtectedPaths.ValidateFile(path, confidential: true);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            await using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(file, settings, Protocol.Json, ct);
                await file.FlushAsync(ct);
                file.Flush(flushToDisk: true);
            }
            ProtectedPaths.ValidateFile(temp, confidential: true);
            ct.ThrowIfCancellationRequested();
            File.Move(temp, path, overwrite: true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    public static bool RequiresRedaction(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        return document.RootElement.EnumerateObject().Any(property => string.Equals(property.Name, "credential", StringComparison.OrdinalIgnoreCase));
    }
    public override string ToString() => $"AgentSettings {{ DeviceId = {DeviceId}, Credential = [redacted] }}";
}
