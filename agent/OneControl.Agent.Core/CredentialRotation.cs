using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace OneControl.Agent.Core;

public static class CredentialRotation
{
    public static Task<AgentSettings> RecoverOrRotateAsync(string settingsPath, CancellationToken ct) =>
        RecoverOrRotateAsync(settingsPath, new HttpCredentialTransport(), ct);

    internal static async Task<AgentSettings> RecoverOrRotateAsync(string settingsPath, ICredentialRotationTransport transport, CancellationToken ct)
    {
        // Reload after any previous exception: disk may contain a pending credential not yet returned to the worker.
        var settings = AgentSettings.Load(settingsPath);
        if (AgentSettings.RequiresRedaction(settingsPath)) await AgentSettings.SaveAsync(settingsPath, settings, ct);
        if (settings.PendingProtectedCredential is null)
        {
            if (settings.CredentialCreatedAt >= DateTimeOffset.UtcNow.AddDays(-30)) return settings;
            var credential = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var pending = settings with { PendingProtectedCredential = AgentSettings.ProtectCredential(credential), PendingCredentialCreatedAt = DateTimeOffset.UtcNow };
            // The new secret must survive a crash before the server can shorten the old credential's life.
            await AgentSettings.SaveAsync(settingsPath, pending, ct);
            settings = pending;
        }
        var next = settings with
        {
            ProtectedCredential = settings.PendingProtectedCredential!,
            PendingProtectedCredential = null,
            CredentialCreatedAt = settings.PendingCredentialCreatedAt ?? DateTimeOffset.UtcNow,
            PendingCredentialCreatedAt = null
        };
        try { await transport.ProbeAsync(next, ct); }
        catch (HttpRequestException error) when (error.StatusCode == HttpStatusCode.Unauthorized)
        {
            var credentialHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(next.Credential)));
            await transport.RegisterAsync(settings, credentialHash, ct);
            await transport.ProbeAsync(next, ct);
        }
        // Commit only after proving the new secret works. A failed save leaves durable pending recovery intact.
        await AgentSettings.SaveAsync(settingsPath, next, ct);
        return next;
    }

    internal sealed class HttpCredentialTransport : ICredentialRotationTransport
    {
        private readonly Func<AgentSettings, ControlPlaneClient> clientFactory;
        public HttpCredentialTransport() : this(settings => new(settings.ControlPlane, settings.Credential)) { }
        internal HttpCredentialTransport(Func<AgentSettings, ControlPlaneClient> clientFactory) => this.clientFactory = clientFactory;
        public async Task ProbeAsync(AgentSettings settings, CancellationToken ct)
        {
            using var api = clientFactory(settings);
            await api.SendAsync("v1/agent/heartbeat", new { }, ct);
        }
        public async Task RegisterAsync(AgentSettings settings, string credentialHash, CancellationToken ct)
        {
            using var api = clientFactory(settings);
            await api.SendAsync("v1/agent/credentials/rotate", new { credentialHash }, ct);
        }
    }
}

internal interface ICredentialRotationTransport
{
    Task ProbeAsync(AgentSettings settings, CancellationToken ct);
    Task RegisterAsync(AgentSettings settings, string credentialHash, CancellationToken ct);
}
