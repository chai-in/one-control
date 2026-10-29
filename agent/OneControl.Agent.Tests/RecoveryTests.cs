using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Security.Principal;
using OneControl.Agent.Core;
using Microsoft.Win32;
using Xunit;

namespace OneControl.Agent.Tests;

public sealed class RecoveryTests
{
    [RequiresAdministratorTheory]
    [InlineData("response")]
    [InlineData("commit")]
    public async Task RotationRecoversDurablePendingSecretAfterUncertainNetworkOrFileCommit(string failure)
    {
        using var fixture = new ProtectedFixture();
        var path = Path.Combine(fixture.Path, "agent.json");
        await AgentSettings.SaveAsync(path, fixture.Settings, CancellationToken.None);
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddDays(-31));
        using var transport = new RotationTransport(path, failure);
        await Assert.ThrowsAnyAsync<Exception>(() => CredentialRotation.RecoverOrRotateAsync(path, transport, CancellationToken.None));
        var pending = AgentSettings.Load(path);
        Assert.NotNull(pending.PendingProtectedCredential);
        Assert.Equal(fixture.Settings.ProtectedCredential, pending.ProtectedCredential);
        transport.ReleaseCommitLock();
        var recovered = await CredentialRotation.RecoverOrRotateAsync(path, transport, CancellationToken.None);
        Assert.Null(recovered.PendingProtectedCredential);
        Assert.Equal(transport.RegisteredHash, Digest(recovered.Credential));
        Assert.Equal(1, transport.Registrations);
        Assert.Equal(JsonSerializer.Serialize(recovered, Protocol.Json), JsonSerializer.Serialize(AgentSettings.Load(path), Protocol.Json));
        Assert.DoesNotContain(recovered.Credential, await File.ReadAllTextAsync(path));
    }

    [RequiresAdministratorFact]
    public async Task CancelledSettingsSavePreservesExistingConfiguration()
    {
        using var fixture = new ProtectedFixture();
        var path = Path.Combine(fixture.Path, "agent.json");
        await AgentSettings.SaveAsync(path, fixture.Settings, CancellationToken.None);
        var before = await File.ReadAllBytesAsync(path);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AgentSettings.SaveAsync(path,
            fixture.Settings with { PendingProtectedCredential = "must-not-commit" }, cancelled.Token));
        Assert.Equal(before, await File.ReadAllBytesAsync(path));
        Assert.Empty(Directory.GetFiles(fixture.Path, "*.new"));
    }

    [RequiresAdministratorFact]
    public void ParentDeleteChildAuthorityCannotBeHiddenByProtectedLeaf()
    {
        using var fixture = new ProtectedFixture();
        var parent = Directory.CreateDirectory(System.IO.Path.Combine(fixture.Path, "parent"));
        var leaf = Directory.CreateDirectory(System.IO.Path.Combine(parent.FullName, "leaf"));
        var acl = parent.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-32-545"), FileSystemRights.DeleteSubdirectoriesAndFiles, AccessControlType.Allow));
        parent.SetAccessControl(acl);
        Assert.Throws<InvalidDataException>(() => ProtectedPaths.ValidateDirectory(leaf.FullName, privateLeaf: true));
    }

    [RequiresAdministratorFact]
    public void ReparsePointCannotRedirectProtectedState()
    {
        using var fixture = new ProtectedFixture();
        var target = Directory.CreateDirectory(System.IO.Path.Combine(fixture.Path, "target"));
        var link = System.IO.Path.Combine(fixture.Path, "link");
        Directory.CreateSymbolicLink(link, target.FullName);
        try { Assert.Throws<InvalidDataException>(() => ProtectedPaths.ValidateDirectory(link, privateLeaf: true)); }
        finally { Directory.Delete(link); }
    }

    [Fact]
    public void UnrestrictedDaclIsRejectedEvenWithTrustedOwner()
    {
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm("O:BAG:BAD:NO_ACCESS_CONTROL");
        Assert.Throws<InvalidDataException>(() => ProtectedPaths.ValidateSecurity(security, FileSystemRights.FullControl));
    }

    [Theory]
    [InlineData("GR")]
    [InlineData("GX")]
    public void PrivateStateRejectsGenericReadOrExecutePermissions(string permission)
    {
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm($"O:BAG:BAD:P(A;;FA;;;BA)(A;;{permission};;;BU)");
        Assert.Throws<InvalidDataException>(() => ProtectedPaths.ValidateSecurity(security, FileSystemRights.FullControl));
        ProtectedPaths.ValidateSecurity(security, FileSystemRights.Write);
    }

    [RequiresAdministratorFact]
    public async Task SettingsNeverSerializePlaintextAndLegacyRedactionPreservesCredentialAge()
    {
        using var fixture = new ProtectedFixture();
        var path = Path.Combine(fixture.Path, "agent.json");
        var legacy = JsonSerializer.SerializeToNode(fixture.Settings, Protocol.Json)!;
        legacy["credential"] = "legacy-plaintext-fixture";
        File.WriteAllText(path, legacy.ToJsonString());
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddDays(-10));
        var priorAge = File.GetLastWriteTimeUtc(path);
        var loaded = AgentSettings.Load(path);
        Assert.True(AgentSettings.RequiresRedaction(path));
        await CredentialRotation.RecoverOrRotateAsync(path, new RotationTransport(path, "unused"), CancellationToken.None);
        Assert.False(AgentSettings.RequiresRedaction(path));
        Assert.Equal(new DateTimeOffset(priorAge), AgentSettings.Load(path).CredentialCreatedAt);
        Assert.Equal(loaded.ProtectedCredential, AgentSettings.Load(path).ProtectedCredential);
        Assert.DoesNotContain("initial-test-secret", await File.ReadAllTextAsync(path));
        Assert.DoesNotContain("initial-test-secret", loaded.ToString());
    }

    [Fact]
    public void ExpiredMaintenanceWindowFailsBeforeProviderCanStart()
    {
        Assert.Throws<ExecutionPreconditionException>(() => MaintenanceWindow.EnsureOpen(DateTimeOffset.UtcNow.AddSeconds(-1), CancellationToken.None));
        MaintenanceWindow.EnsureOpen(DateTimeOffset.UtcNow.AddMinutes(1), CancellationToken.None);
    }

    [Theory]
    [InlineData("winget.upgrade", "Microsoft.PowerToys", "1.2.3", "winget")]
    [InlineData("store.upgrade", "9NBLGGH4NNS1", null, "msstore")]
    public void ManagedPackagePolicyAcceptsAgreementsWithoutBroadeningTheApprovedTarget(string kind, string package, string? version, string source)
    {
        var arguments = UserPackageCommand.Arguments(new(kind, package, version));
        Assert.Equal(["upgrade", "--id", package, "--exact", "--source", source], arguments.Take(6));
        Assert.Contains("--accept-source-agreements", arguments);
        Assert.Contains("--accept-package-agreements", arguments);
        Assert.DoesNotContain("--all", arguments);
        Assert.DoesNotContain("--ignore-security-hash", arguments);
        if (version is not null) Assert.Equal(["--version", version], arguments.TakeLast(2));
    }

    [Theory]
    [InlineData("winget.upgrade", "--all", "1.2.3")]
    [InlineData("winget.upgrade", "Microsoft.PowerToys", "latest")]
    [InlineData("winget.upgrade", "Microsoft.PowerToys", "unknown")]
    [InlineData("store.upgrade", "Microsoft.PowerToys", null)]
    public void PackagePolicyRejectsUnpinnedVersionsAndAlternateStoreIdentities(string kind, string package, string? version) =>
        Assert.Throws<InvalidDataException>(() => UserPackageCommand.Arguments(new(kind, package, version)));

    private static string Digest(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private sealed class RotationTransport(string path, string failure) : ICredentialRotationTransport, IDisposable
    {
        public string? RegisteredHash { get; private set; }
        public int Registrations { get; private set; }
        private FileStream? commitLock;
        public Task ProbeAsync(AgentSettings settings, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (Digest(settings.Credential) != RegisteredHash) throw new HttpRequestException("Not registered", null, HttpStatusCode.Unauthorized);
            return Task.CompletedTask;
        }
        public Task RegisterAsync(AgentSettings settings, string credentialHash, CancellationToken ct)
        {
            Assert.NotNull(AgentSettings.Load(path).PendingProtectedCredential);
            RegisteredHash = credentialHash; Registrations++;
            if (failure == "response") throw new HttpRequestException("Response lost after server commit");
            commitLock = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return Task.CompletedTask;
        }
        public void ReleaseCommitLock() { commitLock?.Dispose(); commitLock = null; }
        public void Dispose() => ReleaseCommitLock();
    }

    private sealed class ProtectedFixture : IDisposable
    {
        private readonly string root = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OneControl.Agent.TestFixtures");
        public string Path { get; }
        public AgentSettings Settings { get; }
        public ProtectedFixture()
        {
            var acl = new DirectorySecurity();
            acl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
            new DirectoryInfo(root).Create(acl);
            ProtectedPaths.ValidateDirectory(root, privateLeaf: true);
            Path = System.IO.Path.Combine(root, Guid.NewGuid().ToString("N"));
            new DirectoryInfo(Path).Create(acl);
            var broker = System.IO.Path.Combine(Path, "broker.exe");
            var key = System.IO.Path.Combine(Path, "release.pem");
            File.WriteAllText(broker, "non-executable test fixture"); File.WriteAllText(key, "public-key fixture");
            Settings = new(new Uri("https://management.example"), Guid.NewGuid(), AgentSettings.ProtectCredential("initial-test-secret"), ["updates.example"], ["example-application"], key, broker);
        }
        public void Dispose()
        {
            var resolved = System.IO.Path.GetFullPath(Path);
            if (!resolved.StartsWith(System.IO.Path.GetFullPath(root) + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Test cleanup escaped its dedicated fixture root");
            ProtectedPaths.ValidateDirectory(resolved, privateLeaf: true);
            Directory.Delete(resolved, recursive: true);
        }
    }
}
