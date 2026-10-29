using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using OneControl.Agent.Core;
using Xunit;

namespace OneControl.Agent.Tests;

public sealed class TrustTests
{
    [Fact]
    public void InventoryUsesTheDeclaredAgentVersion()
    {
        var version = typeof(Inventory).Assembly.GetName().Version;
        Assert.NotNull(version);
        var declared = XDocument.Load(Path.Combine(AppContext.BaseDirectory, "DeclaredBuild.props"))
            .Root?.Element("PropertyGroup")?.Element("Version")?.Value;
        Assert.NotNull(declared);
        Assert.Equal(new Version(declared + ".0"), version);
    }
    private static AgentSettings Settings() => new(new Uri("https://management.example.com"), Guid.NewGuid(), "unused",
        ["updates.example.com"], ["one-control-agent", "example-application"], @"C:\trust\release.pem", @"C:\apps\broker.exe");
    private static ReleaseManifest Manifest() => new(1, "one-control-agent", 1, "0.1.0", "https://updates.example.com/agent.msi",
        new string('a', 64), 1234, new string('A', 40), DateTimeOffset.UtcNow.AddHours(1));
    private static SignedEnvelope Sign(RSA rsa, ReleaseManifest manifest)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, Protocol.Json);
        return new(Convert.ToBase64String(bytes), Convert.ToBase64String(rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)));
    }
    [Fact]
    public void TrustedReleaseVerifies()
    {
        using var rsa = RSA.Create(3072); var manifest = Manifest();
        var result = ReleaseInstaller.Verify(Sign(rsa, manifest), rsa.ExportSubjectPublicKeyInfoPem(), Settings(), DateTimeOffset.UtcNow);
        Assert.Equal(manifest, result);
    }
    [Fact]
    public void ChangedBytesAndForeignKeysFail()
    {
        using var rsa = RSA.Create(3072); using var other = RSA.Create(3072);
        var original = Sign(rsa, Manifest()); var changed = Sign(rsa, Manifest() with { Sequence = 2 });
        Assert.Throws<InvalidDataException>(() => ReleaseInstaller.Verify(original with { Payload = changed.Payload }, rsa.ExportSubjectPublicKeyInfoPem(), Settings(), DateTimeOffset.UtcNow));
        Assert.Throws<InvalidDataException>(() => ReleaseInstaller.Verify(original, other.ExportSubjectPublicKeyInfoPem(), Settings(), DateTimeOffset.UtcNow));
    }
    [Theory]
    [InlineData("http://updates.example.com/agent.msi")]
    [InlineData("https://evil.example.com/agent.msi")]
    [InlineData("https://updates.example.com/agent.exe")]
    [InlineData("https://updates.example.com:8443/agent.msi")]
    public void ForeignArtifactOriginsFail(string url)
    {
        using var rsa = RSA.Create(3072);
        Assert.Throws<InvalidDataException>(() => ReleaseInstaller.Verify(Sign(rsa, Manifest() with { ArtifactUrl = url }), rsa.ExportSubjectPublicKeyInfoPem(), Settings(), DateTimeOffset.UtcNow));
    }
    [Fact]
    public void ExpiredAndUnapprovedPackagesFail()
    {
        using var rsa = RSA.Create(3072);
        Assert.Throws<InvalidDataException>(() => ReleaseInstaller.Verify(Sign(rsa, Manifest() with { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1) }), rsa.ExportSubjectPublicKeyInfoPem(), Settings(), DateTimeOffset.UtcNow));
        Assert.Throws<InvalidDataException>(() => ReleaseInstaller.Verify(Sign(rsa, Manifest() with { PackageId = "unapproved" }), rsa.ExportSubjectPublicKeyInfoPem(), Settings(), DateTimeOffset.UtcNow));
    }
    [Fact]
    public void UnfinishedMutationSurvivesRestartWithoutReplay()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".db");
        var lease = new Lease(Guid.NewGuid(), "token", DateTimeOffset.UtcNow.AddMinutes(2), new("windows.install"), null, DateTimeOffset.UtcNow.AddHours(1));
        try
        {
            using (var first = new Journal(path)) { first.Begin(lease); first.ReserveSequence("one-control-agent", 3); }
            using var restarted = new Journal(path);
            Assert.Single(restarted.Pending()); Assert.Null(restarted.Pending()[0].Receipt);
            Assert.Throws<InvalidOperationException>(() => restarted.Begin(lease));
            Assert.Throws<InvalidDataException>(() => restarted.ReserveSequence("one-control-agent", 3));
            Assert.Throws<InvalidDataException>(() => restarted.ReserveSequence("one-control-agent", 2));
            restarted.ReserveSequence("one-control-agent", 4);
        }
        finally { foreach (var file in new[] { path, path + "-wal", path + "-shm" }) if (File.Exists(file)) File.Delete(file); }
    }
    [Fact]
    public async Task PipeProtocolRejectsOversizedMessages()
    {
        using var stream = new MemoryStream();
        await Assert.ThrowsAsync<InvalidDataException>(() => PipeProtocol.WriteAsync(stream, new string('x', 70000), CancellationToken.None));
        await stream.WriteAsync(BitConverter.GetBytes(70000)); stream.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() => PipeProtocol.ReadAsync<Command>(stream, CancellationToken.None));
    }
    [Fact]
    public void DeviceCredentialsRequireTls()
    {
        Assert.Throws<InvalidDataException>(() => AgentSettings.ValidateOrigin(new Uri("http://management.example.com")));
        Assert.Throws<InvalidDataException>(() => AgentSettings.ValidateOrigin(new Uri("https://user:pass@management.example.com")));
        Assert.Throws<InvalidDataException>(() => AgentSettings.ValidateOrigin(new Uri("https://management.example.com/other")));
    }
}
