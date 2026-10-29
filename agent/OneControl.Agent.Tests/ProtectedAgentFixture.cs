using System.Security.AccessControl;
using System.Security.Cryptography;
using OneControl.Agent.Core;

namespace OneControl.Agent.Tests;

internal sealed class ProtectedAgentFixture : IDisposable
{
    private readonly string root = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OneControl.Agent.HttpFixtures");
    public string Path { get; }
    public string SettingsPath => System.IO.Path.Combine(Path, "agent.json");
    public AgentSettings Settings { get; }
    public ProtectedAgentFixture()
    {
        var acl = new DirectorySecurity(); acl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        new DirectoryInfo(root).Create(acl); ProtectedPaths.ValidateDirectory(root, privateLeaf: true);
        Path = System.IO.Path.Combine(root, Guid.NewGuid().ToString("N")); new DirectoryInfo(Path).Create(acl);
        var broker = System.IO.Path.Combine(Path, "never-run.exe"); var key = System.IO.Path.Combine(Path, "public-key.pem");
        File.WriteAllText(broker, "non-executable fixture"); File.WriteAllText(key, "non-key fixture");
        Settings = new(new Uri("https://management.example"), Guid.NewGuid(), AgentSettings.ProtectCredential(Convert.ToHexString(RandomNumberGenerator.GetBytes(32))),
            [], [], key, broker, CredentialCreatedAt: DateTimeOffset.UtcNow);
        AgentSettings.SaveAsync(SettingsPath, Settings, CancellationToken.None).GetAwaiter().GetResult();
    }
    public static Lease Lease() => new(Guid.NewGuid(), Convert.ToHexString(RandomNumberGenerator.GetBytes(32)), DateTimeOffset.UtcNow.AddMinutes(5),
        new("package.install"), null, DateTimeOffset.UtcNow.AddHours(1));
    public void Dispose()
    {
        var resolved = System.IO.Path.GetFullPath(Path);
        if (!resolved.StartsWith(System.IO.Path.GetFullPath(root) + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Fixture cleanup escaped its root");
        ProtectedPaths.ValidateDirectory(resolved, privateLeaf: true); Directory.Delete(resolved, recursive: true);
    }
}
