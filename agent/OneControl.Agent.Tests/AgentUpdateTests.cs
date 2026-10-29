using System.Security.AccessControl;
using OneControl.Agent.Core;
using Xunit;

namespace OneControl.Agent.Tests;

public sealed class AgentUpdateTests
{
    [Fact]
    public void KnownCatalogueNoOpDoesNotClaimARealApplicationUpgrade()
    {
        var receipt = UserPackageCommand.Receipt(new("store.upgrade", "9WZDNCRFHVN5"), unchecked((int)0x8A15002B));
        Assert.Equal("succeeded", receipt.State);
        Assert.Equal("no_applicable_update", receipt.Result["outcome"]);
        Assert.Equal(false, receipt.Result["changed"]);
        Assert.Equal("indeterminate", UserPackageCommand.Receipt(new("winget.upgrade", "Microsoft.NuGet", "7.0.0"), unchecked((int)0x8A150011)).State);
    }

    [RequiresAdministratorFact]
    public async Task SuccessfulHandoffActivatesOnceAndPersistsTerminalReceipt()
    {
        using var fixture = new Fixture();
        var platform = new FakePlatform(fixture.Store);
        var runner = new AgentUpdateRunner(fixture.Store, platform);
        var result = await runner.RunAsync(fixture.Plan, CancellationToken.None);
        Assert.Equal("succeeded", result.Receipt?.State);
        Assert.Equal(AgentUpdatePhase.Reporting, fixture.Store.Read()?.Phase);
        await runner.RunAsync(result, CancellationToken.None);
        Assert.Equal(1, platform.Installs);
        Assert.Equal(1, platform.Activations);
        Assert.Equal(0, platform.Rollbacks);
        Assert.True(fixture.Store.Owns(fixture.Plan.Lease.Id));
        fixture.Store.Save(result with { Phase = AgentUpdatePhase.Completed });
        Assert.False(fixture.Store.Owns(fixture.Plan.Lease.Id));
    }

    [RequiresAdministratorFact]
    public async Task RestartDuringInstallerQuarantinesWithoutRepeatingAnyMutation()
    {
        using var fixture = new Fixture();
        var platform = new FakePlatform(fixture.Store);
        var result = await new AgentUpdateRunner(fixture.Store, platform).RunAsync(fixture.Plan with { Phase = AgentUpdatePhase.Installing }, CancellationToken.None);
        Assert.Equal("indeterminate", result.Receipt?.State);
        Assert.Equal(0, platform.Installs);
        Assert.Equal(0, platform.Activations);
        Assert.Equal(0, platform.Rollbacks);
    }

    [RequiresAdministratorFact]
    public async Task FailureAfterDurableInstallerIntentIsNotMisclassifiedAsSafeToRetry()
    {
        using var fixture = new Fixture();
        var platform = new FakePlatform(fixture.Store) { FailDuringInstall = true };
        var result = await new AgentUpdateRunner(fixture.Store, platform).RunAsync(fixture.Plan, CancellationToken.None);
        Assert.Equal("indeterminate", result.Receipt?.State);
        await new AgentUpdateRunner(fixture.Store, platform).RunAsync(result, CancellationToken.None);
        Assert.Equal(1, platform.Installs);
        Assert.Equal(0, platform.Activations);
    }

    [RequiresAdministratorTheory]
    [InlineData(AgentUpdatePhase.Activating)]
    [InlineData(AgentUpdatePhase.Verifying)]
    [InlineData(AgentUpdatePhase.RollingBack)]
    public async Task RestartAfterActivationRestoresKnownGoodWithoutReinstalling(AgentUpdatePhase phase)
    {
        using var fixture = new Fixture();
        var platform = new FakePlatform(fixture.Store);
        var result = await new AgentUpdateRunner(fixture.Store, platform).RunAsync(fixture.Plan with { Phase = phase }, CancellationToken.None);
        Assert.Equal("failed", result.Receipt?.State);
        Assert.Equal(true, result.Receipt?.Result["rollbackVerified"]);
        Assert.Equal(0, platform.Installs);
        Assert.Equal(0, platform.Activations);
        Assert.Equal(1, platform.Rollbacks);
    }

    [RequiresAdministratorTheory]
    [InlineData(true, "failed")]
    [InlineData(false, "indeterminate")]
    public async Task UnhealthyCandidateRequiresVerifiedRollbackOrQuarantine(bool canRecover, string expected)
    {
        using var fixture = new Fixture();
        var platform = new FakePlatform(fixture.Store) { Healthy = false, CanRecover = canRecover };
        var result = await new AgentUpdateRunner(fixture.Store, platform).RunAsync(fixture.Plan, CancellationToken.None);
        Assert.Equal(expected, result.Receipt?.State);
        Assert.Equal(canRecover, result.Receipt?.Result["rollbackVerified"]);
        Assert.Equal(1, platform.Rollbacks);
    }

    [RequiresAdministratorFact]
    public async Task ExpiredWindowNeverStartsTheInstaller()
    {
        using var fixture = new Fixture();
        var platform = new FakePlatform(fixture.Store);
        var result = await new AgentUpdateRunner(fixture.Store, platform).RunAsync(fixture.Plan with { Lease = fixture.Plan.Lease with { EndsAt = DateTimeOffset.UtcNow.AddMinutes(-1) } }, CancellationToken.None);
        Assert.Equal("failed", result.Receipt?.State);
        Assert.Equal(0, platform.Installs);
    }

    [RequiresAdministratorFact]
    public async Task CancelledLeaseCannotPreventLocalRestorationAfterActivation()
    {
        using var fixture = new Fixture();
        var platform = new FakePlatform(fixture.Store);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var result = await new AgentUpdateRunner(fixture.Store, platform).RunAsync(
            fixture.Plan with { Phase = AgentUpdatePhase.Verifying }, cancelled.Token);
        Assert.Equal("failed", result.Receipt?.State);
        Assert.Equal(true, result.Receipt?.Result["rollbackVerified"]);
        Assert.Equal(1, platform.Rollbacks);
        Assert.Equal(0, platform.Installs);
    }

    [Theory]
    [InlineData("device")]
    [InlineData("process")]
    [InlineData("path")]
    [InlineData("version")]
    [InlineData("time")]
    public void HealthCannotBeSatisfiedByAnotherProcessOrStaleAgent(string mismatch)
    {
        var id = Guid.NewGuid(); var since = DateTimeOffset.UtcNow;
        var health = new AgentHealth(id, 123, @"C:\trusted\agent.exe", "0.1.1.0", since.AddSeconds(1));
        Assert.True(AgentHealth.Matches(health, id, 123, health.Executable, new Version(0, 1, 1, 0), since));
        health = mismatch switch
        {
            "device" => health with { DeviceId = Guid.NewGuid() },
            "process" => health with { ProcessId = 456 },
            "path" => health with { Executable = @"C:\other\agent.exe" },
            "version" => health with { Version = "0.1.0.0" },
            _ => health with { AuthenticatedAt = since.AddSeconds(-1) }
        };
        Assert.False(AgentHealth.Matches(health, id, 123, @"C:\trusted\agent.exe", new Version(0, 1, 1, 0), since));
    }

    private sealed class FakePlatform(AgentUpdateStore store) : IAgentUpdatePlatform
    {
        public int Installs, Activations, Rollbacks;
        public bool FailDuringInstall, Healthy = true, CanRecover = true;
        public Task<AgentUpdatePlan> InstallAsync(AgentUpdatePlan plan, CancellationToken ct)
        {
            Installs++;
            store.Save(plan with { Phase = AgentUpdatePhase.Installing });
            if (FailDuringInstall) throw new IOException("Lost installer outcome");
            return Task.FromResult(plan with { Phase = AgentUpdatePhase.Ready });
        }
        public Task ActivateAsync(AgentUpdatePlan plan, CancellationToken ct) { Activations++; return Task.CompletedTask; }
        public Task<bool> HealthyAsync(AgentUpdatePlan plan, CancellationToken ct) => Task.FromResult(Healthy);
        public Task<bool> RollbackAsync(AgentUpdatePlan plan, CancellationToken ct) { ct.ThrowIfCancellationRequested(); Rollbacks++; return Task.FromResult(CanRecover); }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OneControl.Agent.UpdateFixtures");
        private readonly string path;
        public AgentUpdateStore Store { get; }
        public AgentUpdatePlan Plan { get; }
        public Fixture()
        {
            var acl = new DirectorySecurity(); acl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
            new DirectoryInfo(root).Create(acl); ProtectedPaths.ValidateDirectory(root, privateLeaf: true);
            path = Path.Combine(root, Guid.NewGuid().ToString("N")); new DirectoryInfo(path).Create(acl);
            Store = new(path);
            Plan = new(new(Guid.NewGuid(), "test-lease", DateTimeOffset.UtcNow.AddMinutes(2), new("package.install"), null, DateTimeOffset.UtcNow.AddHours(1)), DateTimeOffset.UtcNow);
            Store.Save(Plan);
        }
        public void Dispose()
        {
            var resolved = Path.GetFullPath(path);
            if (!resolved.StartsWith(Path.GetFullPath(root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Fixture cleanup escaped its root");
            ProtectedPaths.ValidateDirectory(resolved, privateLeaf: true);
            Directory.Delete(resolved, recursive: true);
        }
    }
}
