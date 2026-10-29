using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using OneControl.Agent.Core;
using OneControl.Agent.Service;
using Xunit;

namespace OneControl.Agent.Tests;

public sealed class HttpCallerCustodyTests
{
    [RequiresAdministratorFact]
    public async Task ActualWorkerUnknownClaimNeverBeginsExecution()
    {
        using var fixture = new ProtectedAgentFixture();
        var logger = new FailureLogger(); var calls = new List<string>();
        using var worker = new AgentWorker(logger, fixture.Path, _ => ControlPlaneClientTests.Client(new ControlPlaneClientTests.Handler((request, _) => {
            calls.Add(request.RequestUri!.AbsolutePath);
            return Task.FromResult(ControlPlaneClientTests.Reply(request.RequestUri.AbsolutePath.EndsWith("claim", StringComparison.Ordinal) ? HttpStatusCode.InternalServerError : HttpStatusCode.NoContent));
        })));
        await RunUntilAsync(worker, logger.Failure.Task);
        Assert.Equal(nameof(DatabaseCommitUnknownException), logger.ErrorType);
        Assert.Equal(["/v1/agent/heartbeat", "/v1/agent/claim"], calls);
        using var journal = new Journal(System.IO.Path.Combine(fixture.Path, "journal.db")); Assert.Empty(journal.Pending());
        Assert.Null(new AgentUpdateStore(fixture.Path).Read());
    }
    [RequiresAdministratorFact]
    public async Task ActualWorkerRetainsReceiptThenReportsTheSameIdentityWithoutExecution()
    {
        using var fixture = new ProtectedAgentFixture(); var lease = ProtectedAgentFixture.Lease();
        var receipt = new JobReceipt("indeterminate", new() { ["reason"] = "fixture" });
        using (var journal = new Journal(System.IO.Path.Combine(fixture.Path, "journal.db"))) { journal.Begin(lease); journal.Finish(lease.Id, receipt); }
        var bodies = new List<string>();
        var logger = new FailureLogger();
        using (var worker = new AgentWorker(logger, fixture.Path, _ => ControlPlaneClientTests.Client(new ControlPlaneClientTests.Handler(async (request, ct) => {
            bodies.Add(await request.Content!.ReadAsStringAsync(ct)); return ControlPlaneClientTests.Reply(HttpStatusCode.InternalServerError);
        })))) {
            await RunUntilAsync(worker, logger.Failure.Task);
        }
        Assert.Equal(nameof(DatabaseCommitUnknownException), logger.ErrorType);
        using (var journal = new Journal(System.IO.Path.Combine(fixture.Path, "journal.db"))) {
            var pending = Assert.Single(journal.Pending()); Assert.Equal(lease.Id, pending.Item1.Id); Assert.Equal(lease.LeaseToken, pending.Item1.LeaseToken);
            Assert.Equal(JsonSerializer.Serialize(receipt, Protocol.Json), JsonSerializer.Serialize(pending.Item2, Protocol.Json));
        }
        var claim = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using (var worker = new AgentWorker(new FailureLogger(), fixture.Path, _ => ControlPlaneClientTests.Client(new ControlPlaneClientTests.Handler(async (request, ct) => {
            if (request.RequestUri!.AbsolutePath.EndsWith("/report", StringComparison.Ordinal)) { bodies.Add(await request.Content!.ReadAsStringAsync(ct)); return ControlPlaneClientTests.Reply(HttpStatusCode.NoContent); }
            if (request.RequestUri.AbsolutePath.EndsWith("/claim", StringComparison.Ordinal)) { claim.SetResult(); return ControlPlaneClientTests.Reply(HttpStatusCode.OK, "{\"lease\":null}"); }
            return ControlPlaneClientTests.Reply(HttpStatusCode.NoContent);
        })))) {
            await RunUntilAsync(worker, claim.Task);
        }
        Assert.Equal(2, bodies.Count); Assert.Equal(bodies[0], bodies[1]);
        using var finalJournal = new Journal(System.IO.Path.Combine(fixture.Path, "journal.db")); Assert.Empty(finalJournal.Pending());
    }
    [RequiresAdministratorFact]
    public async Task ActualRecoveryReportingRetainsReceiptUntilTheSameReportSucceeds()
    {
        using var fixture = new ProtectedAgentFixture(); var lease = ProtectedAgentFixture.Lease(); var store = new AgentUpdateStore(fixture.Path);
        var receipt = new JobReceipt("indeterminate", new() { ["reason"] = "fixture" });
        using (var journal = new Journal(System.IO.Path.Combine(fixture.Path, "journal.db"))) journal.Begin(lease);
        store.Save(new(lease, DateTimeOffset.UtcNow, AgentUpdatePhase.Reporting, Receipt: receipt));
        var bodies = new List<string>(); var success = false;
        ControlPlaneClient Factory(AgentSettings _) => ControlPlaneClientTests.Client(new ControlPlaneClientTests.Handler(async (request, ct) => {
            Assert.EndsWith($"/{lease.Id}/report", request.RequestUri!.AbsolutePath); bodies.Add(await request.Content!.ReadAsStringAsync(ct));
            return ControlPlaneClientTests.Reply(success ? HttpStatusCode.NoContent : HttpStatusCode.InternalServerError);
        }));
        await Assert.ThrowsAsync<DatabaseCommitUnknownException>(() => AgentRecovery.RunOnceAsync(fixture.Path, Factory, CancellationToken.None));
        Assert.Equal(AgentUpdatePhase.Reporting, store.Read()!.Phase);
        using (var journal = new Journal(System.IO.Path.Combine(fixture.Path, "journal.db"))) Assert.Equal(lease.Id, Assert.Single(journal.Pending()).Item1.Id);
        success = true; await AgentRecovery.RunOnceAsync(fixture.Path, Factory, CancellationToken.None);
        Assert.Equal(AgentUpdatePhase.Completed, store.Read()!.Phase); Assert.Equal(bodies[0], bodies[1]);
        using var finalJournal = new Journal(System.IO.Path.Combine(fixture.Path, "journal.db")); Assert.Empty(finalJournal.Pending());
    }
    [RequiresAdministratorTheory]
    [InlineData(AgentUpdatePhase.Requested)] [InlineData(AgentUpdatePhase.Ready)]
    public async Task ActualRecoveryInitialUnknownRenewalPreventsForwardWork(AgentUpdatePhase phase)
    {
        using var fixture = new ProtectedAgentFixture(); var store = new AgentUpdateStore(fixture.Path); var lease = ProtectedAgentFixture.Lease(); store.Save(new(lease, DateTimeOffset.UtcNow, phase));
        var calls = new List<string>();
        await Assert.ThrowsAsync<DatabaseCommitUnknownException>(() => AgentRecovery.RunOnceAsync(fixture.Path, _ => ControlPlaneClientTests.Client(new ControlPlaneClientTests.Handler((request, _) => {
            calls.Add(request.RequestUri!.AbsolutePath); return Task.FromResult(ControlPlaneClientTests.Reply(HttpStatusCode.InternalServerError));
        })), CancellationToken.None));
        Assert.Equal(phase, store.Read()!.Phase); Assert.Equal([$"/v1/agent/jobs/{lease.Id}/renew"], calls);
    }
    [RequiresAdministratorTheory]
    [InlineData(AgentUpdatePhase.Installing)] [InlineData(AgentUpdatePhase.Activating)] [InlineData(AgentUpdatePhase.Verifying)] [InlineData(AgentUpdatePhase.RollingBack)]
    public async Task ActualRecoveryOfflinePhasesReachReportingWithoutRenewalOrInstaller(AgentUpdatePhase phase)
    {
        using var fixture = new ProtectedAgentFixture(); var store = new AgentUpdateStore(fixture.Path); var lease = ProtectedAgentFixture.Lease(); store.Save(new(lease, DateTimeOffset.UtcNow, phase));
        var calls = new List<string>();
        await Assert.ThrowsAsync<DatabaseCommitUnknownException>(() => AgentRecovery.RunOnceAsync(fixture.Path, _ => ControlPlaneClientTests.Client(new ControlPlaneClientTests.Handler((request, _) => {
            calls.Add(request.RequestUri!.AbsolutePath); return Task.FromResult(ControlPlaneClientTests.Reply(HttpStatusCode.InternalServerError));
        })), CancellationToken.None));
        Assert.Equal(AgentUpdatePhase.Reporting, store.Read()!.Phase); Assert.Equal([$"/v1/agent/jobs/{lease.Id}/report"], calls);
    }
    [RequiresAdministratorTheory]
    [InlineData(1)] [InlineData(2)] [InlineData(3)]
    public async Task ActualRotationRetainsChosenCredentialAcrossEveryUnknownHttpStage(int failAt)
    {
        using var fixture = new ProtectedAgentFixture(); await AgentSettings.SaveAsync(fixture.SettingsPath, fixture.Settings with { CredentialCreatedAt = DateTimeOffset.UtcNow.AddDays(-31) }, CancellationToken.None);
        var stage = 0;
        var transport = new CredentialRotation.HttpCredentialTransport(_ => ControlPlaneClientTests.Client(new ControlPlaneClientTests.Handler((_, _) => {
            stage++; return Task.FromResult(ControlPlaneClientTests.Reply(stage == failAt ? HttpStatusCode.InternalServerError : stage == 1 ? HttpStatusCode.Unauthorized : HttpStatusCode.NoContent));
        })));
        await Assert.ThrowsAsync<DatabaseCommitUnknownException>(() => CredentialRotation.RecoverOrRotateAsync(fixture.SettingsPath, transport, CancellationToken.None));
        var pending = AgentSettings.Load(fixture.SettingsPath); Assert.NotNull(pending.PendingProtectedCredential); Assert.Equal(fixture.Settings.ProtectedCredential, pending.ProtectedCredential);
        var expected = (pending with { ProtectedCredential = pending.PendingProtectedCredential! }).Credential;
        var recovered = await CredentialRotation.RecoverOrRotateAsync(fixture.SettingsPath,
            new CredentialRotation.HttpCredentialTransport(settings => {
                Assert.Equal(expected, settings.Credential); return ControlPlaneClientTests.Client(new ControlPlaneClientTests.Handler((_, _) => Task.FromResult(ControlPlaneClientTests.Reply(HttpStatusCode.NoContent))));
            }), CancellationToken.None);
        Assert.Equal(expected, recovered.Credential); Assert.Null(recovered.PendingProtectedCredential);
    }
    private static async Task RunUntilAsync(AgentWorker worker, Task observation)
    {
        try { await worker.StartAsync(CancellationToken.None); await observation.WaitAsync(TimeSpan.FromSeconds(10)); }
        finally {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await worker.StopAsync(deadline.Token);
            if (worker.ExecuteTask is { } execution) await execution.WaitAsync(deadline.Token);
        }
    }
    private sealed class FailureLogger : ILogger<AgentWorker>
    {
        public TaskCompletionSource Failure { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public string? ErrorType;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (state is IEnumerable<KeyValuePair<string, object?>> values && values.FirstOrDefault(pair => pair.Key == "ErrorType").Value is string type) {
                ErrorType = type; Failure.TrySetResult();
            }
        }
    }
}
