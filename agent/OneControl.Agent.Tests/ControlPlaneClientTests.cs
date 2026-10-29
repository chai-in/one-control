using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using OneControl.Agent.Core;
using Xunit;
using Xunit.Abstractions;

namespace OneControl.Agent.Tests;

public sealed class ControlPlaneClientTests(ITestOutputHelper output)
{
    internal const string Unknown = "{\"error\":\"database_commit_unknown\",\"databaseOutcome\":\"unknown\",\"retryAllowed\":false,\"requestId\":\"fixture\"}";
    internal sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) { Calls++; return respond(request, ct); }
    }
    internal static HttpResponseMessage Reply(HttpStatusCode code, string body = Unknown) => new(code) { Content = new StringContent(body), ReasonPhrase = "REASON_CANARY" };
    internal static ControlPlaneClient Client(HttpMessageHandler handler, TimeSpan? deadline = null) => new(new Uri("https://management.example"), "fresh-fixture-token", handler, deadline ?? TimeSpan.FromSeconds(2));

    [Fact]
    public async Task ExactEnvelopeHasFixedExceptionAndOneRequest()
    {
        using var handler = new Handler((_, _) => Task.FromResult(Reply(HttpStatusCode.InternalServerError)));
        using var client = Client(handler);
        var error = await Assert.ThrowsAsync<DatabaseCommitUnknownException>(() => client.ClaimAsync(CancellationToken.None));
        Assert.Equal("unknown", error.DatabaseOutcome); Assert.False(error.RetryAllowed); Assert.Null(error.InnerException);
        Assert.DoesNotContain("fixture", error.ToString()); Assert.Equal(1, handler.Calls);
    }
    [Fact]
    public async Task InvalidSuccessfulLeaseHasFixedExceptionWithoutParserCause()
    {
        using var client = Client(new Handler((_, _) => Task.FromResult(Reply(HttpStatusCode.OK, "{\"lease\":{\"PROPERTY_CANARY\":true}}"))));
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => client.ClaimAsync(CancellationToken.None));
        Assert.Equal("Invalid control plane response", error.Message); Assert.Null(error.InnerException);
    }
    [Fact]
    public async Task RequestCorrelationBoundDoesNotBecomeAgentDiagnostics()
    {
        foreach (var length in new[] { 256, 257 })
        {
            var body = Unknown.Replace("fixture", new string('x', length), StringComparison.Ordinal);
            using var client = Client(new Handler((_, _) => Task.FromResult(Reply(HttpStatusCode.InternalServerError, body))));
            if (length == 256) await Assert.ThrowsAsync<DatabaseCommitUnknownException>(() => client.ClaimAsync(CancellationToken.None));
            else Assert.Equal(HttpStatusCode.InternalServerError, (await Assert.ThrowsAsync<HttpRequestException>(() => client.ClaimAsync(CancellationToken.None))).StatusCode);
        }
    }
    [Theory]
    [InlineData("{}")]
    [InlineData("{\"error\":\"database_commit_unknown\",\"databaseOutcome\":\"unknown\",\"retryAllowed\":false,\"requestId\":\"x\",\"requestId\":\"x\"}")]
    [InlineData("{\"error\":\"database_commit_unknown\",\"databaseOutcome\":\"unknown\",\"retryAllowed\":false,\"requestId\":\"x\",\"extra\":true}")]
    [InlineData("{\"error\":\"database_commit_unknown\",\"databaseOutcome\":\"unknown\",\"retryAllowed\":\"false\",\"requestId\":\"x\"}")]
    [InlineData("{\"error\":\"database_commit_unknown\",\"databaseOutcome\":\"unknown\",\"retryAllowed\":false,\"requestId\":\"\"}")]
    [InlineData("[]")]
    [InlineData("{\"error\":\"database_commit_unknown\",\"databaseOutcome\":\"unknown\",\"retryAllowed\":false,\"requestId\":\"x\"} {}")]
    [InlineData("{\"error\":\"database_commit_unknown\",\"databaseOutcome\":\"unknown\",\"retryAllowed\":false,\"requestId\":{}}")]
    [InlineData("SQL_BODY_CANARY")]
    public async Task InvalidEnvelopePreservesKnownStatusWithoutBodyOrCause(string body)
    {
        using var client = Client(new Handler((_, _) => Task.FromResult(Reply(HttpStatusCode.InternalServerError, body))));
        var error = await Assert.ThrowsAsync<HttpRequestException>(() => client.ClaimAsync(CancellationToken.None));
        Assert.Equal(HttpStatusCode.InternalServerError, error.StatusCode); Assert.Null(error.InnerException);
        Assert.Equal("Control plane request failed", error.Message);
    }
    [Theory]
    [InlineData(401)] [InlineData(404)] [InlineData(409)]
    public async Task OrdinaryStatusesRemainOrdinary(int status)
    {
        using var client = Client(new Handler((_, _) => Task.FromResult(Reply((HttpStatusCode)status))));
        var error = await Assert.ThrowsAsync<HttpRequestException>(() => client.SendAsync("v1/fixture", new { }, CancellationToken.None));
        Assert.Equal((HttpStatusCode)status, error.StatusCode); Assert.Null(error.InnerException);
    }
    [Theory]
    [InlineData(500, 4097)] [InlineData(200, 524289)]
    public async Task StreamingBoundsDisposeContent(int status, int count)
    {
        var stream = new GeneratedStream(count);
        using var client = Client(new Handler((_, _) => Task.FromResult(new HttpResponseMessage((HttpStatusCode)status) { Content = new StreamContent(stream) })));
        if (status == 500) await Assert.ThrowsAsync<HttpRequestException>(() => client.ClaimAsync(CancellationToken.None));
        else await Assert.ThrowsAsync<InvalidDataException>(() => client.ClaimAsync(CancellationToken.None));
        Assert.True(stream.Disposed); Assert.True(stream.BytesRead <= count);
    }
    [Fact]
    public async Task UnusedSuccessfulContentIsDisposedWithoutReading()
    {
        var stream = new GeneratedStream(100);
        using var client = Client(new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent) { Content = new StreamContent(stream) })));
        await client.SendAsync("v1/fixture", new { }, CancellationToken.None);
        Assert.Equal(0, stream.BytesRead); Assert.True(stream.Disposed);
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task StreamingBodyUsesTheSameDeadlineAndPreservesCallerCancellation(bool callerCancels)
    {
        var stream = new GeneratedStream(100, delayed: true);
        using var caller = new CancellationTokenSource();
        if (callerCancels) caller.CancelAfter(25);
        using var client = Client(new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StreamContent(stream) })), TimeSpan.FromMilliseconds(150));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ClaimAsync(caller.Token));
        Assert.True(stream.Disposed); Assert.Equal(0, stream.BytesRead);
    }
    [Fact]
    public void AllPostReplyShapesFitSuccessLimit()
    {
        var lease = new Lease(Guid.NewGuid(), new string('x', 256), DateTimeOffset.MaxValue,
            new("windows.install", Updates: Enumerable.Range(0, 100).Select(_ => new UpdateIdentity(Guid.NewGuid(), int.MaxValue)).ToArray()),
            new(new string('\u0001', 16384), new string('\u0001', 1024)), DateTimeOffset.MaxValue);
        Assert.InRange(JsonSerializer.SerializeToUtf8Bytes(new { lease }, Protocol.Json).Length, 1, 524288);
        Assert.InRange(JsonSerializer.SerializeToUtf8Bytes(new { deviceId = Guid.NewGuid(), credential = new string('x', 256) }, Protocol.Json).Length, 1, 524288);
    }
    [Theory]
    [InlineData("http://management.example", 1)] [InlineData("https://management.example/path", 1)]
    [InlineData("https://management.example", 0)] [InlineData("https://management.example", 26)]
    public void InternalSeamRetainsOriginAndDeadlineRules(string origin, int seconds)
    {
        using var handler = new Handler((_, _) => throw new InvalidOperationException());
        Assert.ThrowsAny<Exception>(() => new ControlPlaneClient(new Uri(origin), null, handler, TimeSpan.FromSeconds(seconds)));
    }
    [Fact]
    public async Task HeldResponseExposesShortDeadlineAndPreservesBothOriginalFailures()
    {
        var server = new TlsFixture("truncated", 500, holdResponse: true);
        var clientOutcome = new ClientOutcome();
        Task<Lease?>? pending = null;
        await clientOutcome.VerifyAsync(async () =>
        {
            using var client = new ControlPlaneClient(server.Origin, null, server.Handler(), TimeSpan.FromMilliseconds(350));
            server.Observe("client-started");
            pending = client.ClaimAsync(CancellationToken.None);
            await server.RequestReady.WaitAsync(TimeSpan.FromSeconds(3));
            var primary = await clientOutcome.ObserveAsync(pending);
            server.Observe(primary is OperationCanceledException ? "client-canceled" : "client-unexpected");
            Assert.IsAssignableFrom<OperationCanceledException>(primary);
            Assert.False(server.HeadersSent); Assert.False(server.HeadersReceived);
            server.ReleaseResponse(failHeaderWrite: true);
            await server.Terminal.WaitAsync(TimeSpan.FromSeconds(3));
            var failures = await server.CloseAsync();
            var serverFailure = Assert.Single(failures);
            Assert.IsType<ObjectDisposedException>(serverFailure);
            var masked = await Record.ExceptionAsync(async () => {
                try { ExceptionDispatchInfo.Capture(primary!).Throw(); }
                finally { await server.DisposeAsync(); }
            });
            Assert.Same(serverFailure, masked);
            var preserved = Assert.Throws<AggregateException>(() => ThrowFailures(primary, failures));
            Assert.Same(primary, preserved.InnerExceptions[0]); Assert.Same(serverFailure, preserved.InnerExceptions[1]);
            var rejected = new ClientOutcome();
            await rejected.VerifyAsync(async () => {
                await rejected.ObserveAsync(pending);
                Assert.IsType<HttpRequestException>(rejected.Original);
            });
            var rejectedFailures = Assert.Throws<AggregateException>(() => rejected.ThrowFailures(failures));
            Assert.Equal(3, rejectedFailures.InnerExceptions.Count);
            Assert.Same(primary, rejectedFailures.InnerExceptions[0]);
            Assert.Same(rejected.ContractFailure, rejectedFailures.InnerExceptions[1]);
            Assert.Same(serverFailure, rejectedFailures.InnerExceptions[2]);
            Assert.Same(failures, await server.CloseAsync());
            Assert.Same(serverFailure, await Record.ExceptionAsync(async () => await server.DisposeAsync()));
            Assert.True(server.Joined); Assert.True(server.KeyAbsent); Assert.Equal(1, server.CleanupCount);
        });
        int clientJoinFailures = 0;
        if (!clientOutcome.Observed && pending is not null)
        {
            var error = await clientOutcome.ObserveAsync(pending.WaitAsync(TimeSpan.FromSeconds(3)));
            if (error is not null) clientJoinFailures++;
            server.Observe(error is OperationCanceledException ? "client-canceled-after-milestone-failure" : "client-joined-after-milestone-failure");
        }
        var serverFailures = await server.CloseAsync();
        output.WriteLine(JsonSerializer.Serialize(new { control = "held-response-short-deadline", phases = server.Snapshot(), server.Joined, server.KeyAbsent, server.CleanupCount, serverFailures = serverFailures.Count, clientJoinFailures }));
        if (clientOutcome.ContractFailure is not null) clientOutcome.ThrowFailures(serverFailures);
    }
    [Theory]
    [InlineData("chunked", 500)] [InlineData("absent", 200)] [InlineData("truncated", 500)] [InlineData("stalled", 500)]
    public async Task OwnedTlsFramingIsBoundedAndJoined(string mode, int status)
    {
        var server = new TlsFixture(mode, status);
        var clientOutcome = new ClientOutcome();
        Task<Lease?>? pending = null;
        await clientOutcome.VerifyAsync(async () =>
        {
            using var client = new ControlPlaneClient(server.Origin, null, server.Handler(), TimeSpan.FromSeconds(5));
            server.Observe("client-started");
            using var caller = new CancellationTokenSource();
            pending = client.ClaimAsync(caller.Token);
            if (mode == "stalled")
            {
                await server.ClientHeaders.WaitAsync(TimeSpan.FromSeconds(3));
                server.Observe("caller-cancellation-armed"); caller.CancelAfter(150);
            }
            var outcome = await clientOutcome.ObserveAsync(pending);
            server.Observe(outcome switch {
                OperationCanceledException => "client-canceled",
                HttpRequestException => "client-http-error",
                InvalidDataException => "client-invalid-response",
                null => "client-succeeded",
                _ => "client-other-error"
            });
            if (mode == "stalled")
            {
                Assert.IsAssignableFrom<OperationCanceledException>(outcome); Assert.True(caller.IsCancellationRequested);
            }
            else if (status == 200) Assert.IsType<InvalidDataException>(outcome);
            else
            {
                var error = Assert.IsType<HttpRequestException>(outcome);
                Assert.Equal(HttpStatusCode.InternalServerError, error.StatusCode);
                Assert.Equal("Control plane request failed", error.Message); Assert.Null(error.InnerException);
            }
            Assert.True(server.HeadersSent); Assert.True(server.HeadersReceived);
            if (mode != "stalled")
            {
                await server.Terminal.WaitAsync(TimeSpan.FromSeconds(3)); Assert.True(server.BodySent);
                Assert.Equal(mode == "truncated" ? 3 : status == 200 ? 524289 : 4097, server.BodyPayloadBytes);
            }
        });
        if (clientOutcome.ContractFailure is not null) server.Observe("client-assertion-failed");
        var failures = new List<Exception>();
        int clientJoinFailures = 0;
        if (!clientOutcome.Observed && pending is not null)
        {
            var error = await clientOutcome.ObserveAsync(pending.WaitAsync(TimeSpan.FromSeconds(3)));
            if (error is not null) clientJoinFailures++;
            server.Observe(error is OperationCanceledException ? "client-canceled-after-milestone-failure" : "client-joined-after-milestone-failure");
        }
        var serverFailures = await server.CloseAsync(); failures.AddRange(serverFailures);
        output.WriteLine(JsonSerializer.Serialize(new { mode, phases = server.Snapshot(), server.BodyPayloadBytes, server.Joined, server.KeyAbsent, server.CleanupCount, serverFailures = serverFailures.Count, clientJoinFailures }));
        clientOutcome.ThrowFailures(failures);
        Assert.True(server.Joined); Assert.True(server.KeyAbsent); Assert.Equal(1, server.CleanupCount);
    }
    [Fact]
    public async Task RejectedClientContractRetainsOriginalObjectsAndStacks()
    {
        var original = Record.Exception((Action)(() => throw new OperationCanceledException("original-client")))!;
        var server = Record.Exception((Action)(() => throw new IOException("original-server")))!;
        var cleanup = Record.Exception((Action)(() => throw new InvalidOperationException("original-cleanup")))!;
        var serverStack = server.StackTrace;
        var cleanupStack = cleanup.StackTrace;
        var collector = new ClientOutcome();
        await collector.VerifyAsync(async () => {
            await collector.ObserveAsync(Task.FromException(original));
            Assert.IsType<HttpRequestException>(collector.Original);
        });
        var originalStack = original.StackTrace;
        var assertion = Assert.IsAssignableFrom<Exception>(collector.ContractFailure);
        var assertionStack = assertion.StackTrace;
        var aggregate = Assert.Throws<AggregateException>(() => collector.ThrowFailures([server, cleanup, original, server]));
        Assert.Equal(4, aggregate.InnerExceptions.Count);
        Assert.Same(original, aggregate.InnerExceptions[0]); Assert.Same(assertion, aggregate.InnerExceptions[1]);
        Assert.Same(server, aggregate.InnerExceptions[2]); Assert.Same(cleanup, aggregate.InnerExceptions[3]);
        Assert.Equal(originalStack, original.StackTrace); Assert.Equal(assertionStack, assertion.StackTrace);
        Assert.Equal(serverStack, server.StackTrace); Assert.Equal(cleanupStack, cleanup.StackTrace);
        var expected = new ClientOutcome();
        await expected.VerifyAsync(async () => {
            await expected.ObserveAsync(Task.FromException(original));
            Assert.IsAssignableFrom<OperationCanceledException>(expected.Original);
        });
        expected.ThrowFailures([]);
        var milestone = new ClientOutcome();
        await milestone.VerifyAsync(() => Task.FromException(assertion));
        Assert.False(milestone.Observed);
        await milestone.ObserveAsync(Task.FromException(original).WaitAsync(TimeSpan.FromSeconds(3)));
        var joined = Assert.Throws<AggregateException>(() => milestone.ThrowFailures([server]));
        Assert.Equal(3, joined.InnerExceptions.Count);
        Assert.Same(original, joined.InnerExceptions[0]); Assert.Same(assertion, joined.InnerExceptions[1]);
        Assert.Same(server, joined.InnerExceptions[2]); Assert.True(milestone.Observed);
        var single = Record.Exception(() => ThrowFailures(null, [server]));
        Assert.Same(server, single); Assert.StartsWith(serverStack!, server.StackTrace!);
    }
    private sealed class ClientOutcome
    {
        public Exception? Original { get; private set; }
        public Exception? ContractFailure { get; private set; }
        public bool Observed { get; private set; }
        public async Task<Exception?> ObserveAsync(Task pending)
        {
            Original = await Record.ExceptionAsync(() => pending); Observed = true; return Original;
        }
        public async Task VerifyAsync(Func<Task> contract)
        {
            try { await contract(); }
            catch (Exception error) { ContractFailure = error; }
        }
        public void ThrowFailures(IReadOnlyList<Exception> secondary)
        {
            var failures = new List<Exception>();
            if (ContractFailure is not null)
            {
                if (Original is not null) failures.Add(Original);
                failures.Add(ContractFailure);
            }
            failures.AddRange(secondary);
            ControlPlaneClientTests.ThrowFailures(null, failures);
        }
    }
    private static void ThrowFailures(Exception? primary, IReadOnlyList<Exception> secondary)
    {
        var failures = primary is null ? new List<Exception>() : [primary];
        foreach (var error in secondary)
            if (!failures.Contains(error, ReferenceEqualityComparer.Instance)) failures.Add(error);
        if (failures.Count == 1) ExceptionDispatchInfo.Capture(failures[0]).Throw();
        if (failures.Count > 1) throw new AggregateException(failures);
    }
    private sealed class GeneratedStream(int remaining, bool delayed = false) : Stream
    {
        public int BytesRead; public bool Disposed;
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) { var n = Math.Min(count, remaining); Array.Fill(buffer, (byte)'x', offset, n); remaining -= n; BytesRead += n; return n; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) { if (delayed) await Task.Delay(1000, ct); ct.ThrowIfCancellationRequested(); var n = Math.Min(buffer.Length, remaining); buffer.Span[..n].Fill((byte)'x'); remaining -= n; BytesRead += n; return n; }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
        public override void Flush() => throw new NotSupportedException(); public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException(); public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
    private sealed class TlsFixture : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop = new(TimeSpan.FromSeconds(10));
        private readonly X509Certificate2 certificate;
        private readonly CngKey? ownedKey;
        private readonly string? keyName;
        private readonly Task server;
        private TcpClient? socket;
        private readonly Stopwatch clock = Stopwatch.StartNew();
        private readonly List<(string Phase, double Milliseconds)> phases = [];
        private readonly TaskCompletionSource requestReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource clientHeaders = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource responseGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource terminal = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private Task<IReadOnlyList<Exception>>? closeTask;
        private bool failHeaderWrite;
        public int CleanupCount { get; private set; }
        public bool KeyAbsent { get; private set; }
        public bool BodySent { get; private set; }
        public int BodyPayloadBytes { get; private set; }
        public Task RequestReady => requestReady.Task;
        public Task ClientHeaders => clientHeaders.Task;
        public Task Terminal => terminal.Task;
        public void Observe(string phase) { lock (phases) phases.Add((phase, clock.Elapsed.TotalMilliseconds)); }
        public object[] Snapshot() { lock (phases) return phases.Select(p => (object)new { phase = p.Phase, milliseconds = p.Milliseconds }).ToArray(); }
        public void ReleaseResponse(bool failHeaderWrite = false) { this.failHeaderWrite = failHeaderWrite; responseGate.TrySetResult(); }
        public bool Joined { get; private set; }
        public bool HeadersSent { get; private set; }
        public bool HeadersReceived { get; private set; }
        public Uri Origin { get; }
        public TlsFixture(string mode, int status, bool holdResponse = false)
        {
            try {
                using var key = OperatingSystem.IsWindows() ? CreateWindowsKey(out ownedKey, out keyName) : RSA.Create(2048);
                var request = new CertificateRequest("CN=owned-fixture", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(10));
                listener.Start(); Origin = new Uri($"https://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
                if (!holdResponse) responseGate.SetResult();
                server = RunAsync(mode, status);
            } catch (Exception primary) {
                var cleanup = new List<Exception>();
                try { listener.Stop(); } catch (Exception error) { cleanup.Add(error); }
                try { certificate?.Dispose(); } catch (Exception error) { cleanup.Add(error); }
                if (ownedKey is not null)
                {
                    try { ownedKey.Delete(); } catch (Exception error) { cleanup.Add(error); }
                    try { ownedKey.Dispose(); } catch (Exception error) { cleanup.Add(error); }
                    try { Assert.False(CngKey.Exists(keyName!, CngProvider.MicrosoftSoftwareKeyStorageProvider)); }
                    catch (Exception error) { cleanup.Add(error); }
                }
                try { stop.Dispose(); } catch (Exception error) { cleanup.Add(error); }
                ThrowFailures(primary, cleanup); throw;
            }
        }
        private static RSA CreateWindowsKey(out CngKey owned, out string name)
        {
            name = "OneControl.HttpFixture." + Guid.NewGuid().ToString("N");
            Assert.False(CngKey.Exists(name, CngProvider.MicrosoftSoftwareKeyStorageProvider));
            owned = CngKey.Create(CngAlgorithm.Rsa, name, new CngKeyCreationParameters {
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                Parameters = { new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None) }
            });
            return new RSACng(owned);
        }
        public HttpMessageHandler Handler() => new HeaderObserver(() => { HeadersReceived = true; Observe("client-headers-received"); clientHeaders.TrySetResult(); }, new HttpClientHandler { AllowAutoRedirect = false,
            ServerCertificateCustomValidationCallback = (_, presented, _, _) => presented is not null && presented.RawData.AsSpan().SequenceEqual(certificate.RawData) });
        private sealed class HeaderObserver(Action observed, HttpMessageHandler handler) : DelegatingHandler(handler)
        {
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            {
                var response = await base.SendAsync(request, ct); observed(); return response;
            }
        }
        private async Task RunAsync(string mode, int status)
        {
            SslStream? tls = null;
            Exception? primary = null;
            var cleanup = new List<Exception>();
            try
            {
                socket = await listener.AcceptTcpClientAsync(stop.Token); Observe("accepted");
                tls = new SslStream(socket.GetStream());
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, stop.Token); Observe("tls-authenticated");
                var head = new List<byte>(); var one = new byte[1];
                while (head.Count < 16384 && await tls.ReadAsync(one, stop.Token) > 0) { head.Add(one[0]); if (head.Count >= 4 && head.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break; }
                if (head.Count < 4 || !head.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) throw new InvalidDataException("Fixture request header incomplete");
                Observe("request-header-complete"); requestReady.TrySetResult();
                await responseGate.Task.WaitAsync(stop.Token);
                if (failHeaderWrite) tls.Dispose();
                Observe("response-header-attempted");
                var framing = mode == "chunked" ? "Transfer-Encoding: chunked\r\n" : mode == "truncated" ? "Content-Length: 1000\r\n" : mode == "stalled" ? "Content-Length: 100\r\n" : "";
                await tls.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {status} Fixture\r\n{framing}Connection: close\r\n\r\n"), stop.Token);
                await tls.FlushAsync(stop.Token);
                HeadersSent = true; Observe("response-header-complete");
                if (mode == "stalled") { Observe("body-stalled"); await Task.Delay(Timeout.Infinite, stop.Token); }
                var length = mode == "truncated" ? 3 : status == 200 ? 524289 : 4097;
                var payload = new string('x', length);
                if (mode == "chunked") payload = $"{length:x}\r\n{payload}\r\n0\r\n\r\n";
                Observe("body-attempted");
                await tls.WriteAsync(Encoding.ASCII.GetBytes(payload), stop.Token); await tls.FlushAsync(stop.Token);
                BodyPayloadBytes = length; BodySent = true; Observe("body-complete");
            }
            catch (OperationCanceledException error) when (mode == "stalled" && HeadersSent && stop.IsCancellationRequested && error.CancellationToken == stop.Token) { Observe("server-teardown-canceled"); }
            catch (Exception error) { primary = error; }
            finally
            {
                try { if (tls is not null) await tls.DisposeAsync(); }
                catch (Exception error) { cleanup.Add(error); Observe("tls-close-failed"); }
                Observe("server-terminal"); terminal.TrySetResult();
            }
            ThrowFailures(primary, cleanup);
        }
        public Task<IReadOnlyList<Exception>> CloseAsync() => closeTask ??= CloseCoreAsync();
        public async ValueTask DisposeAsync() => ThrowFailures(null, await CloseAsync());
        private async Task<IReadOnlyList<Exception>> CloseCoreAsync()
        {
            CleanupCount++; Observe("teardown-requested");
            var failures = new List<Exception>();
            try { await stop.CancelAsync(); } catch (Exception error) { failures.Add(error); }
            try { listener.Stop(); } catch (Exception error) { failures.Add(error); }
            try { socket?.Dispose(); } catch (Exception error) { failures.Add(error); }
            try { await server.WaitAsync(TimeSpan.FromSeconds(3)); }
            catch (Exception error) { failures.Add(error); }
            Joined = server.IsCompleted;
            if (Joined) Observe("server-joined");
            try { certificate.Dispose(); } catch (Exception error) { failures.Add(error); }
            if (ownedKey is not null)
            {
                try { ownedKey.Delete(); } catch (Exception error) { failures.Add(error); }
                try { ownedKey.Dispose(); } catch (Exception error) { failures.Add(error); }
                try { KeyAbsent = !CngKey.Exists(keyName!, CngProvider.MicrosoftSoftwareKeyStorageProvider); Assert.True(KeyAbsent); }
                catch (Exception error) { failures.Add(error); }
            }
            else KeyAbsent = true;
            try { stop.Dispose(); } catch (Exception error) { failures.Add(error); }
            Observe("cleanup-terminal");
            return failures;
        }
    }
}
