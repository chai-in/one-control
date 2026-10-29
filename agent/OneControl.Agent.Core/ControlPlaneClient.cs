using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net;
using System.Text.Json;

namespace OneControl.Agent.Core;

public sealed class ControlPlaneClient : IDisposable
{
    private readonly HttpClient client;
    private readonly TimeSpan deadline;
    public ControlPlaneClient(Uri origin, string? credential) : this(origin, credential,
        new HttpClientHandler { AllowAutoRedirect = false }, TimeSpan.FromSeconds(25)) { }
    internal ControlPlaneClient(Uri origin, string? credential, HttpMessageHandler ownedHandler, TimeSpan deadline)
    {
        AgentSettings.ValidateOrigin(origin);
        if (deadline <= TimeSpan.Zero || deadline > TimeSpan.FromSeconds(25)) throw new ArgumentOutOfRangeException(nameof(deadline));
        this.deadline = deadline;
        client = new HttpClient(ownedHandler)
        { BaseAddress = origin, Timeout = TimeSpan.FromSeconds(25) };
        if (credential is not null) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", credential);
    }
    public async Task<T> PostAsync<T>(string path, object body, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(deadline);
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body, options: Protocol.Json) };
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        await EnsureSuccessAsync(response, timeout.Token);
        try
        {
            var bytes = await ReadBoundedAsync(response.Content, 524_288, timeout.Token);
            return JsonSerializer.Deserialize<T>(bytes, Protocol.Json) ?? throw new InvalidDataException();
        }
        catch (Exception)
        {
            timeout.Token.ThrowIfCancellationRequested();
            throw new InvalidDataException("Invalid control plane response");
        }
    }
    public async Task SendAsync(string path, object body, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(deadline);
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(body, options: Protocol.Json) };
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        await EnsureSuccessAsync(response, timeout.Token);
    }
    private static async Task<byte[]> ReadBoundedAsync(HttpContent content, long limit, CancellationToken ct)
    {
        if (content.Headers.ContentLength > limit) throw new InvalidDataException();
        await content.LoadIntoBufferAsync(limit, ct);
        return await content.ReadAsByteArrayAsync(ct);
    }
    private static async Task EnsureSuccessAsync(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode) return;
        if (response.StatusCode == HttpStatusCode.InternalServerError)
        {
            bool recognized;
            try { recognized = IsCommitUnknown(await ReadBoundedAsync(response.Content, 4096, ct)); }
            catch (Exception) { ct.ThrowIfCancellationRequested(); recognized = false; }
            ct.ThrowIfCancellationRequested();
            if (recognized) throw new DatabaseCommitUnknownException();
        }
        throw new HttpRequestException("Control plane request failed", null, response.StatusCode);
    }
    private static bool IsCommitUnknown(ReadOnlySpan<byte> bytes)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 16 });
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) return false;
        var fields = new HashSet<string>(StringComparer.Ordinal);
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if (reader.TokenType != JsonTokenType.PropertyName) return false;
            var field = reader.GetString()!;
            if (!fields.Add(field) || !reader.Read()) return false;
            var valid = field switch
            {
                "error" => reader.TokenType == JsonTokenType.String && reader.GetString() == "database_commit_unknown",
                "databaseOutcome" => reader.TokenType == JsonTokenType.String && reader.GetString() == "unknown",
                "retryAllowed" => reader.TokenType == JsonTokenType.False,
                "requestId" => reader.TokenType == JsonTokenType.String && reader.GetString() is { Length: > 0 and <= 256 },
                _ => false
            };
            if (!valid) return false;
        }
        return reader.TokenType == JsonTokenType.EndObject && fields.Count == 4 && !reader.Read();
    }
    public async Task<Lease?> ClaimAsync(CancellationToken ct)
    {
        var result = await PostAsync<JsonElement>("v1/agent/claim", new { }, ct);
        try
        {
            return result.GetProperty("lease").ValueKind == JsonValueKind.Null ? null
                : result.GetProperty("lease").Deserialize<Lease>(Protocol.Json);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException)
        { throw new InvalidDataException("Invalid control plane response"); }
    }
    public Task ReportAsync(Lease lease, JobReceipt receipt, CancellationToken ct) =>
        SendAsync($"v1/agent/jobs/{lease.Id}/report", new { lease.LeaseToken, receipt.State, receipt.Result }, ct);
    public Task RenewAsync(Lease lease, CancellationToken ct) =>
        SendAsync($"v1/agent/jobs/{lease.Id}/renew", new { lease.LeaseToken }, ct);
    public void Dispose() => client.Dispose();
}
