using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OneControl.Agent.Core;

public static partial class ReleaseInstaller
{
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")] private static partial Regex PackagePattern();
    [GeneratedRegex("^[a-f0-9]{64}$")] private static partial Regex HashPattern();
    [GeneratedRegex("^[A-F0-9]{40}$")] private static partial Regex PublisherPattern();
    public static ReleaseManifest Verify(SignedEnvelope envelope, string publicKey, AgentSettings settings, DateTimeOffset now)
    {
        var payload = Convert.FromBase64String(envelope.Payload);
        if (payload.Length is < 1 or > 8192 || Convert.ToBase64String(payload) != envelope.Payload) throw new InvalidDataException("Invalid release encoding");
        using var rsa = RSA.Create(); rsa.ImportFromPem(publicKey);
        if (rsa.KeySize < 3072 || !rsa.VerifyData(payload, Convert.FromBase64String(envelope.Signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            throw new InvalidDataException("Release signature rejected");
        var manifest = JsonSerializer.Deserialize<ReleaseManifest>(payload, Protocol.Json) ?? throw new InvalidDataException("Manifest missing");
        var uri = new Uri(manifest.ArtifactUrl);
        if (manifest.SchemaVersion != 1 || manifest.Sequence < 1 || manifest.Size is < 1 or > 2147483648 ||
            manifest.ExpiresAt <= now || !PackagePattern().IsMatch(manifest.PackageId) || !HashPattern().IsMatch(manifest.Sha256) ||
            !PublisherPattern().IsMatch(manifest.PublisherThumbprint) || !settings.AllowedPackages.Contains(manifest.PackageId, StringComparer.Ordinal) ||
            uri.Scheme != "https" || !uri.IsDefaultPort || !string.IsNullOrEmpty(uri.UserInfo) ||
            !settings.ArtifactHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase) || !uri.AbsolutePath.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Manifest policy rejected");
        return manifest;
    }
    public static async Task<JobReceipt> InstallAsync(Lease lease, AgentSettings settings, Journal journal,
        string stagingDirectory, CancellationToken ct)
    {
        if (lease.Release is null) throw new InvalidDataException("Signed release required");
        var manifest = Verify(lease.Release, await File.ReadAllTextAsync(settings.ReleasePublicKeyFile, ct), settings, DateTimeOffset.UtcNow);
        if (manifest.PackageId == "one-control-agent") throw new ExecutionPreconditionException("Agent updates require independent recovery handoff");
        // Reserve before any side effect, even if the download fails. Reissue requires a new release sequence.
        journal.ReserveSequence(manifest.PackageId, manifest.Sequence);
        Directory.CreateDirectory(stagingDirectory);
        var destination = Path.Combine(stagingDirectory, lease.Id + ".msi");
        try
        {
            using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMinutes(20) };
            using var downloadDeadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            downloadDeadline.CancelAfter(TimeSpan.FromMinutes(20));
            var downloadToken = downloadDeadline.Token;
            using var response = await client.GetAsync(manifest.ArtifactUrl, HttpCompletionOption.ResponseHeadersRead, downloadToken);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is long length && length != manifest.Size) throw new InvalidDataException("Artifact size mismatch");
            await using (var source = await response.Content.ReadAsStreamAsync(downloadToken))
            await using (var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[65536]; long total = 0;
                int read;
                while ((read = await source.ReadAsync(buffer, downloadToken)) > 0)
                {
                    total += read; if (total > manifest.Size) throw new InvalidDataException("Artifact exceeded signed size");
                    digest.AppendData(buffer, 0, read); await target.WriteAsync(buffer.AsMemory(0, read), downloadToken);
                }
                if (total != manifest.Size || Convert.ToHexStringLower(digest.GetHashAndReset()) != manifest.Sha256)
                    throw new InvalidDataException("Artifact integrity rejected");
            }
            VerifyAuthenticode(destination, manifest.PublisherThumbprint);
            ct.ThrowIfCancellationRequested();
            if (DateTimeOffset.UtcNow >= lease.EndsAt || DateTimeOffset.UtcNow >= manifest.ExpiresAt) throw new InvalidDataException("Update window expired before install");
            var code = await ProcessRunner.RunAsync(Path.Combine(Environment.SystemDirectory, "msiexec.exe"),
                ["/i", destination, "/qn", "/norestart", "REBOOT=ReallySuppress"], TimeSpan.FromMinutes(45), ct);
            return new(code is 0 or 3010 ? "succeeded" : "indeterminate", new()
            {
                ["exitCode"] = code,
                ["rebootRequired"] = code == 3010,
                ["packageId"] = manifest.PackageId,
                ["version"] = manifest.Version,
                ["verification"] = "installer_receipt; installed version must be reconciled by inventory"
            });
        }
        finally { if (File.Exists(destination)) File.Delete(destination); }
    }
    public static void VerifyAuthenticode(string path, string expectedThumbprint)
    {
        var file = new TrustFile { Size = (uint)Marshal.SizeOf<TrustFile>(), FilePath = path };
        var filePointer = Marshal.AllocHGlobal(Marshal.SizeOf<TrustFile>());
        try
        {
            Marshal.StructureToPtr(file, filePointer, false);
            var data = new TrustData
            {
                Size = (uint)Marshal.SizeOf<TrustData>(),
                UiChoice = 2,
                RevocationChecks = 1,
                UnionChoice = 1,
                File = filePointer,
                ProviderFlags = 0x80
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            if (WinVerifyTrust(IntPtr.Zero, ref action, ref data) != 0) throw new InvalidDataException("Windows publisher trust rejected");
#pragma warning disable SYSLIB0057 // Authenticode extraction only; WinVerifyTrust performs trust verification above.
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            if (!string.Equals(certificate.Thumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Installer publisher pin mismatch");
        }
        finally { Marshal.DestroyStructure<TrustFile>(filePointer); Marshal.FreeHGlobal(filePointer); }
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct TrustFile { public uint Size; public string FilePath; public IntPtr FileHandle; public IntPtr KnownSubject; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct TrustData
    {
        public uint Size; public IntPtr PolicyCallback; public IntPtr SipClient; public uint UiChoice;
        public uint RevocationChecks; public uint UnionChoice; public IntPtr File; public uint StateAction;
        public IntPtr StateData; public IntPtr UrlReference; public uint ProviderFlags; public uint UiContext;
        public IntPtr SignatureSettings;
    }
    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
}
