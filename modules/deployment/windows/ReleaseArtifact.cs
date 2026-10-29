using System.Security.Cryptography;

namespace OneControl.Agent.Core;

internal static class ReleaseArtifact
{
    public static async Task DownloadAsync(ReleaseManifest manifest, string destination, CancellationToken ct)
    {
        ProtectedPaths.ValidateDirectory(Path.GetDirectoryName(Path.GetFullPath(destination))!, privateLeaf: true);
        var created = false;
        try
        {
            using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMinutes(20) };
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromMinutes(20));
            using var response = await client.GetAsync(manifest.ArtifactUrl, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is long length && length != manifest.Size) throw new InvalidDataException("Artifact size mismatch");
            await using (var source = await response.Content.ReadAsStreamAsync(deadline.Token))
            await using (var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                created = true;
                using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[65536]; long total = 0;
                int read;
                while ((read = await source.ReadAsync(buffer, deadline.Token)) > 0)
                {
                    total += read;
                    if (total > manifest.Size) throw new InvalidDataException("Artifact exceeded signed size");
                    digest.AppendData(buffer, 0, read);
                    await target.WriteAsync(buffer.AsMemory(0, read), deadline.Token);
                }
                if (total != manifest.Size || Convert.ToHexStringLower(digest.GetHashAndReset()) != manifest.Sha256)
                    throw new InvalidDataException("Artifact integrity rejected");
                await target.FlushAsync(deadline.Token);
                target.Flush(flushToDisk: true);
            }
            ProtectedPaths.ValidateFile(destination, confidential: true);
            ReleaseInstaller.VerifyAuthenticode(destination, manifest.PublisherThumbprint);
        }
        catch { if (created && File.Exists(destination)) File.Delete(destination); throw; }
    }
}
