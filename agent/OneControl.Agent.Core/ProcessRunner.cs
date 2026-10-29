using System.Diagnostics;

namespace OneControl.Agent.Core;

public static class ProcessRunner
{
    public static async Task<int> RunAsync(string executable, IEnumerable<string> arguments,
        TimeSpan timeout, CancellationToken ct)
    {
        if (!Path.IsPathFullyQualified(executable)) throw new InvalidDataException("Executable must use an absolute trusted path");
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(executable)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }
        };
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        if (!process.Start()) throw new InvalidOperationException("Could not start provider");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        // Drain streams without persisting installer output (which can contain user data).
        var stdout = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
        var stderr = process.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
        try
        {
            await process.WaitForExitAsync(deadline.Token);
            await Task.WhenAll(stdout, stderr);
            return process.ExitCode;
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            // Killing a launcher cannot prove that an installer or OS transaction was rolled back.
            throw new ExecutionIndeterminateException("Provider deadline or coordinator lease lost");
        }
    }
}
public sealed class ExecutionIndeterminateException(string message) : Exception(message);
