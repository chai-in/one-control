using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace OneControl.Agent.Core;

// The service owns fleet credentials. A transient lower-privilege process receives one typed task only.
public static class SessionBroker
{
    public static bool HasInteractiveSession => InteractiveSessions.FindTarget() is not null;
    public static async Task<JobReceipt> ExecuteAsync(string brokerPath, Command command, DateTimeOffset endsAt, CancellationToken ct)
    {
        if (!Protocol.IsUserCommand(command)) throw new InvalidDataException("Broker command forbidden");
        var session = InteractiveSessions.FindTarget();
        if (session is null) return new("failed", new() { ["reason"] = "unambiguous_interactive_user_session_required" });
        if (!WTSQueryUserToken(session.Value, out var token)) throw NativeFailure("query_user_token");
        using (token)
        using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
        {
            var pipeName = "one-control-task-" + Guid.NewGuid().ToString("N");
            var security = new PipeSecurity(); security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(identity.User!, PipeAccessRights.ReadWrite, AccessControlType.Allow));
            await using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 8192, 8192, security);
            if (!CreateEnvironmentBlock(out var environment, token, false)) throw NativeFailure("create_user_environment");
            try
            {
                var startup = new StartupInfo { Size = Marshal.SizeOf<StartupInfo>(), Desktop = @"winsta0\default" };
                var arguments = new System.Text.StringBuilder($"\"{brokerPath}\" --pipe {pipeName}");
                if (!CreateProcessAsUser(token, brokerPath, arguments, IntPtr.Zero, IntPtr.Zero, false,
                    0x08000000 | 0x00000400, environment, Path.GetDirectoryName(brokerPath)!, ref startup, out var process))
                    throw NativeFailure("create_user_process");
                CloseHandle(process.Thread);
                try
                {
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromMinutes(45));
                    await pipe.WaitForConnectionAsync(deadline.Token);
                    if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var clientPid) || clientPid != process.ProcessId)
                        throw new InvalidDataException("Unexpected broker process");
                    // Length-framed bounded JSON, never PowerShell, command strings, credentials or arbitrary paths.
                    MaintenanceWindow.EnsureOpen(endsAt, deadline.Token);
                    await PipeProtocol.WriteAsync(pipe, new BrokerTask(command, endsAt), deadline.Token);
                    return await PipeProtocol.ReadAsync<JobReceipt>(pipe, deadline.Token);
                }
                catch (OperationCanceledException) { throw new ExecutionIndeterminateException("User provider interrupted"); }
                finally { CloseHandle(process.Process); }
            }
            finally { DestroyEnvironmentBlock(environment); }
        }
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size; public string? Reserved; public string? Desktop; public string? Title;
        public int X; public int Y; public int XSize; public int YSize; public int XChars; public int YChars;
        public int Fill; public int Flags; public short Show; public short ReservedSize;
        public IntPtr ReservedPointer; public IntPtr StdInput; public IntPtr StdOutput; public IntPtr StdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInfo { public IntPtr Process; public IntPtr Thread; public uint ProcessId; public uint ThreadId; }
    private static Win32Exception NativeFailure(string operation)
    {
        var error = new Win32Exception(Marshal.GetLastWin32Error());
        error.Data["operation"] = operation;
        return error;
    }
    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQueryUserToken(uint session, out SafeAccessTokenHandle token);
    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateEnvironmentBlock(out IntPtr environment, SafeAccessTokenHandle token, bool inherit);
    [DllImport("userenv.dll")][return: MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyEnvironmentBlock(IntPtr environment);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessAsUser(SafeAccessTokenHandle token, string application,
        System.Text.StringBuilder arguments, IntPtr processAttributes, IntPtr threadAttributes, bool inherit,
        uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
}
public static class PipeProtocol
{
    public static async Task WriteAsync<T>(Stream stream, T value, CancellationToken ct, int maximumBytes = 65536)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, Protocol.Json);
        if (bytes.Length > maximumBytes) throw new InvalidDataException("IPC payload too large");
        var prefix = new byte[4]; System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(prefix, bytes.Length);
        await stream.WriteAsync(prefix, ct); await stream.WriteAsync(bytes, ct); await stream.FlushAsync(ct);
    }
    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken ct, int maximumBytes = 65536)
    {
        var prefix = new byte[4]; await stream.ReadExactlyAsync(prefix, ct);
        var length = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (length < 1 || length > maximumBytes) throw new InvalidDataException("IPC payload size rejected");
        var bytes = new byte[length]; await stream.ReadExactlyAsync(bytes, ct);
        return JsonSerializer.Deserialize<T>(bytes, Protocol.Json) ?? throw new InvalidDataException("IPC payload missing");
    }
}
