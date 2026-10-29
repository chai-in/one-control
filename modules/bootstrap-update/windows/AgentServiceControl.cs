using System.ComponentModel;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Win32;

namespace OneControl.Agent.Core;

internal static class AgentServiceControl
{
    private const string ServiceName = "OneControlAgent";
    public static string Executable()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + ServiceName);
        var value = key?.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        if (value is not { Length: > 2 } || value[0] != '"' || value[^1] != '"' || value[1..^1].Contains('"'))
            throw new InvalidDataException("Agent service must use one quoted absolute executable without arguments");
        var executable = value[1..^1];
        ProtectedPaths.ValidateFile(executable);
        return executable;
    }
    public static bool RecoveryAvailable()
    {
        using var service = new ServiceController("OneControlRecovery");
        try { return service.Status == ServiceControllerStatus.Running; }
        catch (InvalidOperationException) { return false; }
    }
    public static async Task StopAsync(CancellationToken ct)
    {
        using var service = new ServiceController(ServiceName);
        service.Refresh();
        if (service.Status != ServiceControllerStatus.Stopped && service.Status != ServiceControllerStatus.StopPending) service.Stop();
        await WaitAsync(service, ServiceControllerStatus.Stopped, ct);
    }
    public static async Task StartAsync(CancellationToken ct)
    {
        using var service = new ServiceController(ServiceName);
        service.Refresh();
        if (service.Status == ServiceControllerStatus.Stopped) service.Start();
        await WaitAsync(service, ServiceControllerStatus.Running, ct);
    }
    private static async Task WaitAsync(ServiceController service, ServiceControllerStatus desired, CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(45);
        do
        {
            ct.ThrowIfCancellationRequested(); service.Refresh();
            if (service.Status == desired) return;
            await Task.Delay(500, ct);
        } while (DateTimeOffset.UtcNow < deadline);
        throw new System.TimeoutException("Agent service did not reach the required state");
    }
    public static void Configure(string executable)
    {
        ProtectedPaths.ValidateFile(executable);
        using var service = new ServiceController(ServiceName);
        // Reopen with the precise configuration right; ServiceController's default handle is read-only.
        var manager = OpenSCManager(null, null, 1);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var handle = OpenService(manager, ServiceName, 2);
            if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                if (!ChangeServiceConfig(handle, uint.MaxValue, uint.MaxValue, uint.MaxValue, '"' + executable + '"', null, IntPtr.Zero, null, null, null, null))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally { CloseServiceHandle(handle); }
        }
        finally { CloseServiceHandle(manager); }
    }
    public static int ProcessId()
    {
        using var service = new ServiceController(ServiceName);
        if (!QueryServiceStatusEx(service.ServiceHandle.DangerousGetHandle(), 0, out var status, Marshal.SizeOf<ServiceStatus>(), out _))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return checked((int)status.ProcessId);
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus { public uint Type, State, Controls, ExitCode, SpecificExitCode, CheckPoint, WaitHint, ProcessId, Flags; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig(IntPtr service, uint type, uint start, uint error, string path, string? group, IntPtr tag, string? dependencies, string? account, string? password, string? displayName);
    [DllImport("advapi32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatus status, int size, out int needed);
}
