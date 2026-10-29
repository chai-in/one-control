using System.ComponentModel;
using System.Runtime.InteropServices;

namespace OneControl.Agent.Core;

public sealed record InteractiveSession(uint Id, bool Active, bool HasUser);

public static class InteractiveSessions
{
    public static uint? Select(IReadOnlyList<InteractiveSession> sessions, uint consoleId)
    {
        var active = sessions.Where(session => session.Active && session.HasUser).ToArray();
        var console = active.FirstOrDefault(session => session.Id == consoleId);
        if (console is not null) return console.Id;
        return active.Length == 1 ? active[0].Id : null;
    }

    public static uint? FindTarget()
    {
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var buffer, out var count))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var sessions = new List<InteractiveSession>();
            var size = Marshal.SizeOf<SessionInfo>();
            for (var index = 0; index < count; index++)
            {
                var session = Marshal.PtrToStructure<SessionInfo>(buffer + index * size);
                var hasUser = false;
                if (session.State == 0 && WTSQuerySessionInformation(IntPtr.Zero, session.Id, 5, out var user, out var bytes))
                {
                    try { hasUser = bytes > 2 && !string.IsNullOrWhiteSpace(Marshal.PtrToStringUni(user)); }
                    finally { WTSFreeMemory(user); }
                }
                sessions.Add(new(session.Id, session.State == 0, hasUser));
            }
            return Select(sessions, WTSGetActiveConsoleSessionId());
        }
        finally { WTSFreeMemory(buffer); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SessionInfo { public uint Id; public IntPtr Name; public int State; }
    [DllImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQuerySessionInformation(IntPtr server, uint session, int info, out IntPtr buffer, out int size);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr buffer);
    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
}
