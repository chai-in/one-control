using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace OneControl.Agent.Core;

internal sealed record MemorySnapshot(ulong TotalBytes, ulong AvailableBytes);
internal sealed record DiskSnapshot(string Name, string? FileSystem, long? TotalBytes, long? FreeBytes,
    bool SystemVolume, string Status);
internal sealed record HardwareSnapshot(string? Manufacturer, string? Model, string? Processor,
    uint? LogicalProcessors, MemorySnapshot? Memory, List<DiskSnapshot> Disks, long UptimeSeconds);

internal static class HardwareInventory
{
    public static HardwareSnapshot Collect(InventoryDiagnostics diagnostics)
    {
        var identity = diagnostics.Capture<(string?, string?, string?)>("hardware.identity", () =>
        {
            using var bios = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            using var cpu = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            return (InventoryDiagnostics.Text(bios?.GetValue("SystemManufacturer"), 128),
                InventoryDiagnostics.Text(bios?.GetValue("SystemProductName"), 128),
                InventoryDiagnostics.Text(cpu?.GetValue("ProcessorNameString"), 256));
        }, (null, null, null));
        var processors = diagnostics.Capture<uint?>("hardware.processors", () =>
        {
            var count = GetActiveProcessorCount(ushort.MaxValue); // All Windows processor groups.
            if (count == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
            return count;
        }, null);
        var memory = diagnostics.Capture<MemorySnapshot?>("hardware.memory", () =>
        {
            var value = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
            if (!GlobalMemoryStatusEx(ref value)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return new(value.TotalPhysical, value.AvailablePhysical);
        }, null);
        var disks = diagnostics.Capture("hardware.disks", () => Disks(diagnostics), []);
        return new(identity.Item1, identity.Item2, identity.Item3, processors, memory, disks,
            Math.Max(0, Environment.TickCount64 / 1000));
    }

    private static List<DiskSnapshot> Disks(InventoryDiagnostics diagnostics)
    {
        var result = new List<DiskSnapshot>();
        var systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
        // Local fixed volumes only. Never enumerate files, network shares, removable media or volume labels.
        foreach (var drive in DriveInfo.GetDrives().Take(32))
        {
            var fixedVolume = diagnostics.Capture("hardware.disks", () => drive.DriveType == DriveType.Fixed, false);
            if (!fixedVolume) continue;
            var name = InventoryDiagnostics.Text(drive.Name, 16) ?? "Unknown";
            var system = string.Equals(drive.Name, systemRoot, StringComparison.OrdinalIgnoreCase);
            var observation = diagnostics.Capture<DiskSnapshot?>("hardware.disks", () =>
            {
                if (!drive.IsReady) throw new IOException("Volume is not ready");
                return new(name, InventoryDiagnostics.Text(drive.DriveFormat, 32), drive.TotalSize,
                    drive.TotalFreeSpace, system, "available");
            }, null);
            result.Add(observation ?? new(name, null, null, null, system, "unavailable"));
        }
        return result;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatus status);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetActiveProcessorCount(ushort groupNumber);
}
