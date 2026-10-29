# Device inventory and capacity

Imported and adapted design guidance. See phase 1 validation for current results. Source-era pilot observations remain historical evidence in the preserved transfer; they do not establish One Control deployment or live endpoint acceptance.

Agent 0.2.2 adds read-only hardware observations and inventory coverage metadata. The optional console renders these fields when present; older agents remain compatible and show unreported fields explicitly. No collector installs software, searches user files, runs commands, changes services or modifies security policy.

## Observed fields

- Manufacturer, model and processor description are best-effort Windows hardware-registry values. Active logical processor count includes all Windows processor groups.
- Physical memory uses `GlobalMemoryStatusEx`: `totalBytes` is physical memory available to Windows, rather than an inventory of installed DIMMs. `availableBytes` is immediately reusable physical memory at collection time. It is not a historical memory-pressure diagnosis.
- Fixed drive-letter volumes report name, filesystem, total bytes and total free bytes. The Windows volume is identified separately. Network shares, removable drives, volume labels and directory contents are not collected. An unreadable volume retains its name with `status: unavailable` and null capacity.
- Uptime uses the operating system's monotonic tick count. The console labels it as uptime at collection, preserving the observation's timestamp when a computer goes offline.
- Restart status observes Windows Update, Component Based Servicing and pending file-rename indicators. It is advisory; OneControl never forces a reboot. An unreadable check returns unknown rather than a false negative.

The native memory and processor APIs are documented by Microsoft: [MEMORYSTATUSEX](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex), [GetActiveProcessorCount](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getactiveprocessorcount). Drive capacity follows [.NET DriveInfo](https://learn.microsoft.com/en-us/dotnet/api/system.io.driveinfo.totalsize).

## Scope and failure handling

`collection.schemaVersion` is 2. `collection.status` is `complete` or `partial` for the supported collection scope. `collection.issues` contains bounded section/code pairs such as `hardware.disks/unavailable` or `applications/collection_limit`; exception text and private paths are excluded. Other observations remain available when a registry entry or native query fails. An absent field is not a zero reading or a successful health check.

The application list covers the 32-bit and 64-bit machine uninstall registries. It does not claim all per-user or Store applications. It stops at 500 records, 2,048 inspected registry entries or a 128 KiB escaped-JSON list budget. Display strings are length-bounded, control characters are removed, unsupported registry value kinds are omitted, and uninstall strings are never read or executed.

The full snapshot has a 192 KiB budget, leaving space below the API's 256 KiB request limit for transport fields. A final defensive check retains the small heartbeat fields and reports partial inventory if a future collector exceeds that budget. This only reduces outgoing observations; it never deletes endpoint state or installed applications. Count and byte budgets do not promise a hard deadline for operating-system I/O.

## Console interpretation

Device details show memory, processor, uptime and fixed-volume capacity. Less than 10% free disk space raises an advisory. It does not establish how much space a particular update requires or prevent installation automatically. Missing, invalid or inconsistent capacity is shown as unavailable. Fleet filters expose reported low space, stopped recovery, pending restart and partial inventory without classifying an unreported computer as healthy.

Native modal dialogs keep the background inert and prevent background scrolling. Closing a dialog restores focus to its originating control when that control still exists.

## Acceptance status

Current One Control validation is recorded in the phase 1 report. Original device observations and pilot results remain in the preserved Sentry transfer. No production inventory claim is carried forward by this import.
