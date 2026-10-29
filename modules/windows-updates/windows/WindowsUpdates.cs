using System.Runtime.InteropServices;

namespace OneControl.Agent.Core;

public static class WindowsUpdates
{
    // Dedicated STA thread: WUA COM does not provide reliable cancellation of synchronous installs.
    public static Task<JobReceipt> ExecuteAsync(Command command, DateTimeOffset endsAt, CancellationToken ct)
    {
        var completion = new TaskCompletionSource<JobReceipt>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var comObjects = new List<object>();
            try
            {
                dynamic session = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.Session")
                    ?? throw new InvalidOperationException("Windows Update unavailable"))!;
                comObjects.Add(session); session.ClientApplicationID = "One Control";
                dynamic searcher = session.CreateUpdateSearcher(); comObjects.Add(searcher);
                // Respect existing WSUS/WUfB configuration. Never enable Microsoft Update or drivers implicitly.
                dynamic found = searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'"); comObjects.Add(found);
                var available = new List<Dictionary<string, object?>>();
                dynamic selected = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.UpdateColl")!)!;
                comObjects.Add(selected);
                for (var index = 0; index < found.Updates.Count; index++)
                {
                    dynamic update = found.Updates.Item(index); comObjects.Add(update);
                    // Feature upgrades are excluded; drivers already excluded by the query.
                    bool featureUpgrade = false;
                    for (var category = 0; category < update.Categories.Count; category++)
                        if ((string)update.Categories.Item(category).CategoryID == "3689bdc8-b205-4af4-8d4a-a63924c5e9d5") featureUpgrade = true;
                    if (featureUpgrade || update.InstallationBehavior.CanRequestUserInput) continue;
                    var id = Guid.Parse((string)update.Identity.UpdateID);
                    int revision = update.Identity.RevisionNumber;
                    available.Add(new()
                    {
                        ["id"] = id,
                        ["revision"] = revision,
                        ["title"] = (string)update.Title,
                        ["eulaAccepted"] = (bool)update.EulaAccepted
                    });
                    if (command.Updates?.Any(item => item.Id == id && item.Revision == revision) == true)
                    {
                        selected.Add(update);
                    }
                }
                if (command.Kind == "windows.scan")
                {
                    completion.SetResult(new("succeeded", new() { ["updates"] = available })); return;
                }
                MaintenanceWindow.EnsureOpen(endsAt, ct);
                if (command.Kind != "windows.install" || command.Updates is not { Length: > 0 } || selected.Count != command.Updates.Length)
                    throw new InvalidOperationException("Approved update IDs/revisions no longer applicable");
                // Organisation policy authorises terms for exact, approved managed updates; scans remain read-only.
                for (var index = 0; index < selected.Count; index++)
                {
                    MaintenanceWindow.EnsureOpen(endsAt, ct);
                    dynamic update = selected.Item(index); comObjects.Add(update);
                    if (!update.EulaAccepted) update.AcceptEula();
                }
                dynamic downloader = session.CreateUpdateDownloader(); comObjects.Add(downloader);
                downloader.Updates = selected;
                dynamic download = downloader.Download(); comObjects.Add(download);
                if ((int)download.ResultCode != 2) throw new ExecutionIndeterminateException("Windows Update download did not complete");
                // Scanning/downloading can outlast the approved window. Recheck immediately before OS mutation.
                MaintenanceWindow.EnsureOpen(endsAt, ct);
                dynamic installer = session.CreateUpdateInstaller(); comObjects.Add(installer); installer.Updates = selected;
                dynamic installed = installer.Install(); comObjects.Add(installed);
                var results = new List<Dictionary<string, object?>>();
                for (var index = 0; index < selected.Count; index++)
                {
                    dynamic result = installed.GetUpdateResult(index); comObjects.Add(result);
                    results.Add(new() { ["id"] = (string)selected.Item(index).Identity.UpdateID, ["resultCode"] = (int)result.ResultCode, ["hresult"] = (int)result.HResult });
                }
                completion.SetResult(new((int)installed.ResultCode == 2 ? "succeeded" : "indeterminate",
                    new() { ["updates"] = results, ["rebootRequired"] = (bool)installed.RebootRequired }));
            }
            catch (Exception error) { completion.SetException(error); }
            finally { foreach (var item in comObjects.AsEnumerable().Reverse()) if (Marshal.IsComObject(item)) Marshal.FinalReleaseComObject(item); }
        })
        { IsBackground = true, Name = "OneControl Windows Update" };
        thread.SetApartmentState(ApartmentState.STA); thread.Start();
        return completion.Task;
    }
}
