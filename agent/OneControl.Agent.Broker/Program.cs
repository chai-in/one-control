using System.IO.Pipes;
using System.Text.RegularExpressions;
using OneControl.Agent.Core;

if (args is not ["--pipe", var pipeName] || !Regex.IsMatch(pipeName, "^one-control-task-[a-f0-9]{32}$")) return;
using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(45));
await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
await pipe.ConnectAsync(15_000, timeout.Token);
var task = await PipeProtocol.ReadAsync<BrokerTask>(pipe, timeout.Token);
var command = task.Command;
JobReceipt receipt;
try
{
    var arguments = UserPackageCommand.Arguments(command);
    var winget = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "winget.exe");
    if (!File.Exists(winget)) throw new InvalidOperationException("WinGet/App Installer unavailable for this user");
    MaintenanceWindow.EnsureOpen(task.EndsAt, timeout.Token);
    var code = await ProcessRunner.RunAsync(winget, arguments, TimeSpan.FromMinutes(40), timeout.Token);
    receipt = UserPackageCommand.Receipt(command, code);
}
catch (Exception error) { receipt = new(error is ExecutionIndeterminateException ? "indeterminate" : "failed", new() { ["reason"] = error.GetType().Name }); }
await PipeProtocol.WriteAsync(pipe, receipt, timeout.Token);
