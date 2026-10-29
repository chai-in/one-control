using System.Security.Principal;
using OneControl.Agent.Core;

if (args.Length != 0) throw new ArgumentException("Recovery service accepts no command line tasks");
if (!WindowsIdentity.GetCurrent().IsSystem) throw new InvalidOperationException("Recovery runs only as LocalSystem");
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "OneControlRecovery");
builder.Services.AddHostedService<RecoveryWorker>();
await builder.Build().RunAsync();

sealed class RecoveryWorker(ILogger<RecoveryWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var state = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "OneControl", "Agent");
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await AgentRecovery.RunOnceAsync(state, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error) { logger.LogWarning("Agent recovery requires retry or reconciliation: {ErrorType}", error.GetType().Name); }
            try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
