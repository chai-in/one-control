using System.Security.Principal;
using System.Text.Json;
using OneControl.Agent.Core;
using OneControl.Agent.Service;

if (args is ["--inventory"])
{
    Console.WriteLine(JsonSerializer.Serialize(Inventory.Collect(), Protocol.Json)); return;
}
if (!WindowsIdentity.GetCurrent().IsSystem) throw new InvalidOperationException("OneControl service runs only as LocalSystem");
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "OneControlAgent");
builder.Services.AddHostedService<AgentWorker>();
await builder.Build().RunAsync();
