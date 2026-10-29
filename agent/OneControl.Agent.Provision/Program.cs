using System.Security.Principal;
using System.Text.Json;
using OneControl.Agent.Core;

if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
    throw new InvalidOperationException("Elevated IT provisioning required");
if (args is ["--repair-settings", var settingsFile])
{
    if (System.Diagnostics.Process.GetProcessesByName("OneControl.Agent.Service").Length != 0)
        throw new InvalidOperationException("Stop the OneControl agent before repairing settings");
    var existing = AgentSettings.Load(settingsFile);
    await AgentSettings.SaveAsync(settingsFile, existing, CancellationToken.None);
    Console.WriteLine("Protected settings repaired; credential, identity, issuance time and journal preserved.");
    return;
}
if (args is not [var inputFile, var outputFile]) throw new ArgumentException("Usage: OneControl.Agent.Provision enrollment.json agent.json OR --repair-settings agent.json");
if (File.Exists(outputFile)) throw new InvalidOperationException("Device already configured; explicit decommission required");
ProtectedPaths.ValidateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputFile))!, privateLeaf: true);
ProtectedPaths.ValidateFile(inputFile, confidential: true);
var input = JsonSerializer.Deserialize<EnrollmentInput>(await File.ReadAllTextAsync(inputFile), Protocol.Json)
    ?? throw new InvalidDataException("Enrollment configuration missing");
ProtectedPaths.ValidateFile(input.BrokerPath);
ProtectedPaths.ValidateFile(input.ReleasePublicKeyFile);
using var client = new ControlPlaneClient(input.ControlPlane, null);
var enrollment = await client.PostAsync<EnrollmentResponse>("v1/agent/enroll", new { input.Token, hostname = Environment.MachineName }, CancellationToken.None);
var settings = new AgentSettings(input.ControlPlane, enrollment.DeviceId, AgentSettings.ProtectCredential(enrollment.Credential),
    input.ArtifactHosts, input.AllowedPackages, input.ReleasePublicKeyFile, input.BrokerPath, CredentialCreatedAt: DateTimeOffset.UtcNow);
await AgentSettings.SaveAsync(outputFile, settings, CancellationToken.None);
Console.WriteLine($"Enrolled device {enrollment.DeviceId}. Credential protected with Windows DPAPI.");
sealed record EnrollmentInput(Uri ControlPlane, string Token, string[] ArtifactHosts, string[] AllowedPackages, string ReleasePublicKeyFile, string BrokerPath);
sealed record EnrollmentResponse(Guid DeviceId, string Credential);
