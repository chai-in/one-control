using System.Security.Principal;
using Xunit;

namespace OneControl.Agent.Tests;

internal static class AdministratorTests
{
    public static bool ShouldSkip
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)
                && Environment.GetEnvironmentVariable("CI") != "true";
        }
    }
    public const string Reason = "Requires an elevated Windows account for SYSTEM/Administrators-owned storage; the Windows CI job runs this coverage.";
}

public sealed class RequiresAdministratorFactAttribute : FactAttribute
{
    public RequiresAdministratorFactAttribute()
    {
        if (AdministratorTests.ShouldSkip) Skip = AdministratorTests.Reason;
    }
}

public sealed class RequiresAdministratorTheoryAttribute : TheoryAttribute
{
    public RequiresAdministratorTheoryAttribute()
    {
        if (AdministratorTests.ShouldSkip) Skip = AdministratorTests.Reason;
    }
}
