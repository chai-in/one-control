using OneControl.Agent.Core;
using Xunit;

namespace OneControl.Agent.Tests;

public sealed class SessionTests
{
    [Fact]
    public void ActiveConsoleUserTakesPrecedence()
    {
        Assert.Equal(3u, InteractiveSessions.Select([new(3, true, true), new(4, true, true)], 3));
    }
    [Fact]
    public void SingleRdpUserIsUsableWhenTheConsoleHasNoUser()
    {
        Assert.Equal(4u, InteractiveSessions.Select([new(3, true, false), new(4, true, true)], 3));
    }
    [Fact]
    public void AmbiguousRdpUsersAreNeverChosenImplicitly()
    {
        Assert.Null(InteractiveSessions.Select([new(4, true, true), new(5, true, true)], 3));
    }
    [Fact]
    public void DisconnectedAndLogonScreenSessionsAreNotEligible()
    {
        Assert.Null(InteractiveSessions.Select([new(3, true, false), new(4, false, true)], 3));
    }
}
