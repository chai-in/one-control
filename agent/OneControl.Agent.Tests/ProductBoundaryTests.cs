using System.Text.Json;
using OneControl.Agent.Core;
using Xunit;

namespace OneControl.Agent.Tests;

public sealed class ProductBoundaryTests
{
    [Theory]
    [InlineData("crm.status")]
    [InlineData("crm.update")]
    [InlineData("android.lock")]
    [InlineData("amapi.command")]
    [InlineData("shell.exec")]
    public void ExcludedAndUnknownCommandsCannotEnterTheUserBroker(string kind)
    {
        Assert.False(Protocol.IsUserCommand(new(kind)));
        Assert.Throws<InvalidDataException>(() => UserPackageCommand.Arguments(new(kind)));
    }

    [Theory]
    [InlineData("crmPublisherThumbprint")]
    [InlineData("requestId")]
    public void RemovedBrokerFieldsAreRejectedInsteadOfIgnored(string field)
    {
        var task = JsonSerializer.Serialize(new BrokerTask(new("store.upgrade", "9NBLGGH4NNS1"), DateTimeOffset.UtcNow), Protocol.Json);
        var extra = task[..^1] + ",\"" + field + "\":\"legacy-value\"}";
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<BrokerTask>(extra, Protocol.Json));
    }
}
