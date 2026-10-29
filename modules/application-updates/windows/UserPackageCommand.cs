using System.Text.RegularExpressions;

namespace OneControl.Agent.Core;

public static class UserPackageCommand
{
    // Microsoft's documented UPDATE_NOT_APPLICABLE is a terminal no-op, not an uncertain installer.
    public static JobReceipt Receipt(Command command, int code)
    {
        var noUpdate = code == unchecked((int)0x8A15002B);
        return new(code == 0 || noUpdate ? "succeeded" : "indeterminate", new()
        {
            ["exitCode"] = code,
            ["packageId"] = command.PackageId,
            ["provider"] = command.Kind == "store.upgrade" ? "winget-msstore" : "winget",
            ["agreementPolicy"] = "organisation_default",
            ["outcome"] = noUpdate ? "no_applicable_update" : code == 0 ? "provider_completed" : "uncertain",
            ["changed"] = noUpdate ? false : null,
            ["scope"] = command.Kind == "store.upgrade" ? "selected interactive user; Store catalogue packages only" : "selected interactive user"
        });
    }

    public static string[] Arguments(Command command)
    {
        if (!Protocol.IsUserCommand(command) || command.PackageId is null)
            throw new InvalidDataException("Invalid user package task");
        var store = command.Kind == "store.upgrade";
        if (!Regex.IsMatch(command.PackageId, store ? "^[A-Za-z0-9]{8,32}$" : "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"))
            throw new InvalidDataException("Invalid package identity");
        if (!store && (command.Version is null || !Regex.IsMatch(command.Version, "^[A-Za-z0-9][A-Za-z0-9._+()-]{0,63}$") ||
            command.Version.Equals("latest", StringComparison.OrdinalIgnoreCase) || command.Version.Equals("unknown", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("Exact WinGet version required");
        var arguments = new List<string> { "upgrade", "--id", command.PackageId, "--exact", "--source", store ? "msstore" : "winget",
            "--silent", "--disable-interactivity", "--accept-source-agreements", "--accept-package-agreements" };
        if (!store) { arguments.Add("--version"); arguments.Add(command.Version!); }
        return arguments.ToArray();
    }
}
