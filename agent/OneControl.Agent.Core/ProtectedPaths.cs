using System.Security.AccessControl;
using System.Security.Principal;

namespace OneControl.Agent.Core;

public static class ProtectedPaths
{
    private static readonly HashSet<string> TrustedOwners = [
        "S-1-5-18", "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" // TrustedInstaller
    ];
    private const FileSystemRights NamespaceWrites = FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
    private const FileSystemRights FileWrites = NamespaceWrites | FileSystemRights.WriteData | FileSystemRights.AppendData |
        FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes;

    public static void ValidateDirectory(string path, bool privateLeaf = false)
    {
        var full = Path.GetFullPath(path);
        if (full.StartsWith(@"\\", StringComparison.Ordinal)) throw new InvalidDataException("Local protected storage required");
        var leaf = new DirectoryInfo(full);
        for (var current = leaf; current is not null; current = current.Parent)
        {
            if (!current.Exists || (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Protected directory is missing or traverses a reparse point");
            ValidateSecurity(current.GetAccessControl(), current.FullName == leaf.FullName
                ? privateLeaf ? FileSystemRights.FullControl : FileWrites : NamespaceWrites);
        }
    }

    public static void ValidateFile(string path, bool confidential = false)
    {
        ValidateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var file = new FileInfo(path);
        if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Trusted file is missing or is a reparse point");
        ValidateSecurity(file.GetAccessControl(), confidential ? FileSystemRights.FullControl : FileWrites);
    }

    public static void ValidateSecurity(FileSystemSecurity security, FileSystemRights forbidden)
    {
        if (new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl is null)
            throw new InvalidDataException("Protected path has an unrestricted DACL");
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !TrustedOwners.Contains(owner.Value))
            throw new InvalidDataException("Protected path has an untrusted owner; IT must reconcile existing state");
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow || (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
            if (rule.IdentityReference is SecurityIdentifier sid && TrustedOwners.Contains(sid.Value)) continue;
            // Include generic access masks, which can appear on inherited filesystem ACLs.
            var genericForbidden = forbidden == FileSystemRights.FullControl ? 0xf0000000u : 0x50000000u;
            if ((rule.FileSystemRights & forbidden) != 0 || ((uint)rule.FileSystemRights & genericForbidden) != 0)
                throw new InvalidDataException("Protected path permits untrusted access; IT must reconcile existing state");
        }
    }
}
