using System.Security.AccessControl;
using System.Text.Json;

namespace OneControl.Agent.Core;

internal static class ProtectedJson
{
    public static void EnsurePrivateDirectory(string path)
    {
        ProtectedPaths.ValidateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!, privateLeaf: true);
        if (!Directory.Exists(path))
        {
            var security = new DirectorySecurity();
            security.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
            new DirectoryInfo(path).Create(security);
        }
        ProtectedPaths.ValidateDirectory(path, privateLeaf: true);
    }

    public static T? Read<T>(string path)
    {
        ProtectedPaths.ValidateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!, privateLeaf: true);
        if (!File.Exists(path)) return default;
        ProtectedPaths.ValidateFile(path, confidential: true);
        if (new FileInfo(path).Length > 128 * 1024) throw new InvalidDataException("Protected record exceeds size limit");
        return JsonSerializer.Deserialize<T>(File.ReadAllText(path), Protocol.Json) ?? throw new InvalidDataException("Invalid protected record");
    }

    public static void Write<T>(string path, T value)
    {
        ProtectedPaths.ValidateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!, privateLeaf: true);
        if (File.Exists(path)) ProtectedPaths.ValidateFile(path, confidential: true);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(file, value, Protocol.Json);
                file.Flush(flushToDisk: true);
            }
            ProtectedPaths.ValidateFile(temporary, confidential: true);
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
