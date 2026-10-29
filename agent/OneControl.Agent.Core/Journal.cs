using Microsoft.Data.Sqlite;
using System.Text.Json;

namespace OneControl.Agent.Core;

// Write-ahead execution records survive service restart. Mutations are never re-executed automatically.
public sealed class Journal : IDisposable
{
    private readonly SqliteConnection db;
    public Journal(string path)
    {
        db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        db.Open();
        using var command = db.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY,lease TEXT NOT NULL,receipt TEXT,acknowledged INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS sequences(package TEXT PRIMARY KEY,sequence INTEGER NOT NULL);
            """;
        command.ExecuteNonQuery();
    }
    public void Begin(Lease lease)
    {
        using var command = db.CreateCommand();
        command.CommandText = "INSERT INTO receipts(id,lease) VALUES($id,$lease) ON CONFLICT(id) DO NOTHING";
        command.Parameters.AddWithValue("$id", lease.Id.ToString());
        command.Parameters.AddWithValue("$lease", JsonSerializer.Serialize(lease, Protocol.Json));
        if (command.ExecuteNonQuery() == 1) return;
        if (Protocol.IsMutation(lease.Command)) throw new InvalidOperationException("Mutation already recorded; reconcile instead of replay");
        command.CommandText = "UPDATE receipts SET lease=$lease,receipt=NULL,acknowledged=0 WHERE id=$id AND acknowledged=1";
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Unreconciled job already recorded");
    }
    public void Finish(Guid id, JobReceipt receipt)
    {
        using var command = db.CreateCommand();
        command.CommandText = "UPDATE receipts SET receipt=$receipt WHERE id=$id";
        command.Parameters.AddWithValue("$id", id.ToString());
        command.Parameters.AddWithValue("$receipt", JsonSerializer.Serialize(receipt, Protocol.Json));
        command.ExecuteNonQuery();
    }
    public void Acknowledge(Guid id)
    {
        using var command = db.CreateCommand();
        command.CommandText = "UPDATE receipts SET acknowledged=1 WHERE id=$id";
        command.Parameters.AddWithValue("$id", id.ToString());
        command.ExecuteNonQuery();
    }
    public IReadOnlyList<(Lease Lease, JobReceipt? Receipt)> Pending()
    {
        using var command = db.CreateCommand();
        command.CommandText = "SELECT lease,receipt FROM receipts WHERE acknowledged=0";
        using var reader = command.ExecuteReader();
        var rows = new List<(Lease, JobReceipt?)>();
        while (reader.Read()) rows.Add((JsonSerializer.Deserialize<Lease>(reader.GetString(0), Protocol.Json)!,
            reader.IsDBNull(1) ? null : JsonSerializer.Deserialize<JobReceipt>(reader.GetString(1), Protocol.Json)));
        return rows;
    }
    public void ReserveSequence(string package, long sequence)
    {
        using var command = db.CreateCommand();
        command.CommandText = """
            INSERT INTO sequences(package,sequence) VALUES($package,$sequence)
            ON CONFLICT(package) DO UPDATE SET sequence=excluded.sequence WHERE excluded.sequence>sequences.sequence
            """;
        command.Parameters.AddWithValue("$package", package);
        command.Parameters.AddWithValue("$sequence", sequence);
        if (command.ExecuteNonQuery() != 1) throw new InvalidDataException("Release sequence replay or downgrade rejected");
    }
    public void Dispose() => db.Dispose();
}
