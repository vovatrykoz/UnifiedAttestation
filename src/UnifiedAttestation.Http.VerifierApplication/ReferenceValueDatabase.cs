using Microsoft.Data.Sqlite;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.Http.VerifierApplication;

public record DatabaseEntry(Guid Id, string Name, TpmReferenceValues Value);

public class ReferenceValueDatabase
{
    private readonly string _connectionString;

    private ReferenceValueDatabase(string connectionString)
    {
        _connectionString = connectionString;
    }

    public static ReferenceValueDatabase Initialize()
    {
        string dbPath = Path.Combine(AppContext.BaseDirectory, "mydatabase.db");
        string connectionString = new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString();

        using var connection = new SqliteConnection(connectionString);
        connection.Open();

        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS ReferenceDataTable (
                EntryId INTEGER PRIMARY KEY AUTOINCREMENT,
                Id TEXT NOT NULL UNIQUE,
                Name TEXT NOT NULL,
                JsonReferenceData TEXT NOT NULL
            );
            """;

        command.ExecuteNonQuery();

        return new ReferenceValueDatabase(connectionString);
    }

    public DatabaseEntry[] GetManyReferenceValues(int count)
    {
        if (count <= 0)
        {
            return [];
        }

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT Id, Name, JsonReferenceData
            FROM ReferenceDataTable
            LIMIT $count;
            """;

        command.Parameters.AddWithValue("$count", count);

        using SqliteDataReader reader = command.ExecuteReader();

        var results = new List<DatabaseEntry>();

        while (reader.Read())
        {
            string idText = reader.GetString(0);
            string name = reader.GetString(1);
            string json = reader.GetString(2);

            if (!Guid.TryParse(idText, out Guid id))
            {
                continue;
            }

            var value = TpmReferenceValues.ParseFromJson(json);
            results.Add(new DatabaseEntry(id, name, value));
        }

        return results.ToArray();
    }

    public DatabaseEntry? GetReferenceValues(Guid id)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT Name, JsonReferenceData
            FROM ReferenceDataTable
            WHERE Id = $id;
            """;

        command.Parameters.AddWithValue("$id", id.ToString());

        using SqliteDataReader reader = command.ExecuteReader();

        if (!reader.Read())
            return null;

        string name = reader.GetString(0);
        string json = reader.GetString(1);
        var value = TpmReferenceValues.ParseFromJson(json);

        return new DatabaseEntry(id, name, value);
    }

    public void Add(Guid id, string name, string jsonData)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ReferenceDataTable (Id, Name, JsonReferenceData)
            VALUES ($id, $name, $json);
            """;

        command.Parameters.AddWithValue("$id", id.ToString());
        command.Parameters.AddWithValue("$name", name);
        command.Parameters.AddWithValue("$json", jsonData);

        command.ExecuteNonQuery();
    }

    public void AddOrReplace(Guid id, string name, string jsonData)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            INSERT OR REPLACE INTO ReferenceDataTable (Id, Name, JsonReferenceData)
            VALUES ($id, $name, $json);
            """;

        command.Parameters.AddWithValue("$id", id.ToString());
        command.Parameters.AddWithValue("$name", name);
        command.Parameters.AddWithValue("$json", jsonData);

        command.ExecuteNonQuery();
    }

    public void Replace(Guid id, string name, string jsonData)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ReferenceDataTable (Id, Name, JsonReferenceData)
            VALUES ($id, $name, $json);
            """;

        command.Parameters.AddWithValue("$id", id.ToString());
        command.Parameters.AddWithValue("$name", name);
        command.Parameters.AddWithValue("$json", jsonData);

        command.ExecuteNonQuery();
    }

    public bool Delete(Guid id)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            DELETE FROM ReferenceDataTable
            WHERE Id = $id;
            """;

        command.Parameters.AddWithValue("$id", id.ToString());

        int affectedRows = command.ExecuteNonQuery();
        return affectedRows == 1;
    }
}
