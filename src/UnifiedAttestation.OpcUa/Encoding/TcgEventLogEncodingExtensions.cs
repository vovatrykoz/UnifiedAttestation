using System.Formats.Cbor;
using System.Security.Cryptography;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.OpcUa.Encoding;

public static class TcgEventLogEncodingExtensions
{
    extension(TcgEventLog log)
    {
        public byte[] Encode()
        {
            var writer = new CborWriter(CborConformanceMode.Canonical);

            writer.WriteStartArray(log.Entries.Count);

            foreach (TcgEventLogEntry entry in log.Entries)
            {
                WriteEntry(writer, entry);
            }

            writer.WriteEndArray();
            return writer.Encode();
        }

        public static TcgEventLog Decode(byte[] cbor)
        {
            var reader = new CborReader(cbor, CborConformanceMode.Canonical);

            int entryCount =
                reader.ReadStartArray() ?? throw new InvalidOperationException("Entry array size was null");
            var entries = new List<TcgEventLogEntry>(entryCount);

            for (int i = 0; i < entryCount; i++)
            {
                entries.Add(ReadEntry(reader));
            }

            reader.ReadEndArray();
            return new TcgEventLog(entries);
        }
    }

    private static void WriteEntry(CborWriter writer, TcgEventLogEntry entry)
    {
        writer.WriteStartArray(4);

        writer.WriteUInt32(entry.PcrIndex);
        writer.WriteUInt32(entry.EventType);

        writer.WriteStartArray(entry.Digests.Length);
        foreach (Digest digest in entry.Digests)
        {
            WriteDigest(writer, digest);
        }
        writer.WriteEndArray();

        writer.WriteByteString(entry.Event);

        writer.WriteEndArray();
    }

    private static void WriteDigest(CborWriter writer, Digest digest)
    {
        writer.WriteStartArray(2);

        writer.WriteTextString(
            digest.AlgorithmName.Name ?? throw new InvalidOperationException("HashAlgorithmName has no Name")
        );

        writer.WriteByteString(digest.Bytes);

        writer.WriteEndArray();
    }

    private static TcgEventLogEntry ReadEntry(CborReader reader)
    {
        reader.ReadStartArray();

        uint pcrIndex = reader.ReadUInt32();
        uint eventType = reader.ReadUInt32();

        int digestCount = reader.ReadStartArray() ?? throw new InvalidOperationException("Digest array size was null");
        var digests = new Digest[digestCount];

        for (int i = 0; i < digestCount; i++)
        {
            digests[i] = ReadDigest(reader);
        }

        reader.ReadEndArray();

        byte[] evt = reader.ReadByteString();

        reader.ReadEndArray();

        return new TcgEventLogEntry(pcrIndex, eventType, digests, evt);
    }

    private static Digest ReadDigest(CborReader reader)
    {
        reader.ReadStartArray();

        string algorithmName = reader.ReadTextString();
        byte[] bytes = reader.ReadByteString();

        reader.ReadEndArray();

        return new Digest(new HashAlgorithmName(algorithmName), bytes);
    }
}
