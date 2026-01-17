using System.Security.Cryptography;

namespace UnifiedAttestation.Core.Tpm;

public interface IEventLog
{
    byte[] Replay(HashAlgorithmName algorithmName, uint pcrIndex);
}

public record Digest(HashAlgorithmName AlgorithmName, byte[] Bytes);

public record TcgEventLogEntry(uint PcrIndex, uint EventType, Digest[] Digests, byte[] Event);

public class TcgEventLog(IEnumerable<TcgEventLogEntry> entries) : IEventLog
{
    public List<TcgEventLogEntry> Entries { get; } = entries.ToList();

    public byte[] Replay(HashAlgorithmName algorithm, uint pcrIndex)
    {
        using HashAlgorithm hashAlgorithm = GetHashAlgorithm(algorithm);
        byte[] pcr = new byte[hashAlgorithm.HashSize / 8];

        foreach (TcgEventLogEntry entry in Entries)
        {
            if (entry.PcrIndex != pcrIndex)
            {
                continue;
            }

            Digest? digest = entry.Digests.FirstOrDefault(d => d.AlgorithmName == algorithm);

            if (digest == null)
            {
                continue;
            }

            byte[] extended = new byte[pcr.Length + digest.Bytes.Length];
            Buffer.BlockCopy(pcr, 0, extended, 0, pcr.Length);
            Buffer.BlockCopy(digest.Bytes, 0, extended, pcr.Length, digest.Bytes.Length);

            pcr = hashAlgorithm.ComputeHash(extended);
        }

        return pcr;
    }

    public static TcgEventLog Empty => new([]);

    private static HashAlgorithm GetHashAlgorithm(HashAlgorithmName algorithm) =>
        algorithm switch
        {
            var a when a == HashAlgorithmName.MD5 => MD5.Create(),
            var a when a == HashAlgorithmName.SHA256 => SHA256.Create(),
            var a when a == HashAlgorithmName.SHA512 => SHA512.Create(),
            _ => throw new NotSupportedException($"Hash algorithm '{algorithm.Name ?? "<null>"}' is not supported."),
        };
}
