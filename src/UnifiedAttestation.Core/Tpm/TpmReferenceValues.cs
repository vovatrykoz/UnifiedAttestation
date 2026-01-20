using System.Security.Cryptography;
using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core.Tpm;

public record TpmReferenceDigest(HashAlgorithmName Algorithm, uint PcrIndex, uint Event, byte[][] ExpectedDigests);

public class TpmReferenceValues(IEnumerable<TpmReferenceDigest> digests) : IReferenceValue
{
    public List<TpmReferenceDigest> Digests { get; } = digests.ToList();

    public byte[][]? GetExpectedPcrValues(HashAlgorithmName algorithm, uint pcrIndex, uint eventCode) =>
        Digests
            .FirstOrDefault(d => d.Algorithm == algorithm && d.PcrIndex == pcrIndex && d.Event == eventCode)
            ?.ExpectedDigests;
}
