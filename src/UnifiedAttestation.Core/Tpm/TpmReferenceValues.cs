using System.Security.Cryptography;
using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core.Tpm;

public record TpmReferenceDigest(HashAlgorithmName Algorithm, uint PcrIndex, byte[][] ExpectedPcrValue);

public class TpmReferenceValues(IEnumerable<TpmReferenceDigest> digests) : IReferenceValue
{
    public List<TpmReferenceDigest> Digests { get; } = digests.ToList();

    public byte[][]? GetExpectedPcrValues(HashAlgorithmName algorithm, uint pcrIndex) =>
        Digests.FirstOrDefault(d => d.Algorithm == algorithm && d.PcrIndex == pcrIndex)?.ExpectedPcrValue;
}
