using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;

namespace UnifiedAttestation.Core.Tpm;

public interface ITpmQuote
{
    byte[] GetRawBytes();
}

public record PcrSelection(HashAlgorithmName Algorithm, int SelectionMask);

public record Tpm20Quote(byte[] KeyName, byte[] Nonce, PcrSelection PcrSelection, byte[] PcrDigest) : ITpmQuote
{
    public byte[] GetRawBytes()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        ushort algId = EncodeHashAlgorithm(PcrSelection.Algorithm);
        Span<byte> algEncoding = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(algEncoding, algId);

        writer.WriteStartArray(5);

        writer.WriteByteString(KeyName);
        writer.WriteByteString(Nonce);
        writer.WriteByteString(algEncoding);
        writer.WriteInt32(PcrSelection.SelectionMask);
        writer.WriteByteString(PcrDigest);

        writer.WriteEndArray();

        return writer.Encode();
    }

    private static ushort EncodeHashAlgorithm(HashAlgorithmName algorithm) =>
        algorithm switch
        {
            var a when a == HashAlgorithmName.SHA1 => 0x0004,
            var a when a == HashAlgorithmName.SHA256 => 0x000B,
            var a when a == HashAlgorithmName.SHA384 => 0x000C,
            var a when a == HashAlgorithmName.SHA512 => 0x000D,
            _ => throw new NotSupportedException(
                $"Hash algorithm '{algorithm.Name ?? "<null>"}' is not supported by TPM 2.0."
            ),
        };

    private static HashAlgorithmName DecodeHashAlgorithm(ushort algId) =>
        algId switch
        {
            0x0004 => HashAlgorithmName.SHA1,
            0x000B => HashAlgorithmName.SHA256,
            0x000C => HashAlgorithmName.SHA384,
            0x000D => HashAlgorithmName.SHA512,
            _ => throw new NotSupportedException($"Unsupported TPM hash algorithm ID: 0x{algId:X4}"),
        };
}
