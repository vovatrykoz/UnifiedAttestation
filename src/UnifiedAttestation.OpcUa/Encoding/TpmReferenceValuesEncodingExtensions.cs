using System.Formats.Cbor;
using System.Security.Cryptography;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.OpcUa.Encoding;

public static class TpmReferenceValuesEncodingExtensions
{
    extension(TpmReferenceValues referenceValues)
    {
        public byte[] Encode()
        {
            var writer = new CborWriter(CborConformanceMode.Strict);

            writer.WriteStartArray(referenceValues.Digests.Count);

            foreach (var digest in referenceValues.Digests)
            {
                EncodeDigest(writer, digest);
            }

            writer.WriteEndArray();
            return writer.Encode();
        }

        public static TpmReferenceValues FromBytes(byte[] bytes)
        {
            var reader = new CborReader(bytes, CborConformanceMode.Strict);

            reader.ReadStartArray();

            var digests = new List<TpmReferenceDigest>();
            while (reader.PeekState() != CborReaderState.EndArray)
            {
                digests.Add(DecodeDigest(reader));
            }

            reader.ReadEndArray();

            if (reader.BytesRemaining != 0)
                throw new FormatException("Extra bytes at end of CBOR payload");

            return new TpmReferenceValues(digests);
        }
    }

    private static void EncodeDigest(CborWriter writer, TpmReferenceDigest digest)
    {
        writer.WriteStartArray(3);

        writer.WriteTextString(
            digest.Algorithm.Name ?? throw new InvalidOperationException("HashAlgorithmName has no name")
        );

        writer.WriteUInt32(digest.PcrIndex);

        writer.WriteStartArray(digest.ExpectedPcrValue.Length);
        foreach (byte[] value in digest.ExpectedPcrValue)
        {
            writer.WriteByteString(value);
        }
        writer.WriteEndArray();

        writer.WriteEndArray();
    }

    private static TpmReferenceDigest DecodeDigest(CborReader reader)
    {
        reader.ReadStartArray();

        string algorithmName = reader.ReadTextString();
        var algorithm = new HashAlgorithmName(algorithmName);

        uint pcrIndex = reader.ReadUInt32();

        reader.ReadStartArray();
        var expectedValues = new List<byte[]>();
        while (reader.PeekState() != CborReaderState.EndArray)
        {
            expectedValues.Add(reader.ReadByteString());
        }
        reader.ReadEndArray();

        reader.ReadEndArray();

        return new TpmReferenceDigest(algorithm, pcrIndex, expectedValues.ToArray());
    }
}
