using System.Formats.Cbor;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.OpcUa.Encoding;

internal static class TpmResultEncoding
{
    public const int NonceMismatch = 100;
    public const int QuoteSignatureCheckFailed = 101;
    public const int ReplayFailed = 102;

    public const int EntryCheckPassed = 200;
    public const int EntryCheckFailed = 201;
    public const int EntryCheckUnknown = 202;

    public const int VerificationReport = 300;
}

public static class TpmResultEncodingExtensions
{
    extension(TpmAttestationResult result)
    {
        public byte[] Encode() =>
            result switch
            {
                TpmNonceMismatch => EncodeSimple(TpmResultEncoding.NonceMismatch),
                TpmQuoteSignatureCheckFailed => EncodeSimple(TpmResultEncoding.QuoteSignatureCheckFailed),
                TpmReplayFailed => EncodeSimple(TpmResultEncoding.ReplayFailed),

                TpmEntryCheckPassed p => EncodeEntryCheckPassed(p),
                TpmEntryCheckFailed f => EncodeEntryCheckFailed(f),
                TpmEntryCheckUnkown u => EncodeEntryCheckUnknown(u),

                TpmVerificationReport r => EncodeVerificationReport(r),

                _ => throw new NotSupportedException($"The {result.GetType().Name} result type is not supported"),
            };

        public static TpmAttestationResult Decode(ReadOnlyMemory<byte> data)
        {
            var reader = new CborReader(data, CborConformanceMode.Strict);
            TpmAttestationResult decodedResult = DecodeResult(reader);

            if (reader.BytesRemaining != 0)
                throw new FormatException("Extra bytes at end of CBOR payload");

            return decodedResult;
        }
    }

    private static byte[] EncodeSimple(int typeId)
    {
        var writer = new CborWriter();
        writer.WriteStartArray(1);
        writer.WriteInt32(typeId);
        writer.WriteEndArray();
        return writer.Encode();
    }

    private static byte[] EncodeEntryCheckPassed(TpmEntryCheckPassed passed)
    {
        var writer = new CborWriter();

        writer.WriteStartArray(2);
        writer.WriteInt32(TpmResultEncoding.EntryCheckPassed);
        writer.WriteByteString(passed.Event);
        writer.WriteEndArray();

        return writer.Encode();
    }

    private static byte[] EncodeEntryCheckFailed(TpmEntryCheckFailed failed)
    {
        var writer = new CborWriter();

        writer.WriteStartArray(4);
        writer.WriteInt32(TpmResultEncoding.EntryCheckFailed);

        writer.WriteByteString(failed.Event);

        writer.WriteStartArray(failed.ExpectedHashes.Length);
        foreach (byte[] hash in failed.ExpectedHashes)
        {
            writer.WriteByteString(hash);
        }
        writer.WriteEndArray();

        if (failed.ActualHash is null)
            writer.WriteNull();
        else
            writer.WriteByteString(failed.ActualHash);

        writer.WriteEndArray();
        return writer.Encode();
    }

    private static byte[] EncodeEntryCheckUnknown(TpmEntryCheckUnkown unknown)
    {
        var writer = new CborWriter();

        writer.WriteStartArray(2);
        writer.WriteInt32(TpmResultEncoding.EntryCheckUnknown);
        writer.WriteByteString(unknown.Event);
        writer.WriteEndArray();

        return writer.Encode();
    }

    private static byte[] EncodeVerificationReport(TpmVerificationReport report)
    {
        var writer = new CborWriter();

        writer.WriteStartArray(2);
        writer.WriteInt32(TpmResultEncoding.VerificationReport);

        writer.WriteStartArray(report.Entries.Length);
        foreach (TpmEntryCheckResult entry in report.Entries)
        {
            byte[] encoded = entry.Encode();
            writer.WriteEncodedValue(encoded);
        }
        writer.WriteEndArray();

        writer.WriteEndArray();
        return writer.Encode();
    }

    private static TpmAttestationResult DecodeResult(CborReader reader)
    {
        reader.ReadStartArray();
        int typeId = reader.ReadInt32();

        return typeId switch
        {
            TpmResultEncoding.NonceMismatch => DecodeSimple(reader, () => new TpmNonceMismatch()),

            TpmResultEncoding.QuoteSignatureCheckFailed => DecodeSimple(
                reader,
                () => new TpmQuoteSignatureCheckFailed()
            ),

            TpmResultEncoding.ReplayFailed => DecodeSimple(reader, () => new TpmReplayFailed()),

            TpmResultEncoding.EntryCheckPassed => DecodeEntryCheckPassed(reader),

            TpmResultEncoding.EntryCheckFailed => DecodeEntryCheckFailed(reader),

            TpmResultEncoding.EntryCheckUnknown => DecodeEntryCheckUnknown(reader),

            TpmResultEncoding.VerificationReport => DecodeVerificationReport(reader),

            _ => throw new NotSupportedException($"Unknown TPM result type: {typeId}"),
        };
    }

    private static T DecodeSimple<T>(CborReader reader, Func<T> factory)
        where T : TpmAttestationResult
    {
        reader.ReadEndArray();
        return factory();
    }

    private static TpmEntryCheckPassed DecodeEntryCheckPassed(CborReader reader)
    {
        byte[] evt = reader.ReadByteString();
        reader.ReadEndArray();
        return new TpmEntryCheckPassed(evt);
    }

    private static TpmEntryCheckFailed DecodeEntryCheckFailed(CborReader reader)
    {
        byte[] evt = reader.ReadByteString();

        reader.ReadStartArray();
        var expected = new List<byte[]>();
        while (reader.PeekState() != CborReaderState.EndArray)
        {
            expected.Add(reader.ReadByteString());
        }
        reader.ReadEndArray();

        byte[]? actual;
        if (reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
            actual = null;
        }
        else
        {
            actual = reader.ReadByteString();
        }

        reader.ReadEndArray();

        return new TpmEntryCheckFailed(evt, expected.ToArray(), actual);
    }

    private static TpmEntryCheckUnkown DecodeEntryCheckUnknown(CborReader reader)
    {
        byte[] evt = reader.ReadByteString();
        reader.ReadEndArray();
        return new TpmEntryCheckUnkown(evt);
    }

    private static TpmVerificationReport DecodeVerificationReport(CborReader reader)
    {
        var entries = new List<TpmEntryCheckResult>();

        reader.ReadStartArray();
        while (reader.PeekState() != CborReaderState.EndArray)
        {
            TpmAttestationResult entry = DecodeResult(reader);
            if (entry is not TpmEntryCheckResult ecr)
                throw new FormatException("VerificationReport contains non-entry result");

            entries.Add(ecr);
        }
        reader.ReadEndArray();

        reader.ReadEndArray();
        return new TpmVerificationReport(entries.ToArray());
    }
}
