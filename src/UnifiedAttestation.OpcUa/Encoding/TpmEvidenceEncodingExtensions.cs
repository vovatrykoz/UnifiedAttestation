using System.Formats.Cbor;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.OpcUa.Encoding;

public static class TpmEvidenceEncodingExtensions
{
    extension(TpmEvidence evidence)
    {
        public byte[] Encode()
        {
            if (evidence.Quote is not Tpm20Quote tpmQuote)
            {
                throw new NotSupportedException(
                    $"Unsupported quote type '{evidence.Quote?.GetType().Name ?? "<null>"}'. "
                        + $"Only 'Tpm20Quote' is currently supported."
                );
            }

            if (evidence.Log is not TcgEventLog eventLog)
            {
                throw new NotSupportedException(
                    $"Unsupported event log type '{evidence.Log?.GetType().Name ?? "<null>"}'. "
                        + $"Only 'TcgEventLog' is currently supported."
                );
            }

            byte[] quoteBytes = tpmQuote.GetRawBytes();
            byte[] logBytes = eventLog.Encode();

            var writer = new CborWriter();

            writer.WriteStartArray(3);

            writer.WriteByteString(quoteBytes);
            writer.WriteByteString(evidence.QuoteSignature);
            writer.WriteByteString(logBytes);

            writer.WriteEndArray();

            return writer.Encode();
        }

        public static TpmEvidence Decode(ReadOnlyMemory<byte> encoding)
        {
            var reader = new CborReader(encoding);

            int? length = reader.ReadStartArray();
            if (length is not 3)
                throw new FormatException($"Expected CBOR array of length 3 but got {length}.");

            byte[] quoteBytes = reader.ReadByteString();
            var quote = Tpm20Quote.FromRawBytes(quoteBytes);

            byte[] signature = reader.ReadByteString();

            byte[] logBytes = reader.ReadByteString();
            TcgEventLog eventLog = TcgEventLog.Decode(logBytes);

            return new TpmEvidence(quote, signature, eventLog);
        }
    }
}
