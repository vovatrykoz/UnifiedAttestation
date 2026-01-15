using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core.Tpm;

public class TpmEvidence(TpmQuote quote, byte[] quoteSignature, EventLog eventLog, byte[] eventLogSignature) : IEvidence
{
    public TpmQuote Quote { get; } = quote;

    public byte[] QuoteSignature { get; } = quoteSignature;

    public EventLog Log { get; } = eventLog;

    public byte[] LogSignature { get; } = eventLogSignature;
}
