using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core.Tpm;

public class TpmEvidence(TpmQuote quote, byte[] quoteSignature, IEventLog eventLog) : IEvidence
{
    public TpmQuote Quote { get; } = quote;

    public byte[] QuoteSignature { get; } = quoteSignature;

    public IEventLog Log { get; } = eventLog;
}
