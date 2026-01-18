using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core.Tpm;

public class TpmEvidence(ITpmQuote quote, byte[] quoteSignature, IEventLog eventLog) : IEvidence
{
    public ITpmQuote Quote { get; } = quote;

    public byte[] QuoteSignature { get; } = quoteSignature;

    public IEventLog Log { get; } = eventLog;
}
