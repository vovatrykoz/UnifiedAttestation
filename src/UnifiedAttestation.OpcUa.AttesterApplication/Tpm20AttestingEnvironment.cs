using System.Security.Cryptography;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.OpcUa.Encoding;

namespace UnifiedAttestation.OpcUa.AttesterApplication;

public class Tpm20AttestingEnvironment(MockTpm20 tpm, TcgEventLog eventLog) : IAttestingEnvironment
{
    private readonly TcgEventLog _eventLog = eventLog;

    private readonly MockTpm20 _tpm = tpm;

    public CborCmw GetAttestationData(byte[] nonce)
    {
        byte[] keyName = [1, 2, 3, 4];
        int[] pcrIndices = [0, 1, 2, 3, 4, 5, 6, 7];
        QuoteCommandResponse tpmResponse = _tpm.GetQuote(keyName, HashAlgorithmName.SHA256, pcrIndices, nonce);

        byte[] evidence = new TpmEvidence(tpmResponse.Quote, tpmResponse.Signature, _eventLog).Encode();
        return new CborCmw((ushort)CoapContentIds.CborId, evidence, ConceptualMessageTypes.Evidence);
    }
}
