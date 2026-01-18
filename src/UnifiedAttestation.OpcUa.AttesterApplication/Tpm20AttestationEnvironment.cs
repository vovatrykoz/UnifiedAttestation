using System.Security.Cryptography;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.OpcUa.AttesterApplication;

public class Tpm20AttestationEnvironment : IAttestingEnvironment
{
    public CborCmw GetAttestationData(byte[] nonce)
    {
        byte[] keyName = [1, 2, 3];
        var pcrSelection = new PcrSelection(HashAlgorithmName.SHA256, 0b1111111);
        byte[] digest = SHA256.HashData(keyName);

        byte[] quote = new Tpm20Quote(keyName, nonce, pcrSelection, digest).GetRawBytes();
        return new CborCmw(60, quote, ConceptualMessageTypes.Evidence);
    }
}
