namespace UnifiedAttestation.OpcUa;

public interface IAttestingEnvironment
{
    public CborCmw GetAttestationData(byte[] nonce);
}
