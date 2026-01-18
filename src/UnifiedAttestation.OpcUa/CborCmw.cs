namespace UnifiedAttestation.OpcUa;

public record CborCmw(ushort ContentId, byte[] Value, ConceptualMessageTypes CmType)
{
    public override string ToString()
    {
        string hexValue = BitConverter.ToString(Value);
        return $"ContentId: {ContentId},\nValue: {hexValue},\nCmType: {CmType}";
    }
}
