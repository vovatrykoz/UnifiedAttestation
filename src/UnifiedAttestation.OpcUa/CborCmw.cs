namespace UnifiedAttestation.OpcUa;

public enum CoapContentIds : ushort
{
    CborId = 60,
    CwtId = 61,
    EatCwtId = 263,
    EatJwtId = 264,
    EatUcsCborId = 267,
    EatUcsJsonId = 268,
}

public record CborCmw(ushort ContentId, byte[] Value, ConceptualMessageTypes CmType)
{
    public override string ToString()
    {
        string hexValue = BitConverter.ToString(Value);
        return $"ContentId: {ContentId},\nValue: {hexValue},\nCmType: {CmType}";
    }
}
