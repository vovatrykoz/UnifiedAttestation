namespace UnifiedAttestation.Core;

public enum CoapContentIds : ushort
{
    CborId = 60,
    CwtId = 61,
    EatCwtId = 263,
    EatJwtId = 264,
    EatUcsCborId = 267,
    EatUcsJsonId = 268,
}

public abstract record ConceptualMessageWrapper;

public record JsonCmw(string MediaType, string Value, ConceptualMessageTypes CmType) : ConceptualMessageWrapper;

public record CborCmw(ushort ContentId, byte[] Value, ConceptualMessageTypes CmType) : ConceptualMessageWrapper
{
    public override string ToString()
    {
        string hexValue = BitConverter.ToString(Value);
        return $"ContentId: {ContentId},\nValue: {hexValue},\nCmType: {CmType}";
    }
}
