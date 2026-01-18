namespace UnifiedAttestation.OpcUa;

[Flags]
public enum ConceptualMessageTypes
{
    ReferenceValue = 0b00001,
    Endorsement = 0b00010,
    Evidence = 0b00100,
    AttestationResult = 0b01000,
    AppraisalPolicy = 0b10000,
}
