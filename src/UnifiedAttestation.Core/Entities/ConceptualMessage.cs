namespace UnifiedAttestation.Core.Entities;

public abstract class ConceptualMessage;

public abstract class ReferenceValue : ConceptualMessage;

public abstract class Endorsement : ConceptualMessage;

public abstract class Evidence : ConceptualMessage;

public abstract class AttestationResult : ConceptualMessage;

public abstract class AppraisalPolicy : ConceptualMessage;
