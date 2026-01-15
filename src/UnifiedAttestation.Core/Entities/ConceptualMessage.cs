namespace UnifiedAttestation.Core.Entities;

public interface IConceptualMessage;

public interface IReferenceValue : IConceptualMessage;

public interface IEndorsement : IConceptualMessage;

public interface IEvidence : IConceptualMessage;

public interface IAttestationResult : IConceptualMessage;

public interface IAppraisalPolicy : IConceptualMessage;
