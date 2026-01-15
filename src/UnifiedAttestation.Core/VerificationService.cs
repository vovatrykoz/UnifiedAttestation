using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core;

public interface IEndorsementProvider
{
    Task<Endorsement> GetEndorsementAsync(Guid entityId);
}

public interface IReferenceValueProvider
{
    Task<ReferenceValue> GetReferenceValuesAsync(Guid entityId);
}

public interface IEvidenceAppraisalPolicy
{
    Task<AttestationResult> AppraiseAsync(
        Evidence evidence,
        byte[] nonce,
        Endorsement endorsements,
        ReferenceValue referenceValues
    );
}

public class VerificationService(
    IEndorsementProvider endorsementProvider,
    IReferenceValueProvider referenceValueProvider,
    IEvidenceAppraisalPolicy evidenceAppraisalPolicy
)
{
    public IEndorsementProvider EndorsementProvider { get; } = endorsementProvider;

    public IReferenceValueProvider ReferenceValueProvider { get; } = referenceValueProvider;

    public IEvidenceAppraisalPolicy EvidenceAppraisalPolicy { get; } = evidenceAppraisalPolicy;

    public async Task<AttestationResult> VerifyAsync(Guid entityId, Evidence evidence, byte[] nonce)
    {
        Endorsement endorsements = await EndorsementProvider.GetEndorsementAsync(entityId);
        ReferenceValue referenceValues = await ReferenceValueProvider.GetReferenceValuesAsync(entityId);
        return await EvidenceAppraisalPolicy.AppraiseAsync(evidence, nonce, endorsements, referenceValues);
    }
}
