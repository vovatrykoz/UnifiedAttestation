using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core;

public interface IEndorsementProvider
{
    Task<IEndorsement> GetEndorsementAsync(Guid entityId, CancellationToken cancellationToken = default);
}

public interface IReferenceValueProvider
{
    Task<IReferenceValue> GetReferenceValuesAsync(Guid entityId, CancellationToken cancellationToken = default);
}

public interface IEvidenceAppraisalPolicy : IAppraisalPolicy
{
    Task<IAttestationResult> AppraiseAsync(
        IEvidence evidence,
        byte[] nonce,
        IEndorsement endorsements,
        IReferenceValue referenceValues,
        CancellationToken cancellationToken = default
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

    public async Task<IAttestationResult> VerifyAsync(
        Guid entityId,
        IEvidence evidence,
        byte[] nonce,
        CancellationToken cancellationToken = default
    )
    {
        IEndorsement endorsements = await EndorsementProvider.GetEndorsementAsync(entityId, cancellationToken);
        IReferenceValue referenceValues = await ReferenceValueProvider.GetReferenceValuesAsync(
            entityId,
            cancellationToken
        );

        return await EvidenceAppraisalPolicy.AppraiseAsync(
            evidence,
            nonce,
            endorsements,
            referenceValues,
            cancellationToken
        );
    }
}
