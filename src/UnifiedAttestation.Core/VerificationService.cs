using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core;

public interface IEndorsementProvider<T>
    where T : IEndorsement
{
    Task<T> GetEndorsementAsync(Guid entityId, CancellationToken cancellationToken = default);
}

public interface IReferenceValueProvider<T>
    where T : IReferenceValue
{
    Task<T> GetReferenceValuesAsync(Guid entityId, CancellationToken cancellationToken = default);
}

public interface IEvidenceAppraisalPolicy<TEvidence, TEndorsement, TReferenceValue, TResult> : IAppraisalPolicy
    where TEvidence : IEvidence
    where TEndorsement : IEndorsement
    where TReferenceValue : IReferenceValue
    where TResult : IAttestationResult
{
    Task<TResult> AppraiseAsync(
        TEvidence evidence,
        byte[] nonce,
        TEndorsement endorsements,
        TReferenceValue referenceValues,
        CancellationToken cancellationToken = default
    );
}

public class VerificationService<TEvidence, TEndorsement, TReferenceValue, TResult>(
    IEndorsementProvider<TEndorsement> endorsementProvider,
    IReferenceValueProvider<TReferenceValue> referenceValueProvider,
    IEvidenceAppraisalPolicy<TEvidence, TEndorsement, TReferenceValue, TResult> evidenceAppraisalPolicy
)
    where TEvidence : IEvidence
    where TEndorsement : IEndorsement
    where TReferenceValue : IReferenceValue
    where TResult : IAttestationResult
{
    public IEndorsementProvider<TEndorsement> EndorsementProvider { get; } = endorsementProvider;

    public IReferenceValueProvider<TReferenceValue> ReferenceValueProvider { get; } = referenceValueProvider;

    public IEvidenceAppraisalPolicy<
        TEvidence,
        TEndorsement,
        TReferenceValue,
        TResult
    > EvidenceAppraisalPolicy { get; } = evidenceAppraisalPolicy;

    public async Task<TResult> VerifyAsync(
        Guid entityId,
        TEvidence evidence,
        byte[] nonce,
        CancellationToken cancellationToken = default
    )
    {
        TEndorsement endorsements = await EndorsementProvider.GetEndorsementAsync(entityId, cancellationToken);
        TReferenceValue referenceValues = await ReferenceValueProvider.GetReferenceValuesAsync(
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
