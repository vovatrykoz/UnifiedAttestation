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

public class VerificationOrchestrator<TEvidence, TEndorsement, TReferenceValue, TResult>(
    IEndorsementProvider<TEndorsement> endorsementProvider,
    IReferenceValueProvider<TReferenceValue> referenceValueProvider,
    IEvidenceAppraisalPolicy<TEvidence, TEndorsement, TReferenceValue, TResult> evidenceAppraisalPolicy
)
    where TEvidence : IEvidence
    where TEndorsement : IEndorsement
    where TReferenceValue : IReferenceValue
    where TResult : IAttestationResult
{
    private readonly IEndorsementProvider<TEndorsement> _endorsementProvider = endorsementProvider;

    private readonly IReferenceValueProvider<TReferenceValue> _referenceValueProvider = referenceValueProvider;

    private readonly IEvidenceAppraisalPolicy<
        TEvidence,
        TEndorsement,
        TReferenceValue,
        TResult
    > _evidenceAppraisalPolicy = evidenceAppraisalPolicy;

    public async Task<TResult> VerifyAsync(
        Guid entityId,
        TEvidence evidence,
        byte[] nonce,
        CancellationToken cancellationToken = default
    )
    {
        TEndorsement endorsements = await _endorsementProvider.GetEndorsementAsync(entityId, cancellationToken);
        TReferenceValue referenceValues = await _referenceValueProvider.GetReferenceValuesAsync(
            entityId,
            cancellationToken
        );

        return await _evidenceAppraisalPolicy.AppraiseAsync(
            evidence,
            nonce,
            endorsements,
            referenceValues,
            cancellationToken
        );
    }
}
