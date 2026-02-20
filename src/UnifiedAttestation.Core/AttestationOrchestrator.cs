using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core;

public interface IAttesterClient
{
    Task<CborCmw> RequestEvidenceAsync(Guid entityId, byte[] nonce, CancellationToken cancellationToken = default);
}

public interface IVerifierClient<TResult>
    where TResult : IAttestationResult
{
    Task<TResult> VerifyEvidenceAsync(
        Guid entityId,
        CborCmw evidence,
        byte[] nonce,
        CancellationToken cancellationToken = default
    );
}

public interface IResultAppraisalPolicy<T> : IAppraisalPolicy
    where T : IAttestationResult
{
    Task AppraiseAsync(Guid entityId, T result, CancellationToken cancellationToken = default);
}

public interface INonceProvider
{
    Task<byte[]> GetFreshNonceAsync(CancellationToken cancellationToken = default);
}

public class AttestationOrchestrator<TResult>(
    IAttesterClient attesterClient,
    IVerifierClient<TResult> verifierClient,
    IResultAppraisalPolicy<TResult> resultAppraisalPolicy,
    INonceProvider nonceProvider
)
    where TResult : IAttestationResult
{
    private readonly IAttesterClient _attesterClient = attesterClient;

    private readonly IVerifierClient<TResult> _verifierClient = verifierClient;

    private readonly IResultAppraisalPolicy<TResult> _resultAppraisalPolicy = resultAppraisalPolicy;

    private readonly INonceProvider _nonceProvider = nonceProvider;

    public async Task VerifyAsync(Guid entityId, CancellationToken cancellationToken = default)
    {
        byte[] nonce = await _nonceProvider.GetFreshNonceAsync(cancellationToken);
        CborCmw evidence = await _attesterClient.RequestEvidenceAsync(entityId, nonce, cancellationToken);
        TResult result = await _verifierClient.VerifyEvidenceAsync(entityId, evidence, nonce, cancellationToken);
        await _resultAppraisalPolicy.AppraiseAsync(entityId, result, cancellationToken);
    }
}
