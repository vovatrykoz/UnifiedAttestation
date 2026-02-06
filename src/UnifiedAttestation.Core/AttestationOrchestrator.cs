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
    public IAttesterClient AttesterClient { get; } = attesterClient;

    public IVerifierClient<TResult> VerifierClient { get; } = verifierClient;

    public IResultAppraisalPolicy<TResult> ResultAppraisalPolicy { get; } = resultAppraisalPolicy;

    public INonceProvider NonceProvider { get; } = nonceProvider;

    public async Task VerifyAsync(Guid entityId, CancellationToken cancellationToken = default)
    {
        byte[] nonce = await NonceProvider.GetFreshNonceAsync(cancellationToken);
        CborCmw evidence = await AttesterClient.RequestEvidenceAsync(entityId, nonce, cancellationToken);
        TResult result = await VerifierClient.VerifyEvidenceAsync(entityId, evidence, nonce, cancellationToken);
        await ResultAppraisalPolicy.AppraiseAsync(entityId, result, cancellationToken);
    }
}
