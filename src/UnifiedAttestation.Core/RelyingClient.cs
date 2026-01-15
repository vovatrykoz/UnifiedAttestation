using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core;

public interface IAttesterClient
{
    Task<IEvidence> RequestEvidenceAsync(Guid entityId, byte[] nonce, CancellationToken cancellationToken = default);
}

public interface IVerifierClient
{
    Task<IAttestationResult> VerifyEvidenceAsync(
        Guid entityId,
        IEvidence evidence,
        byte[] nonce,
        CancellationToken cancellationToken = default
    );
}

public interface IResultAppraisalPolicy : IAppraisalPolicy
{
    Task AppraiseAsync(Guid entityId, IAttestationResult result, CancellationToken cancellationToken = default);
}

public interface INonceProvider
{
    Task<byte[]> GetFreshNonceAsync(CancellationToken cancellationToken = default);
}

public class RelyingClient(
    IAttesterClient attesterClient,
    IVerifierClient verifierClient,
    IResultAppraisalPolicy resultAppraisalPolicy,
    INonceProvider nonceProvider
)
{
    public IAttesterClient AttesterClient { get; } = attesterClient;

    public IVerifierClient VerifierClient { get; } = verifierClient;

    public IResultAppraisalPolicy ResultAppraisalPolicy { get; } = resultAppraisalPolicy;

    public INonceProvider NonceProvider { get; } = nonceProvider;

    public async Task VerifyAsync(Guid entityId, CancellationToken cancellationToken = default)
    {
        byte[] nonce = await NonceProvider.GetFreshNonceAsync(cancellationToken);
        IEvidence evidence = await AttesterClient.RequestEvidenceAsync(entityId, nonce, cancellationToken);
        IAttestationResult result = await VerifierClient.VerifyEvidenceAsync(
            entityId,
            evidence,
            nonce,
            cancellationToken
        );
        await ResultAppraisalPolicy.AppraiseAsync(entityId, result, cancellationToken);
    }
}
