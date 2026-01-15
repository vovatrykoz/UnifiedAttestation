using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core;

public interface IAttesterClient
{
    Task<Evidence> RequestEvidenceAsync(Guid entityId, byte[] nonce);
}

public interface IVerifierClient
{
    Task<AttestationResult> VerifyEvidenceAsync(Guid entityId, Evidence evidence, byte[] nonce);
}

public interface IResultAppraisalPolicy
{
    Task Appraise(Guid entityId, AttestationResult result);
}

public interface INonceProvider
{
    Task<byte[]> GetFreshNonceAsync();
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

    public async Task VerifyAsync(Guid entityId)
    {
        byte[] nonce = await NonceProvider.GetFreshNonceAsync();
        Evidence evidence = await AttesterClient.RequestEvidenceAsync(entityId, nonce);
        AttestationResult result = await VerifierClient.VerifyEvidenceAsync(entityId, evidence, nonce);
        await ResultAppraisalPolicy.Appraise(entityId, result);
    }
}
