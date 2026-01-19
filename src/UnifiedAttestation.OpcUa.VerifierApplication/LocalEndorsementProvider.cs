using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.OpcUa.VerifierApplication;

public class LocalEndorsementProvider(Dictionary<Guid, string> pathResolver) : IEndorsementProvider<TpmEndorsement>
{
    private readonly Dictionary<Guid, string> _pathResolver = pathResolver;

    public async Task<TpmEndorsement> GetEndorsementAsync(Guid entityId, CancellationToken cancellationToken = default)
    {
        string path = _pathResolver[entityId];
        byte[] certBytes = await File.ReadAllBytesAsync(path, cancellationToken);
        return new TpmEndorsement(certBytes);
    }
}
