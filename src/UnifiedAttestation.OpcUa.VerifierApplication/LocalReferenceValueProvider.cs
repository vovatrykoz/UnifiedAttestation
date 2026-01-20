using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.OpcUa.VerifierApplication;

public class LocalReferenceValueProvider(Dictionary<Guid, TpmReferenceValues> pathResolver)
    : IReferenceValueProvider<TpmReferenceValues>
{
    private readonly Dictionary<Guid, TpmReferenceValues> _pathResolver = pathResolver;

    public async Task<TpmReferenceValues> GetReferenceValuesAsync(
        Guid entityId,
        CancellationToken cancellationToken = default
    ) => _pathResolver[entityId];
}
