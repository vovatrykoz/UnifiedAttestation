using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.OpcUa.VerifierApplication;

public class LocalReferenceValueProvider(Dictionary<Guid, TpmReferenceValues> referenceDb)
    : IReferenceValueProvider<TpmReferenceValues>
{
    private readonly Dictionary<Guid, TpmReferenceValues> _referenceDb = referenceDb;

    public async Task<TpmReferenceValues> GetReferenceValuesAsync(
        Guid entityId,
        CancellationToken cancellationToken = default
    ) => _referenceDb[entityId];
}
