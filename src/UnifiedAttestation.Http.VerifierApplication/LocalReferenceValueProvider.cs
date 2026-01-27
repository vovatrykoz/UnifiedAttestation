using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.Http.VerifierApplication;

public class LocalReferenceValueProvider(ReferenceValueDatabase database) : IReferenceValueProvider<TpmReferenceValues>
{
    private readonly ReferenceValueDatabase _database = database;

    public async Task<TpmReferenceValues> GetReferenceValuesAsync(
        Guid entityId,
        CancellationToken cancellationToken = default
    )
    {
        DatabaseEntry? result =
            _database.GetReferenceValues(entityId)
            ?? throw new KeyNotFoundException($"No entry found for entity id {entityId}");

        return result.Value;
    }
}
