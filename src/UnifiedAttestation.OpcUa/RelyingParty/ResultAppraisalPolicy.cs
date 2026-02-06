using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.OpcUa.RelyingParty;

public enum EntityAttestationStatus
{
    Passed,
    Failed,
    Unknown,
}

public record EntityAttestationData(string Name, EntityAttestationStatus Status, TpmAttestationResult Details);

public class ResultAppraisalPolicy(Dictionary<Guid, EntityAttestationData> statusDb)
    : IResultAppraisalPolicy<TpmAttestationResult>
{
    public readonly Dictionary<Guid, EntityAttestationData> _statusDb = statusDb;

    public async Task AppraiseAsync(
        Guid entityId,
        TpmAttestationResult result,
        CancellationToken cancellationToken = default
    )
    {
        EntityAttestationStatus newStatus = result switch
        {
            not TpmVerificationReport => EntityAttestationStatus.Failed,
            TpmVerificationReport r when r.Entries.All(e => e is TpmEntryCheckPassed) => EntityAttestationStatus.Passed,
            TpmVerificationReport r when r.Entries.Any(e => e is TpmEntryCheckFailed) => EntityAttestationStatus.Failed,
            _ => EntityAttestationStatus.Unknown,
        };

        _statusDb[entityId] = _statusDb[entityId] with { Status = newStatus, Details = result };
    }
}
