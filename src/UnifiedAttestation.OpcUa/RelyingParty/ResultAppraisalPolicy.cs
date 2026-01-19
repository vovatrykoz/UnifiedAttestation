using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.OpcUa.RelyingParty;

public enum EntityAttestationStatus
{
    Passed,
    Failed,
    Unknown,
}

public record EntityAttestationData(EntityAttestationStatus Status, TpmAttestationResult Details);

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
        if (result is not TpmVerificationReport report)
        {
            _statusDb[entityId] = new EntityAttestationData(EntityAttestationStatus.Failed, result);
            return;
        }

        if (report.Entries.All(entry => entry is TpmEntryCheckPassed))
        {
            _statusDb[entityId] = new EntityAttestationData(EntityAttestationStatus.Passed, result);
            return;
        }

        if (report.Entries.Any(entry => entry is TpmEntryCheckFailed))
        {
            _statusDb[entityId] = new EntityAttestationData(EntityAttestationStatus.Failed, result);
            return;
        }

        var attestationData = new EntityAttestationData(EntityAttestationStatus.Unknown, result);
        _statusDb[entityId] = attestationData;
    }
}
