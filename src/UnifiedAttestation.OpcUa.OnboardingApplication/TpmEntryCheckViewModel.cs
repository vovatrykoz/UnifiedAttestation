using System;
using System.Linq;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.OpcUa.RelyingParty;

namespace UnifiedAttestation.OpcUa.OnboardingApplication;

public class TpmEntryCheckViewModel
{
    public string PcrInfo { get; }
    public string EventHex { get; }
    public string ExpectedHex { get; }
    public string ActualHex { get; }
    public string StatusText { get; }
    public EntityAttestationStatus Status { get; }

    public TpmEntryCheckViewModel(TpmAttestationResult result)
    {
        switch (result)
        {
            case TpmEntryCheckPassed r:
                PcrInfo = $"PCR: {r.PcrIndex}";
                EventHex = $"Event: {Convert.ToHexString(r.Event)}";
                ExpectedHex = "";
                ActualHex = "";
                StatusText = "PASSED";
                Status = EntityAttestationStatus.Passed;
                break;

            case TpmEntryCheckFailed r:
                PcrInfo = $"PCR: {r.PcrIndex}";
                EventHex = $"Event: {Convert.ToHexString(r.Event)}";
                ExpectedHex = "Expected: " + string.Join(", ", r.ExpectedHashes.Select(Convert.ToHexString));
                ActualHex = "Actual: " + (r.ActualHash is null ? "<not provided>" : Convert.ToHexString(r.ActualHash));
                StatusText = r.ActualHash is null ? "FAILED (no actual hash)" : "FAILED (hash mismatch)";
                Status = EntityAttestationStatus.Failed;
                break;

            case TpmEntryCheckUnkown r:
                PcrInfo = $"PCR: {r.PcrIndex}";
                EventHex = $"Event: {Convert.ToHexString(r.Event)}";
                ExpectedHex = "";
                ActualHex = "";
                StatusText = "UNKNOWN";
                Status = EntityAttestationStatus.Unknown;
                break;

            case TpmNonceMismatch r:
                PcrInfo = "";
                EventHex = "";
                ExpectedHex = "Expected: " + string.Join(", ", Convert.ToHexString(r.ExpectedNonce));
                ActualHex = "Actual: " + string.Join(", ", Convert.ToHexString(r.ActualNonce));
                StatusText = "FAILED: Nonce Mismatch";
                Status = EntityAttestationStatus.Failed;
                break;

            case TpmQuoteSignatureCheckFailed r:
                PcrInfo = "";
                EventHex = "";
                ExpectedHex = "";
                ActualHex = "";
                StatusText = "FAILED: Quote Signature Check Failed";
                Status = EntityAttestationStatus.Failed;
                break;

            case TpmReplayFailed r:
                PcrInfo = "";
                EventHex = "";
                ExpectedHex = "";
                ActualHex = "";
                StatusText = "FAILED: Replay Detected";
                Status = EntityAttestationStatus.Failed;
                break;

            case TpmAttestationResult r:
                PcrInfo = "";
                EventHex = "";
                ExpectedHex = "";
                ActualHex = "";
                StatusText = r.ToString();
                Status = EntityAttestationStatus.Unknown;
                break;

            default:
                PcrInfo = "";
                EventHex = "";
                ExpectedHex = "";
                ActualHex = "";
                StatusText = "UNKNOWN RESULT TYPE";
                Status = EntityAttestationStatus.Unknown;
                break;
        }
    }
}
