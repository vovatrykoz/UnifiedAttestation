using System.Text;
using System.Text.Json.Serialization;
using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core.Tpm;

[JsonPolymorphic(
    TypeDiscriminatorPropertyName = "kind",
    UnknownDerivedTypeHandling = JsonUnknownDerivedTypeHandling.FallBackToNearestAncestor
)]
[JsonDerivedType(typeof(TpmVerificationReport), "report")]
[JsonDerivedType(typeof(TpmNonceMismatch), "nonceMismatch")]
[JsonDerivedType(typeof(TpmQuoteSignatureCheckFailed), "signatureMismatch")]
[JsonDerivedType(typeof(TpmReplayFailed), "replayFail")]
public abstract record TpmAttestationResult : IAttestationResult;

public sealed record TpmNonceMismatch(byte[] ExpectedNonce, byte[] ActualNonce) : TpmAttestationResult;

public sealed record TpmQuoteSignatureCheckFailed : TpmAttestationResult;

public sealed record TpmReplayFailed(byte[] ExpectedDigest, byte[] ActualDigest) : TpmAttestationResult;

[JsonPolymorphic(
    TypeDiscriminatorPropertyName = "kind",
    UnknownDerivedTypeHandling = JsonUnknownDerivedTypeHandling.FallBackToNearestAncestor
)]
[JsonDerivedType(typeof(TpmEntryCheckPassed), "checkPassed")]
[JsonDerivedType(typeof(TpmEntryCheckFailed), "checkFailed")]
[JsonDerivedType(typeof(TpmEntryCheckUnknown), "checkUnknown")]
public abstract record TpmEntryCheckResult : TpmAttestationResult;

public sealed record TpmEntryCheckPassed(uint PcrIndex, byte[] Event) : TpmEntryCheckResult
{
    public override string ToString()
    {
        string hex = Convert.ToHexString(Event);
        return "PCR: " + PcrIndex + ", Event: " + hex + ", Status: OK\n";
    }
}

public sealed record TpmEntryCheckFailed(uint PcrIndex, byte[] Event, byte[][] ExpectedHashes, byte[]? ActualHash)
    : TpmEntryCheckResult
{
    public override string ToString()
    {
        string eventHex = Convert.ToHexString(Event);

        string expectedHex =
            ExpectedHashes.Length == 0 ? "<none>" : string.Join(", ", ExpectedHashes.Select(Convert.ToHexString));

        string actualHex = ActualHash is null ? "<not provided>" : Convert.ToHexString(ActualHash);
        string status = ActualHash is null ? "FAILED (no actual hash provided)" : "FAILED (hash mismatch)";

        return "PCR: "
            + PcrIndex
            + "\n\tEvent: "
            + eventHex
            + "\n\tExpected: "
            + expectedHex
            + "\n\tActual: "
            + actualHex
            + "\n\tStatus: "
            + status
            + "\n";
    }
}

public sealed record TpmEntryCheckUnknown(uint PcrIndex, byte[] Event) : TpmEntryCheckResult
{
    public override string ToString()
    {
        string eventHex = Convert.ToHexString(Event);
        return "PCR: " + PcrIndex + ", Event: " + eventHex + ", Status: UNKNOWN (no reference value found)\n";
    }
}

public sealed record TpmVerificationReport(TpmEntryCheckResult[] Entries) : TpmAttestationResult
{
    public override string ToString()
    {
        var builder = new StringBuilder();
        builder.Append('\n');

        foreach (TpmEntryCheckResult entry in Entries)
        {
            builder.Append('\t' + entry.ToString()?.Replace("\t", "\t\t"));
        }

        builder.Append('\n');
        return builder.ToString();
    }
}
