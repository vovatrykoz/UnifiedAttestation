using System.Text;
using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core.Tpm;

public abstract record TpmAttestationResult : IAttestationResult;

public record TpmNonceMismatch(byte[] ExpectedNonce, byte[] ActualNonce) : TpmAttestationResult;

public record TpmQuoteSignatureCheckFailed : TpmAttestationResult;

public record TpmReplayFailed : TpmAttestationResult;

public abstract record TpmEntryCheckResult : TpmAttestationResult;

public record TpmEntryCheckPassed(uint PcrIndex, byte[] Event) : TpmEntryCheckResult
{
    public override string ToString()
    {
        string hex = Convert.ToHexString(Event);
        return "PCR: " + PcrIndex + ", Event: " + hex + ", Status: OK\n";
    }
}

public record TpmEntryCheckFailed(uint PcrIndex, byte[] Event, byte[][] ExpectedHashes, byte[]? ActualHash)
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

public record TpmEntryCheckUnkown(uint PcrIndex, byte[] Event) : TpmEntryCheckResult
{
    public override string ToString()
    {
        string eventHex = Convert.ToHexString(Event);
        return "PCR: " + PcrIndex + ", Event: " + eventHex + ", Status: UNKNOWN (no reference value found)\n";
    }
}

public record TpmVerificationReport(TpmEntryCheckResult[] Entries) : TpmAttestationResult
{
    public override string ToString()
    {
        var builder = new StringBuilder();
        builder.Append('\n');

        foreach (TpmEntryCheckResult entry in Entries)
        {
            builder.Append('\t' + entry.ToString().Replace("\t", "\t\t"));
        }

        builder.Append('\n');
        return builder.ToString();
    }
}
