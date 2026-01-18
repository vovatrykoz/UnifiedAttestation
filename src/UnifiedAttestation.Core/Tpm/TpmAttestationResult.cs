using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core.Tpm;

public abstract record TpmAttestationResult : IAttestationResult;

public record TpmNonceMismatch : TpmAttestationResult;

public record TpmQuoteSignatureCheckFailed : TpmAttestationResult;

public record TpmReplayFailed : TpmAttestationResult;

public abstract record TpmEntryCheckResult : TpmAttestationResult;

public record TpmEntryCheckPassed(byte[] Event) : TpmEntryCheckResult;

public record TpmEntryCheckFailed(byte[] Event, byte[][] ExpectedHashes, byte[]? ActualHash) : TpmEntryCheckResult;

public record TpmEntryCheckUnkown(byte[] Event) : TpmEntryCheckResult;

public record TpmVerificationReport(TpmEntryCheckResult[] Entries) : TpmAttestationResult;
