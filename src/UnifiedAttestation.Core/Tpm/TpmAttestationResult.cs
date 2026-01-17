using System.Security.Cryptography;
using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core.Tpm;

public abstract record TpmEntryCheckResult;

public record TpmEntryCheckPassed(byte[] Event) : TpmEntryCheckResult;

public record TpmEntryCheckFailed(byte[] Event, byte[][] ExpectedHashes, byte[]? ActualHash) : TpmEntryCheckResult;

public record TpmEntryCheckUnkown(byte[] Event) : TpmEntryCheckResult;

public abstract record TpmAttestationResult : IAttestationResult;

public record TpmQuoteSignatureCheckFailed : TpmAttestationResult;

public record TpmVerificationReport(TpmEntryCheckResult[] Entries) : TpmAttestationResult;
