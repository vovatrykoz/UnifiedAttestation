using System.Security.Cryptography;

namespace UnifiedAttestation.Core.Tpm;

public abstract record TpmQuote;

public record KeyName(HashAlgorithm HashAlgorithm, byte[] Hash);

public record PcrSelection(HashAlgorithm HashAlgorithm, int SelectionMask);

public record Tpm20Quote(KeyName KeyName, byte[] Nonce, PcrSelection PcrSelection, byte[] PcrDigest) : TpmQuote;
