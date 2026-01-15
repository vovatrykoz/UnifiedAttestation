namespace UnifiedAttestation.Core.Tpm;

public abstract record TpmQuote;

public enum HashAlgorithm
{
    MD5,
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

public record KeyName(HashAlgorithm HashAlgorithm, byte[] Hash);

public record PcrSelection(HashAlgorithm HashAlgorithm, int SelectionMask);

public record Tpm20Quote(KeyName KeyName, byte[] Nonce, PcrSelection PcrSelection, byte[] PcrDigest) : TpmQuote;
