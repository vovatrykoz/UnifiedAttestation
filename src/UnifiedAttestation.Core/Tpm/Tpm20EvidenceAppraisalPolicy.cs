using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace UnifiedAttestation.Core.Tpm;

public class TpmEvidenceAppraisalPolicy
    : IEvidenceAppraisalPolicy<TpmEvidence, TpmEndorsement, TpmReferenceValues, TpmAttestationResult>
{
    public async Task<TpmAttestationResult> AppraiseAsync(
        TpmEvidence evidence,
        byte[] nonce,
        TpmEndorsement endorsements,
        TpmReferenceValues referenceValues,
        CancellationToken cancellationToken = default
    )
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (evidence.Quote is not Tpm20Quote tpmQuote)
        {
            throw new NotSupportedException(
                $"Unsupported quote type '{evidence.Quote?.GetType().Name ?? "<null>"}'. "
                    + $"Only 'Tpm20Quote' is currently supported."
            );
        }

        if (evidence.Log is not TcgEventLog eventLog)
        {
            throw new NotSupportedException(
                $"Unsupported event log type '{evidence.Log?.GetType().Name ?? "<null>"}'. "
                    + $"Only 'TcgEventLog' is currently supported."
            );
        }

        if (!nonce.SequenceEqual(tpmQuote.Nonce))
        {
            return new TpmNonceMismatch();
        }

        using (X509Certificate2 cert = X509CertificateLoader.LoadCertificate(endorsements.ManufacturerCertificate))
        {
            bool signatureOk = VerifySignature(cert, tpmQuote.GetRawBytes(), evidence.QuoteSignature);

            if (!signatureOk)
            {
                return new TpmQuoteSignatureCheckFailed();
            }
        }

        cancellationToken.ThrowIfCancellationRequested();

        using (HashAlgorithm hashAlgorithm = GetHashAlgorithm(tpmQuote.PcrSelection.Algorithm))
        {
            List<uint> pcrIndeces = ExtractPcrIndices(tpmQuote.PcrSelection.SelectionMask);
            byte[] concatenated = [];

            foreach (uint pcrIndex in pcrIndeces)
            {
                byte[] pcrDigest = eventLog.Replay(tpmQuote.PcrSelection.Algorithm, pcrIndex);
                concatenated = concatenated.Concat(pcrDigest).ToArray();
            }

            byte[] digest = hashAlgorithm.ComputeHash(concatenated);

            if (!digest.SequenceEqual(tpmQuote.PcrDigest))
            {
                return new TpmReplayFailed();
            }
        }

        List<TpmEntryCheckResult> results = [];

        foreach (TcgEventLogEntry entry in eventLog.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            byte[][]? referenceDigests = referenceValues.GetExpectedPcrValues(HashAlgorithmName.SHA256, entry.PcrIndex);

            if (referenceDigests is null || referenceDigests.Length == 0)
            {
                results.Add(new TpmEntryCheckUnkown(entry.PcrIndex, entry.Event));
                continue;
            }

            Digest? digest = entry.Digests.FirstOrDefault(d => d.AlgorithmName == HashAlgorithmName.SHA256);
            if (digest is null)
            {
                results.Add(new TpmEntryCheckFailed(entry.PcrIndex, entry.Event, referenceDigests, null));
                continue;
            }

            bool atLeastOneMatch = referenceDigests.Any(referenceValue => referenceValue.SequenceEqual(digest.Bytes));
            if (!atLeastOneMatch)
            {
                results.Add(new TpmEntryCheckFailed(entry.PcrIndex, entry.Event, referenceDigests, digest.Bytes));
                continue;
            }

            results.Add(new TpmEntryCheckPassed(entry.PcrIndex, entry.Event));
        }

        return new TpmVerificationReport(results.ToArray());
    }

    private static List<uint> ExtractPcrIndices(int bitmask)
    {
        var positions = new List<uint>();

        for (uint i = 0; i < 32; i++)
        {
            if ((bitmask & (1 << (int)i)) != 0)
            {
                positions.Add(i);
            }
        }

        return positions;
    }

    private static bool VerifySignature(X509Certificate2 cert, byte[] quote, byte[] signature)
    {
        if (cert.GetRSAPublicKey() is RSA rsaKey)
        {
            return rsaKey.VerifyData(quote, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        if (cert.GetECDsaPublicKey() is ECDsa ecdsaKey)
        {
            return ecdsaKey.VerifyData(quote, signature, HashAlgorithmName.SHA256);
        }

        throw new InvalidOperationException("AIK public key type not supported.");
    }

    private static HashAlgorithm GetHashAlgorithm(HashAlgorithmName algorithm) =>
        algorithm switch
        {
            var a when a == HashAlgorithmName.SHA1 => SHA1.Create(),
            var a when a == HashAlgorithmName.SHA256 => SHA256.Create(),
            var a when a == HashAlgorithmName.SHA384 => SHA384.Create(),
            var a when a == HashAlgorithmName.SHA512 => SHA256.Create(),
            _ => throw new NotSupportedException(
                $"Hash algorithm '{algorithm.Name ?? "<null>"}' is not supported by TPM 2.0."
            ),
        };
}
