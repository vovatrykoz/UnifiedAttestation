using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace UnifiedAttestation.Core.Tpm;

public class Tpm20EvidenceAppraisalPolicy
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

        using X509Certificate2 cert = X509CertificateLoader.LoadCertificate(endorsements.ManufacturerCertificate);

        cancellationToken.ThrowIfCancellationRequested();

        bool signatureOk = VerifySignature(cert, tpmQuote.RawBytes(), evidence.QuoteSignature);

        cancellationToken.ThrowIfCancellationRequested();

        if (!signatureOk)
        {
            return new TpmQuoteSignatureCheckFailed();
        }

        List<TpmEntryCheckResult> results = [];

        foreach (TcgEventLogEntry entry in eventLog.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            byte[][]? referenceDigests = referenceValues.GetExpectedPcrValues(HashAlgorithmName.SHA256, entry.PcrIndex);

            if (referenceDigests is null || referenceDigests.Length == 0)
            {
                results.Add(new TpmEntryCheckUnkown(entry.Event));
                continue;
            }

            Digest? digest = entry.Digests.FirstOrDefault(d => d.AlgorithmName == HashAlgorithmName.SHA256);
            if (digest is null)
            {
                results.Add(new TpmEntryCheckFailed(entry.Event, referenceDigests, null));
                continue;
            }

            bool atLeastOneMatch = referenceDigests.Any(referenceValue => referenceValue.SequenceEqual(digest.Bytes));
            if (!atLeastOneMatch)
            {
                results.Add(new TpmEntryCheckFailed(entry.Event, referenceDigests, digest.Bytes));
                continue;
            }

            results.Add(new TpmEntryCheckPassed(entry.Event));
        }

        return new TpmVerificationReport(results.ToArray());
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
}
