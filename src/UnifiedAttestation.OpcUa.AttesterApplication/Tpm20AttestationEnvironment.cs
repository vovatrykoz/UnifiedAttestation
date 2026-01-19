using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.OpcUa.Encoding;

namespace UnifiedAttestation.OpcUa.AttesterApplication;

public class Tpm20AttestationEnvironment : IAttestingEnvironment
{
    private readonly string _certPath;

    private readonly TcgEventLog _log;

    public Tpm20AttestationEnvironment(string certPath)
    {
        _certPath = certPath;
        _log = TcgEventLog.Empty;

        for (uint i = 0; i <= 7; i++)
        {
            var digest = new Digest(HashAlgorithmName.SHA256, SHA256.HashData([(byte)i]));
            var entry = new TcgEventLogEntry(i, i, [digest], [(byte)i]);

            _log.Entries.Add(entry);
        }
    }

    public CborCmw GetAttestationData(byte[] nonce)
    {
        byte[] keyName = [1, 2, 3];
        var pcrSelection = new PcrSelection(HashAlgorithmName.SHA256, 0b11111111);
        List<uint> pcrIndeces = [0, 1, 2, 3, 4, 5, 6, 7];
        byte[] concatenated = [];

        foreach (uint pcrIndex in pcrIndeces)
        {
            byte[] pcrDigest = _log.Replay(pcrSelection.Algorithm, pcrIndex);
            concatenated = concatenated.Concat(pcrDigest).ToArray();
        }

        byte[] digest = SHA256.HashData(concatenated);

        var quote = new Tpm20Quote(keyName, nonce, pcrSelection, digest);

        byte[] signingKey = File.ReadAllBytes(_certPath);
        using X509Certificate2 cert = X509CertificateLoader.LoadPkcs12(signingKey, null);
        if (cert.GetECDsaPrivateKey() is not ECDsa ecdsa)
        {
            throw new InvalidOperationException($"The certificate at {_certPath} does not expose a signing key");
        }

        byte[] signature = ecdsa.SignData(quote.GetRawBytes(), HashAlgorithmName.SHA256);
        byte[] evidence = new TpmEvidence(quote, signature, _log).Encode();
        return new CborCmw(60, evidence, ConceptualMessageTypes.Evidence);
    }
}
