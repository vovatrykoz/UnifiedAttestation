using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Configuration;
using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.OpcUa;
using UnifiedAttestation.OpcUa.Verifier;
using UnifiedAttestation.OpcUa.VerifierApplication;

ITelemetryContext telemetry = DefaultTelemetry.Create(builder => builder.AddConsole());
ILogger<BasicVerificationServer> logger = telemetry.CreateLogger<BasicVerificationServer>();

var verifierApplication = new ApplicationInstance(telemetry)
{
    ApplicationType = ApplicationType.Server,
    ConfigSectionName = "VerifierServer",
};

const string CertFileName =
    "../../../../UnifiedAttestation.OpcUa.AttesterApplication/bin/Debug/net10.0/tpmCerts/attestationCert.pem";

try
{
    ApplicationConfiguration verifierConfig = await verifierApplication.LoadApplicationConfigurationAsync(false);
    bool verifierCertOk = await verifierApplication.CheckApplicationInstanceCertificatesAsync(false);
    if (!verifierCertOk)
    {
        logger.LogError("Application Instance Certificate Checks Failed");
        return;
    }

    string certPath = Path.Combine(AppContext.BaseDirectory, CertFileName);

    Dictionary<Guid, string> pathResolver = [];
    pathResolver.Add(Guid.Empty, certPath);

    var referenceValues = new TpmReferenceValues(
        Enumerable
            .Range(0, 8)
            .Select(i => new TpmReferenceDigest(
                Algorithm: HashAlgorithmName.SHA256,
                PcrIndex: (uint)i,
                ExpectedPcrValue: [SHA256.HashData([(byte)i])]
            ))
    );
    Dictionary<Guid, TpmReferenceValues> referenceDb = [];
    referenceDb.Add(Guid.Empty, referenceValues);

    var endorsementProvider = new LocalEndorsementProvider(pathResolver);
    var referenceValueProvider = new LocalReferenceValueProvider(referenceDb);
    var evidencePolicy = new TpmEvidenceAppraisalPolicy();
    var verificationService = new VerificationOrchestrator<
        TpmEvidence,
        TpmEndorsement,
        TpmReferenceValues,
        TpmAttestationResult
    >(endorsementProvider, referenceValueProvider, evidencePolicy);

    var attestingEnvironment = new Tpm20AttestationEnvironment();
    var verifierServer = new BasicVerificationServer(attestingEnvironment, verificationService);
    await verifierApplication.StartAsync(verifierServer);

    logger.LogInformation("Servers running. Press Enter to exit.");
    Console.ReadLine();
    logger.LogInformation("Shutting down the servers.");
    await verifierApplication.StopAsync();
}
catch (Exception e)
{
    logger.LogTrace(e, "Error");
}

public class Tpm20AttestationEnvironment : IAttestingEnvironment
{
    public CborCmw GetAttestationData(byte[] nonce)
    {
        byte[] keyName = [1, 2, 3];
        var pcrSelection = new PcrSelection(HashAlgorithmName.SHA256, 0b1111111);
        byte[] digest = SHA256.HashData(keyName);

        byte[] quote = new Tpm20Quote(keyName, nonce, pcrSelection, digest).GetRawBytes();
        return new CborCmw(60, quote, ConceptualMessageTypes.Evidence);
    }
}
