using System.Security.Cryptography;
using System.Text.Json;
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

const string certFileName =
    "../../../../UnifiedAttestation.OpcUa.AttesterApplication/bin/Debug/net10.0/tpmCerts/attestationCert.pem";

const string defaultBootPath = "./ReferenceValues/boot1.json";

try
{
    string jsonFilePath = args.Length <= 0 ? defaultBootPath : args[0];
    string jsonString = File.ReadAllText(jsonFilePath);
    logger.LogInformation("Parsing {Path}", jsonFilePath);
    ReferenceValuesJson? referenceValuesJson = JsonSerializer.Deserialize<ReferenceValuesJson>(jsonString);
    if (referenceValuesJson is null || referenceValuesJson.ReferenceValues is null)
    {
        logger.LogError("No reference values found at {Path}", jsonFilePath);
        return;
    }

    var referenceValues = new TpmReferenceValues(
        referenceValuesJson.ReferenceValues.Select(jsonEntry => new TpmReferenceDigest(
            new HashAlgorithmName(jsonEntry.HashAlgorithm),
            jsonEntry.PcrIndex,
            jsonEntry.Event,
            jsonEntry.Digests
        ))
    );

    await verifierApplication.LoadApplicationConfigurationAsync(false);
    bool verifierCertOk = await verifierApplication.CheckApplicationInstanceCertificatesAsync(false);
    if (!verifierCertOk)
    {
        logger.LogError("Application Instance Certificate Checks Failed");
        return;
    }

    string certPath = Path.Combine(AppContext.BaseDirectory, certFileName);

    Dictionary<Guid, string> pathResolver = [];
    pathResolver.Add(Guid.Empty, certPath);

    var referenceDb = new Dictionary<Guid, TpmReferenceValues> { { Guid.Empty, referenceValues } };

    var endorsementProvider = new LocalEndorsementProvider(pathResolver);
    var referenceValueProvider = new LocalReferenceValueProvider(referenceDb);
    var evidencePolicy = new TpmEvidenceAppraisalPolicy();
    var verificationOrchestrator = new VerificationOrchestrator<
        TpmEvidence,
        TpmEndorsement,
        TpmReferenceValues,
        TpmAttestationResult
    >(endorsementProvider, referenceValueProvider, evidencePolicy);

    var attestingEnvironment = new MockAttestingEnvironment();
    var verifierServer = new BasicVerificationServer(attestingEnvironment, verificationOrchestrator);
    await verifierApplication.StartAsync(verifierServer);

    logger.LogInformation("Servers running. Press Enter to exit.");
    Console.ReadLine();
    logger.LogInformation("Shutting down the servers.");
    await verifierApplication.StopAsync();
}
catch (Exception e)
{
    Console.WriteLine(e);
}

public class MockAttestingEnvironment : IAttestingEnvironment
{
    public CborCmw GetAttestationData(byte[] nonce)
    {
        byte[] keyName = [1, 2, 3];
        var pcrSelection = new PcrSelection(HashAlgorithmName.SHA256, 0b1111111);
        byte[] digest = SHA256.HashData(keyName);

        byte[] quote = new Tpm20Quote(keyName, nonce, pcrSelection, digest).GetRawBytes();
        return new CborCmw((ushort)CoapContentIds.CborId, quote, ConceptualMessageTypes.Evidence);
    }
}
