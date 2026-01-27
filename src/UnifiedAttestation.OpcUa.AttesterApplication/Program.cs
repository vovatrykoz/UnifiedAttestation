using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Configuration;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.OpcUa.Attester;
using UnifiedAttestation.OpcUa.AttesterApplication;

ITelemetryContext telemetry = DefaultTelemetry.Create(builder => builder.AddConsole());
ILogger<BasicAttesterServer> logger = telemetry.CreateLogger<BasicAttesterServer>();

const string CertFileName = "tpmCerts\\attestationCert.pem";
const string KeyFileName = "tpmCerts\\attestationCert.pfx";

var attesterApplication = new ApplicationInstance(telemetry)
{
    ApplicationType = ApplicationType.Server,
    ConfigSectionName = "AttesterServer",
};

try
{
    string jsonFilePath = args.Length <= 0 ? "BootConfigs/boot1.json" : args[0];
    string jsonString = File.ReadAllText(jsonFilePath);

    BootComponents? bootComponents = JsonSerializer.Deserialize<BootComponents>(jsonString);
    if (bootComponents is null || bootComponents.Components is null)
    {
        logger.LogError("No boot components found");
        return;
    }

    HashAlgorithmName[] enabledAlgorithms = [HashAlgorithmName.SHA256];
    var tpm = MockTpm20.Initialize(enabledAlgorithms, "tpmKey/private.pem", "tpmKey/public.pem");
    TcgEventLog eventLog = TcgEventLog.Empty;

    foreach (BootComponent component in bootComponents.Components)
    {
        byte[] bootEvent = Encoding.UTF8.GetBytes(component.Content);
        List<Digest> digests = [];

        foreach (HashAlgorithmName algorithm in tpm.EnabledAlgorithms)
        {
            using HashAlgorithm algo = GetHashAlgorithm(algorithm);
            var digest = new Digest(algorithm, algo.ComputeHash(bootEvent));
            digests.Add(digest);
            tpm.Extend(algorithm, component.Pcr, digest.Bytes);
        }

        var newEntry = new TcgEventLogEntry(component.Pcr, component.EventType, digests.ToArray(), bootEvent);
        eventLog.Entries.Add(newEntry);
    }

    ApplicationConfiguration attesterConfig = await attesterApplication.LoadApplicationConfigurationAsync(false);
    bool attesterCertOk = await attesterApplication.CheckApplicationInstanceCertificatesAsync(false);
    if (!attesterCertOk)
    {
        logger.LogError("Application Instance Certificate Checks Failed for Attester");
        return;
    }

    string certPath = Path.Combine(AppContext.BaseDirectory, CertFileName);
    string keyPath = Path.Combine(AppContext.BaseDirectory, KeyFileName);
    string? certDir = Path.GetDirectoryName(certPath);

    if (!string.IsNullOrEmpty(certDir))
    {
        Directory.CreateDirectory(certDir);
    }

    if (!File.Exists(certPath))
    {
        logger.LogInformation("AK Cert doesn't exist. Creating a new one...");
        string privateKeyPem = File.ReadAllText("tpmKey/private.pem");

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(privateKeyPem);

        CertificateRequest request = tpm.GetCsrForAttestationKey(HashAlgorithmName.SHA256);

        using X509Certificate2 cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(5)
        );

        byte[] pubBytes = cert.Export(X509ContentType.Cert);
        File.WriteAllBytes(certPath, pubBytes);

        byte[] pfxBytes = cert.Export(X509ContentType.Pkcs12);
        File.WriteAllBytes(keyPath, pfxBytes);
        logger.LogInformation("New cert created");
    }

    var attestingEnvironment = new Tpm20AttestingEnvironment(tpm, eventLog);
    var attesterServer = new BasicAttesterServer(attestingEnvironment);
    await attesterApplication.StartAsync(attesterServer);

    logger.LogInformation("Attester server running. Press Enter to exit.");
    Console.ReadLine();
    logger.LogInformation("Shutting down attester server.");
    await attesterApplication.StopAsync();
}
catch (Exception e)
{
    logger.LogTrace(e, "Error");
}

static HashAlgorithm GetHashAlgorithm(HashAlgorithmName algorithm) =>
    algorithm switch
    {
        var a when a == HashAlgorithmName.MD5 => MD5.Create(),
        var a when a == HashAlgorithmName.SHA1 => SHA1.Create(),
        var a when a == HashAlgorithmName.SHA256 => SHA256.Create(),
        var a when a == HashAlgorithmName.SHA384 => SHA384.Create(),
        var a when a == HashAlgorithmName.SHA512 => SHA512.Create(),
        var a when a == HashAlgorithmName.SHA3_256 => SHA3_256.Create(),
        var a when a == HashAlgorithmName.SHA3_384 => SHA3_384.Create(),
        var a when a == HashAlgorithmName.SHA3_512 => SHA3_512.Create(),
        _ => throw new NotSupportedException($"Hash algorithm '{algorithm.Name ?? "<null>"}' is not supported."),
    };
