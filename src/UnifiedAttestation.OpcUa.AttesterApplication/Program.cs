using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Configuration;
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
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var request = new CertificateRequest("CN=TPM Signing Cert", ecdsa, HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true)
        );

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.3")], critical: false)
        );

        using X509Certificate2 newCert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(5)
        );

        byte[] pubBytes = newCert.Export(X509ContentType.Cert);
        File.WriteAllBytes(certPath, pubBytes);

        byte[] pfxBytes = newCert.Export(X509ContentType.Pkcs12);
        File.WriteAllBytes(keyPath, pfxBytes);
        logger.LogInformation("New cert created");
    }

    var attesterServer = new BasicAttesterServer(new Tpm20AttestationEnvironment(keyPath));
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
