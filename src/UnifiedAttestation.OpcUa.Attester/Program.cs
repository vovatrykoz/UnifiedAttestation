using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Configuration;
using UnifiedAttestation.OpcUa;
using UnifiedAttestation.OpcUa.Attester;

ITelemetryContext telemetry = DefaultTelemetry.Create(builder => builder.AddConsole());
ILogger<BasicAttesterServer> logger = telemetry.CreateLogger<BasicAttesterServer>();

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

    var attesterServer = new BasicAttesterServer(new Tpm20AttestationEnvironment());
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
