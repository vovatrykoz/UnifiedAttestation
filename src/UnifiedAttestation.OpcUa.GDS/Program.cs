using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Configuration;
using Opc.Ua.Gds.Server;
using Opc.Ua.Server;
using UnifiedAttestation.OpcUa.GDS;
using UnifiedAttestation.OpcUa.GDS.Database;

ITelemetryContext telemetry = DefaultTelemetry.Create(b => b.AddConsole());
ILogger<GlobalDiscoveryServer> logger = telemetry.CreateLogger<GlobalDiscoveryServer>();

var certificateGroup = new CertificateGroup(telemetry);
var applicationDb = new InMemoryApplicationsDatabase();
var userDb = new InMemoryUsersDatabase();

userDb.CreateUser(
    "appadmin",
    "demo",
    new[] { Role.AuthenticatedUser, GdsRole.CertificateAuthorityAdmin, GdsRole.DiscoveryAdmin }
);

userDb.CreateUser(
    "sysadmin",
    "demo",
    new[] { Role.SecurityAdmin, GdsRole.SecurityAdmin, GdsRole.CertificateAuthorityAdmin, GdsRole.DiscoveryAdmin }
);

var server = new GlobalDiscoverySampleServer(applicationDb, applicationDb, certificateGroup, userDb);

var application = new ApplicationInstance(telemetry)
{
    ApplicationType = ApplicationType.Server,
    ConfigSectionName = "GlobalDiscoveryServer",
};

ApplicationConfiguration config = await application.LoadApplicationConfigurationAsync(false);
if (config == null)
{
    logger.LogError("Failed to load application configuration.");
    return;
}

bool haveApplicationCertificate = await application.CheckApplicationInstanceCertificatesAsync(false);
if (!haveApplicationCertificate)
{
    logger.LogError("Application instance certificate is not valid or does not exist.");
    return;
}

try
{
    await application.StartAsync(server);
    Console.ReadLine();
    await application.StopAsync();
}
catch (Exception ex)
{
    logger.LogError(ex, ex.Message);
}
