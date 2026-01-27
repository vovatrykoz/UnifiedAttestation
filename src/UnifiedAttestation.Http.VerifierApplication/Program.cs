using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.Http.VerifierApplication;

const string certFileName =
    "../../../../UnifiedAttestation.OpcUa.AttesterApplication/bin/Debug/net10.0/tpmCerts/attestationCert.pem";

string certPath = Path.Combine(AppContext.BaseDirectory, certFileName);

Dictionary<Guid, string> pathResolver = [];
pathResolver.Add(Guid.Empty, certPath);

var database = ReferenceValueDatabase.Initialize();

var endorsementProvider = new LocalEndorsementProvider(pathResolver);
var referenceValueProvider = new LocalReferenceValueProvider(database);
var evidencePolicy = new TpmEvidenceAppraisalPolicy();
var verificationOrchestrator = new VerificationOrchestrator<
    TpmEvidence,
    TpmEndorsement,
    TpmReferenceValues,
    TpmAttestationResult
>(endorsementProvider, referenceValueProvider, evidencePolicy);

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton(database);
builder.Services.AddControllers();

WebApplication app = builder.Build();
app.MapControllers();
app.Run();
