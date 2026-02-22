using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Gds;
using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.OpcUa.Encoding;

namespace UnifiedAttestation.OpcUa.RelyingParty;

public class OpcUaOnboardingClient(
    ISessionFactory sessionFactory,
    ITelemetryContext telemetryContext,
    IUserIdentity userIdentity,
    Dictionary<Guid, string> endpointDb,
    string verifierEndpoint,
    ApplicationConfiguration config
) : IAttesterClient, IVerifierClient<TpmAttestationResult>, IDisposable
{
    public ISessionFactory SessionFactory { get; } = sessionFactory;

    public ITelemetryContext TelemetryContext { get; } = telemetryContext;

    public IUserIdentity UserIdentity { get; } = userIdentity;

    private readonly Dictionary<Guid, string> _endpointDb = endpointDb;

    public string VerifierEndpoint { get; } = verifierEndpoint;

    public ApplicationConfiguration Config { get; } = config;

    private ISession? _session = null;

    private bool _disposed = false;

    public async Task<CborCmw> RequestEvidenceAsync(
        Guid entityId,
        byte[] nonce,
        CancellationToken cancellationToken = default
    )
    {
        string endpoint = _endpointDb[entityId];
        await ConnectAsync(endpoint, Config, UserIdentity, cancellationToken);
        CborCmw evidence = await GetAttestationDataAsync(nonce, cancellationToken);
        await DisconnectAsync();

        return evidence;
    }

    async Task<TpmAttestationResult> IVerifierClient<TpmAttestationResult>.VerifyEvidenceAsync(
        Guid entityId,
        CborCmw evidence,
        byte[] nonce,
        CancellationToken cancellationToken
    )
    {
        await ConnectAsync(VerifierEndpoint, Config, UserIdentity, cancellationToken);
        CborCmw result = await VerifyEvidenceAsync(entityId, evidence, nonce, cancellationToken);
        await DisconnectAsync();

        return TpmAttestationResult.Decode(result.Value);
    }

    private async Task ConnectAsync(
        string serverUrl,
        ApplicationConfiguration config,
        IUserIdentity userIdentity,
        CancellationToken cancellationToken = default
    )
    {
        await config.ValidateAsync(ApplicationType.Client, cancellationToken);

        if (config.SecurityConfiguration.AutoAcceptUntrustedCertificates)
        {
            config.CertificateValidator.CertificateValidation += (s, e) =>
            {
                e.Accept = true;
            };
        }

        EndpointDescription? endpoint = await CoreClientUtils.SelectEndpointAsync(
            config,
            serverUrl,
            true,
            TelemetryContext,
            cancellationToken
        );

        var endpointConfig = EndpointConfiguration.Create(config);
        var configuredEndpoint = new ConfiguredEndpoint(null, endpoint, endpointConfig);

        _session = await SessionFactory.CreateAsync(
            config,
            configuredEndpoint,
            false,
            "Attestation Client Session",
            15000,
            userIdentity,
            ["en-US"],
            cancellationToken
        );
    }

    private async Task<CborCmw> GetAttestationDataAsync(byte[] nonce, CancellationToken cancellationToken = default)
    {
        if (_session is null)
        {
            throw new InvalidOperationException("A connection needs to be established to start a session");
        }

        var objectId = NodeId.Parse("ns=2;s=Attestation");
        var methodId = NodeId.Parse("ns=2;s=GetAttestationData");

        IList<object> response = await _session.CallAsync(objectId, methodId, cancellationToken, nonce);
        if (response is null || response.Count == 0)
        {
            throw new InvalidDataException("OPC UA method GetAttestationData returned no output arguments.");
        }

        if (response[0] is not byte[] bytes)
        {
            throw new InvalidDataException(
                $"Expected output argument of type byte array, "
                    + $"but received {response[0]?.GetType().FullName ?? "null"}."
            );
        }

        return bytes.ToCborCmwRecord();
    }

    private async Task<CborCmw> VerifyEvidenceAsync(
        Guid id,
        CborCmw evidence,
        byte[] nonce,
        CancellationToken cancellationToken = default
    )
    {
        if (_session is null)
        {
            throw new InvalidOperationException("A connection needs to be established to start a session");
        }

        var objectId = NodeId.Parse("ns=2;s=Attestation");
        var methodId = NodeId.Parse("ns=2;s=AppraiseEvidence");

        IList<object> response = await _session.CallAsync(objectId, methodId, cancellationToken, id, evidence, nonce);

        if (response is null || response.Count == 0)
        {
            throw new InvalidDataException("OPC UA method AppraiseEvidence returned no output arguments.");
        }

        if (response[0] is not byte[] bytes)
        {
            throw new InvalidDataException(
                $"Expected output argument of type byte array, "
                    + $"but received {response[0]?.GetType().FullName ?? "null"}."
            );
        }

        return bytes.ToCborCmwRecord();
    }

    public async Task<byte[]> CreateSigningRequestAsync(
        Guid entityId,
        NodeId appGroup,
        NodeId certType,
        CancellationToken cancellationToken = default
    )
    {
        string endpoint = _endpointDb[entityId];
        await ConnectAsync(endpoint, Config, UserIdentity, cancellationToken);
        byte[] csr = await CallCreateSigningRequestMethodAsync(appGroup, certType, cancellationToken);
        await DisconnectAsync();

        return csr;
    }

    private async Task<byte[]> CallCreateSigningRequestMethodAsync(
        NodeId appGroup,
        NodeId certType,
        CancellationToken cancellationToken = default
    )
    {
        if (_session is null)
        {
            throw new InvalidOperationException("A connection needs to be established to start a session");
        }

        using X509Certificate2 oldCert = X509CertificateLoader.LoadCertificate(_session.Endpoint.ServerCertificate);

        NodeId parentNode = ExpandedNodeId.ToNodeId(Opc.Ua.ObjectIds.ServerConfiguration, _session.NamespaceUris);
        NodeId methodNode = Opc.Ua.MethodIds.ServerConfiguration_CreateSigningRequest;
        bool regeneratePrivateKey = false;
        byte[] nonce = RandomNumberGenerator.GetBytes(32);

        IList<object> response = await _session.CallAsync(
            parentNode,
            methodNode,
            cancellationToken,
            appGroup,
            certType,
            oldCert.SubjectName.Name,
            regeneratePrivateKey,
            nonce
        );

        if (response is null || response.Count == 0)
        {
            throw new InvalidDataException("OPC UA method AppraiseEvidence returned no output arguments.");
        }

        if (response[0] is not byte[] csr)
        {
            throw new InvalidDataException(
                $"Expected output argument of type byte array, "
                    + $"but received {response[0]?.GetType().FullName ?? "null"}."
            );
        }

        return csr;
    }

    public async Task<ApplicationRecordDataType> GetApplicationDataAsync(
        Guid entityId,
        CancellationToken cancellationToken = default
    )
    {
        string endpoint = _endpointDb[entityId];
        await ConnectAsync(endpoint, Config, UserIdentity, cancellationToken);
        ApplicationRecordDataType appRecord = ReadApplicationRecord();
        await DisconnectAsync();

        return appRecord;
    }

    private ApplicationRecordDataType ReadApplicationRecord()
    {
        if (_session is null)
        {
            throw new InvalidOperationException("A connection needs to be established to start a session");
        }

        ApplicationDescription server = _session.Endpoint.Server;
        string applicationUri = _session.Endpoint.Server.ApplicationUri;
        string productUri = server.ProductUri;
        LocalizedText applicationName = server.ApplicationName;
        ApplicationType applicationType = server.ApplicationType;
        StringCollection discoveryUrls = server.DiscoveryUrls;

        return new ApplicationRecordDataType()
        {
            ApplicationUri = applicationUri,
            ApplicationNames = [applicationName],
            ProductUri = productUri,
            ApplicationType = applicationType,
            DiscoveryUrls = discoveryUrls,
        };
    }

    private async Task DisconnectAsync()
    {
        if (_session is null)
        {
            return;
        }

        try
        {
            await _session.CloseAsync();
        }
        finally
        {
            _session.Dispose();
            _session = null;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _session?.Dispose();
            _disposed = true;
        }
    }
}
