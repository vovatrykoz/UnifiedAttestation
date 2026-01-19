using Opc.Ua;
using Opc.Ua.Client;
using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.OpcUa.Encoding;

namespace UnifiedAttestation.OpcUa.RelyingParty;

public class OpcUaRelyingPartyClient(
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

    public async Task<byte[]> RequestEvidenceAsync(
        Guid entityId,
        byte[] nonce,
        CancellationToken cancellationToken = default
    )
    {
        string endpoint = _endpointDb[entityId];
        await ConnectAsync(endpoint, Config, UserIdentity);
        byte[] evidence = await GetAttestationDataAsync(nonce, cancellationToken);
        await DisconnectAsync();

        return evidence;
    }

    async Task<TpmAttestationResult> IVerifierClient<TpmAttestationResult>.VerifyEvidenceAsync(
        Guid entityId,
        byte[] evidence,
        byte[] nonce,
        CancellationToken cancellationToken
    )
    {
        await ConnectAsync(VerifierEndpoint, Config, UserIdentity);
        byte[] result = await VerifyEvidenceAsync(entityId, evidence, nonce, cancellationToken);
        await DisconnectAsync();

        CborCmw cmw = CborCmw.FromBytes(result);
        return TpmAttestationResult.Decode(cmw.Value);
    }

    public async Task ConnectAsync(string serverUrl, ApplicationConfiguration config, IUserIdentity userIdentity)
    {
        await config.ValidateAsync(ApplicationType.Client);

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
            TelemetryContext
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
            ["en-US"]
        );
    }

    public async Task<byte[]> GetAttestationDataAsync(byte[] nonce, CancellationToken cancellationToken = default)
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

        return bytes;
    }

    public async Task<byte[]> VerifyEvidenceAsync(
        Guid id,
        byte[] evidence,
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

        return bytes;
    }

    public async Task DisconnectAsync()
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
