using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Gds;
using Opc.Ua.Gds.Client;
using UnifiedAttestation.OpcUa.RelyingParty;

namespace UnifiedAttestation.OpcUa.OnboardingApplication.OpcUa;

public class GdsClient
{
    private readonly ApplicationConfiguration _config;
    private readonly OpcUaOnboardingClient _attesterClient;
    private readonly ISessionFactory _sessionFactory;
    private readonly IReadOnlyDictionary<Guid, string> _endpointDb;

    public GdsClient(
        ApplicationConfiguration config,
        OpcUaOnboardingClient attesterClient,
        ISessionFactory sessionFactory,
        IDictionary<Guid, string> endpointDb
    )
    {
        _config = config;
        _attesterClient = attesterClient;
        _sessionFactory = sessionFactory;
        _endpointDb = new Dictionary<Guid, string>(endpointDb);
    }

    public async Task PerformOnboardingAsync(
        Guid id,
        IUserIdentity gdsUserIdentity,
        IUserIdentity userIdentity,
        CancellationToken cancellationToken = default
    )
    {
        ApplicationRecordDataType applicationRecord = await _attesterClient.GetApplicationDataAsync(
            id,
            cancellationToken
        );

        using var client = new ServerPushConfigurationClient(_config, _sessionFactory)
        {
            AdminCredentials = userIdentity,
        };

        byte[] csr = await _attesterClient.CreateSigningRequestAsync(
            id,
            client.DefaultApplicationGroup,
            client.ApplicationCertificateType,
            cancellationToken
        );

        using var gdsClient = new GlobalDiscoveryServerClient(_config, gdsUserIdentity, _sessionFactory);
        await gdsClient.ConnectAsync("opc.tcp://localhost:58810/GlobalDiscoveryServer", cancellationToken);

        ApplicationRecordDataType[] applications = await gdsClient.FindApplicationAsync(
            applicationRecord.ApplicationUri,
            cancellationToken
        );

        NodeId applicationId =
            applications.Length == 0
                ? await gdsClient.RegisterApplicationAsync(applicationRecord, cancellationToken)
                : applications.First().ApplicationId;

        NodeId requestId = await gdsClient.StartSigningRequestAsync(
            applicationId,
            client.DefaultApplicationGroup,
            client.ApplicationCertificateType,
            csr,
            cancellationToken
        );
        (byte[] cert, byte[] _, byte[][] issuerCerts) = await gdsClient.FinishRequestAsync(
            applicationId,
            requestId,
            cancellationToken
        );

        string attesterEndpoint = _endpointDb[id];

        await client.ConnectAsync(attesterEndpoint, cancellationToken);

        bool updateRequired = await client.UpdateCertificateAsync(
            client.DefaultApplicationGroup,
            client.ApplicationCertificateType,
            cert,
            null,
            null,
            issuerCerts,
            cancellationToken
        );

        NodeId trustListId = await gdsClient.GetTrustListAsync(applicationId, NodeId.Null, cancellationToken);
        TrustListDataType gdsTrustList = await gdsClient.ReadTrustListAsync(trustListId, cancellationToken);
        updateRequired |= await client.UpdateTrustListAsync(gdsTrustList, cancellationToken);

        if (updateRequired)
        {
            await client.ApplyChangesAsync(cancellationToken);
        }
    }
}
