using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Gds;
using Opc.Ua.Gds.Client;
using Opc.Ua.Security.Certificates;
using UnifiedAttestation.OpcUa.RelyingParty;

namespace UnifiedAttestation.OpcUa.OnboardingApplication.OpcUa;

public class GdsClient(
    ApplicationConfiguration config,
    OpcUaOnboardingClient attesterClient,
    ISessionFactory sessionFactory,
    IDictionary<Guid, string> endpointDb
)
{
    private readonly ApplicationConfiguration _config = config;
    private readonly OpcUaOnboardingClient _attesterClient = attesterClient;
    private readonly ISessionFactory _sessionFactory = sessionFactory;
    private readonly IReadOnlyDictionary<Guid, string> _endpointDb = new Dictionary<Guid, string>(endpointDb);

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
        using var gdsClient = new GlobalDiscoveryServerClient(_config, gdsUserIdentity, _sessionFactory);

        try
        {
            byte[] csr = await _attesterClient.CreateSigningRequestAsync(
                id,
                client.DefaultApplicationGroup,
                client.ApplicationCertificateType,
                cancellationToken
            );

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
        finally
        {
            await gdsClient.DisconnectAsync(cancellationToken);
            await client.DisconnectAsync(cancellationToken);
        }
    }
}

public class OwnGdsClient(ApplicationConfiguration config, ISessionFactory sessionFactory)
{
    private readonly ApplicationConfiguration _config = config;
    private readonly ISessionFactory _sessionFactory = sessionFactory;

    public async Task GetOwnCertificateSignedAsync(
        string gdsEndpoint,
        IUserIdentity gdsUserIdentity,
        ITelemetryContext telemetryContext,
        CancellationToken cancellationToken = default
    )
    {
        using var gdsClient = new GlobalDiscoveryServerClient(_config, gdsUserIdentity, _sessionFactory);

        try
        {
            X509Certificate2 currentCert = await _config.SecurityConfiguration.ApplicationCertificate.FindAsync(
                false,
                ct: cancellationToken
            );
            byte[] csr = CertificateFactory.CreateSigningRequest(currentCert);

            await gdsClient.ConnectAsync(gdsEndpoint, cancellationToken);
            ApplicationRecordDataType[] applications = await gdsClient.FindApplicationAsync(
                _config.ApplicationUri,
                cancellationToken
            );

            var applicationRecord = new ApplicationRecordDataType()
            {
                ApplicationUri = _config.ApplicationUri,
                ApplicationNames = [_config.ApplicationName],
                ProductUri = _config.ProductUri,
                ApplicationType = _config.ApplicationType,
            };

            NodeId applicationId =
                applications.Length == 0
                    ? await gdsClient.RegisterApplicationAsync(applicationRecord, cancellationToken)
                    : applications.First().ApplicationId;

            NodeId requestId = await gdsClient.StartSigningRequestAsync(
                applicationId,
                NodeId.Null,
                NodeId.Null,
                csr,
                cancellationToken
            );

            (byte[] cert, byte[] _, byte[][] issuerCerts) = await gdsClient.FinishRequestAsync(
                applicationId,
                requestId,
                cancellationToken
            );

            NodeId trustListId = await gdsClient.GetTrustListAsync(applicationId, NodeId.Null, cancellationToken);
            TrustListDataType gdsTrustList = await gdsClient.ReadTrustListAsync(trustListId, cancellationToken);

            X509Certificate2 newCert = X509CertificateLoader.LoadCertificate(cert);

            CertificateIdentifier certIdentifier = _config.SecurityConfiguration.ApplicationCertificate;
            ICertificateStore store = certIdentifier.OpenStore(telemetryContext);
            using X509Certificate2 existingCert = await certIdentifier.FindAsync(true, ct: cancellationToken);

            RSA? privateKey = existingCert.GetRSAPrivateKey();

            if (privateKey is null)
            {
                return;
            }

            X509Certificate2 mergedCert = newCert.CopyWithPrivateKey(privateKey);
            string thumbprint = existingCert.Thumbprint;
            await store.DeleteAsync(thumbprint, cancellationToken);
            await store.AddAsync(mergedCert, ct: cancellationToken);

            ICertificateStore issuerStore = _config.SecurityConfiguration.TrustedIssuerCertificates.OpenStore(
                telemetryContext
            );

            ICertificateStore trustedStore = _config.SecurityConfiguration.TrustedPeerCertificates.OpenStore(
                telemetryContext
            );

            X509Certificate2Collection existingTrusted = await trustedStore.EnumerateAsync(cancellationToken);
            foreach (X509Certificate2 existingTrustedCert in existingTrusted)
            {
                await trustedStore.DeleteAsync(existingTrustedCert.Thumbprint, cancellationToken);
            }

            X509Certificate2Collection existingIssuer = await issuerStore.EnumerateAsync(cancellationToken);
            foreach (X509Certificate2 existingIssuerCert in existingIssuer)
            {
                await issuerStore.DeleteAsync(existingIssuerCert.Thumbprint, cancellationToken);
            }

            X509CRLCollection trustedCrls = await trustedStore.EnumerateCRLsAsync(cancellationToken);
            foreach (X509CRL? crl in trustedCrls)
            {
                await trustedStore.DeleteCRLAsync(crl, cancellationToken);
            }

            X509CRLCollection issuerCrls = await issuerStore.EnumerateCRLsAsync(cancellationToken);
            foreach (X509CRL? crl in issuerCrls)
            {
                await issuerStore.DeleteCRLAsync(crl, cancellationToken);
            }

            foreach (byte[] issueCert in issuerCerts)
            {
                X509Certificate2 newIssuerCert = X509CertificateLoader.LoadCertificate(issueCert);
                await issuerStore.AddAsync(newIssuerCert, ct: cancellationToken);
            }

            foreach (byte[]? issuerCertBytes in gdsTrustList.IssuerCertificates)
            {
                X509Certificate2 issuerCert = X509CertificateLoader.LoadCertificate(issuerCertBytes);
                await issuerStore.AddAsync(issuerCert, ct: cancellationToken);
            }

            foreach (byte[]? trustedCertBytes in gdsTrustList.TrustedCertificates)
            {
                X509Certificate2 newTrustedCert = X509CertificateLoader.LoadCertificate(trustedCertBytes);
                await trustedStore.AddAsync(newTrustedCert, ct: cancellationToken);
            }

            foreach (byte[]? crlBytes in gdsTrustList.TrustedCrls)
            {
                var crl = new X509CRL(crlBytes);
                await trustedStore.AddCRLAsync(crl, cancellationToken);
            }

            foreach (byte[]? crlBytes in gdsTrustList.IssuerCrls)
            {
                var crl = new X509CRL(crlBytes);
                await issuerStore.AddCRLAsync(crl, cancellationToken);
            }

            await _config.CertificateValidator.UpdateAsync(_config.SecurityConfiguration, ct: cancellationToken);
        }
        finally
        {
            await gdsClient.DisconnectAsync(cancellationToken);
        }
    }
}
