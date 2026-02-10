using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Gds;
using Opc.Ua.Gds.Server;
using Opc.Ua.Gds.Server.Database;
using Opc.Ua.Security.Certificates;
using Opc.Ua.Server;
using Opc.Ua.Server.UserDatabase;

namespace UnifiedAttestation.OpcUa.GDS;

public class GlobalDiscoveryServer : StandardServer
{
    public GlobalDiscoveryServer(
        IApplicationsDatabase database,
        ICertificateRequest request,
        ICertificateGroup certificateGroup,
        IUserDatabase userDatabase,
        bool autoApprove = true
    )
    {
        m_database = database;
        m_request = request;
        m_certificateGroup = certificateGroup;
        m_userDatabase = userDatabase;
        m_autoApprove = autoApprove;
    }

    #region Overridden Methods
    /// <summary>
    /// Called after the server has been started.
    /// </summary>
    protected override void OnServerStarted(IServerInternal server)
    {
        base.OnServerStarted(server);
        OnServerStartedCore(server);
    }

    //Overridable hook, useful for test class
    protected virtual void OnServerStartedCore(IServerInternal server)
    {
        // request notifications when the user identity is changed. all valid users are accepted by default.
        server.SessionManager.ImpersonateUser += SessionManager_ImpersonateUser;
    }

    /// <summary>
    /// Creates the node managers for the server.
    /// </summary>
    /// <remarks>
    /// This method allows the sub-class create any additional node managers which it uses. The SDK
    /// always creates a CoreNodeManager which handles the built-in nodes defined by the specification.
    /// Any additional NodeManagers are expected to handle application specific nodes.
    /// </remarks>
    protected override MasterNodeManager CreateMasterNodeManager(
        IServerInternal server,
        ApplicationConfiguration configuration
    )
    {
        List<INodeManager> nodeManagers =
        [
            // create the custom node managers.
            new ApplicationsNodeManager(
                server,
                configuration,
                m_database,
                m_request,
                m_certificateGroup,
                m_autoApprove
            ),
        ];

        // create master node manager.
        return new MasterNodeManager(server, configuration, null, nodeManagers.ToArray());
    }

    /// <summary>
    /// Loads the non-configurable properties for the application.
    /// </summary>
    /// <remarks>
    /// These properties are exposed by the server but cannot be changed by administrators.
    /// </remarks>
    protected override ServerProperties LoadServerProperties()
    {
        ServerProperties properties = new ServerProperties
        {
            ManufacturerName = "ABB ab.",
            ProductName = "Global Discovery Server",
            ProductUri = "http://abb.com/GlobalDiscoveryServer",
            SoftwareVersion = Utils.GetAssemblySoftwareVersion(),
            BuildNumber = Utils.GetAssemblyBuildNumber(),
            BuildDate = Utils.GetAssemblyTimestamp(),
        };

        return properties;
    }

    /// <summary>
    /// This method is called at the being of the thread that processes a request.
    /// </summary>
    protected override OperationContext ValidateRequest(
        SecureChannelContext context,
        RequestHeader requestHeader,
        RequestType requestType
    )
    {
        OperationContext opContext = base.ValidateRequest(context, requestHeader, requestType);

        if (requestType == RequestType.Write)
        {
            if (opContext.UserIdentity.TokenType == UserTokenType.Anonymous)
            {
                var info = new TranslationInfo(
                    "NoWriteAllowed",
                    "en-US",
                    "Must provide a valid user before calling write."
                );

                throw new ServiceResultException(ServiceResult.Bad);
            }

            UserIdentityToken securityToken = opContext.UserIdentity.GetIdentityToken();

            if (securityToken is UserNameIdentityToken userNameToken)
            {
                lock (m_lock)
                {
                    m_contexts.Add(opContext.RequestId, new ImpersonationContext());
                }
            }
        }

        return opContext;
    }

    /// <summary>
    /// This method is called in a finally block at the end of request processing (i.e. called even on exception).
    /// </summary>
    protected override void OnRequestComplete(OperationContext context)
    {
        ImpersonationContext? impersonationContext = null;

        lock (m_lock)
        {
            if (m_contexts.TryGetValue(context.RequestId, out impersonationContext))
            {
                m_contexts.Remove(context.RequestId);
            }
        }

        base.OnRequestComplete(context);
    }

    /// <summary>
    /// Called when a client tries to change its user identity.
    /// </summary>
    private void SessionManager_ImpersonateUser(ISession session, ImpersonateEventArgs args)
    {
        //Rejecting anonymous connections
        if (args.NewIdentity is AnonymousIdentityToken)
        {
            throw new ServiceResultException(StatusCodes.BadIdentityTokenRejected, "Anonymous access is disabled!");
        }

        // check for a user name token
        if (args.NewIdentity is UserNameIdentityToken userNameToken)
        {
            if (VerifyPassword(userNameToken))
            {
                IEnumerable<Role> roles = m_userDatabase.GetUserRoles(userNameToken.UserName);

                args.Identity = new GdsRoleBasedIdentity(new UserIdentity(userNameToken), roles);
                return;
            }
        }

        // check for x509 user token.
        X509IdentityToken? x509Token = args.NewIdentity as X509IdentityToken;
        if (x509Token != null)
        {
            VerifyUserTokenCertificate(x509Token.Certificate);

            // todo: is cert listed in admin list? then
            // role = GdsRole.ApplicationAdmin;

            m_logger.LogInformation(
                "X509 Token Accepted: {0} as {1}",
                args.Identity.DisplayName,
                Role.AuthenticatedUser
            );
            args.Identity = new GdsRoleBasedIdentity(
                new UserIdentity(x509Token),
                new List<Role> { Role.AuthenticatedUser }
            );
            return;
        }

        //Currently we don't support application self admin privilage, but might come to change if we think it would be applicable.
        /*
        //check if applicable for application self admin privilege
        if (session.ClientCertificate != null)
        {
            if (VerifiyApplicationRegistered(session))
            {
                ImpersonateAsApplicationSelfAdmin(session, args);
            }
        }
        */

        throw new ServiceResultException(StatusCodes.BadIdentityTokenRejected, "Unsupported identity token!");
    }

    /// <summary>
    /// Verifies if an Application is registered with the provided certificate at at the GDS
    /// </summary>
    /// <param name="session">the session</param>
    /// <returns></returns>
    protected bool VerifiyApplicationRegistered(Session session)
    {
        X509Certificate2 applicationInstanceCertificate = session.ClientCertificate;
        bool applicationRegistered = false;

        Uri applicationUri = Utils.ParseUri(session.SessionDiagnostics.ClientDescription.ApplicationUri);
        X509Utils.DoesUrlMatchCertificate(applicationInstanceCertificate, applicationUri);

        //get access to GDS configuration section to find out ApplicationCertificatesStorePath
        GlobalDiscoveryServerConfiguration configuration =
            Configuration.ParseExtension<GlobalDiscoveryServerConfiguration>();
        if (configuration == null)
        {
            configuration = new GlobalDiscoveryServerConfiguration();
        }
        //check if application certificate is in the Store of the GDS
        var certificateStoreIdentifier = new CertificateStoreIdentifier(configuration.ApplicationCertificatesStorePath);
        using (ICertificateStore ApplicationsStore = certificateStoreIdentifier.OpenStore(MessageContext.Telemetry))
        {
            X509Certificate2Collection matchingCerts = ApplicationsStore
                .FindByThumbprintAsync(applicationInstanceCertificate.Thumbprint)
                .Result;

            if (matchingCerts.Contains(applicationInstanceCertificate))
            {
                applicationRegistered = true;
            }
        }
        //skip revocation check if application is not registered
        if (!applicationRegistered)
        {
            return false;
        }
        //check if application certificate is revoked
        certificateStoreIdentifier = new CertificateStoreIdentifier(configuration.AuthoritiesStorePath);
        using (ICertificateStore AuthoritiesStore = certificateStoreIdentifier.OpenStore(MessageContext.Telemetry))
        {
            X509CRLCollection crls = AuthoritiesStore.EnumerateCRLsAsync().Result;
            foreach (X509CRL crl in crls)
            {
                if (crl.IsRevoked(applicationInstanceCertificate))
                {
                    applicationRegistered = false;
                }
            }
        }
        return applicationRegistered;
    }

    /// <summary>
    /// Verifies that a certificate user token is trusted.
    /// </summary>
    protected void VerifyUserTokenCertificate(X509Certificate2 certificate, CancellationToken ct = default)
    {
        try
        {
            CertificateValidator.ValidateAsync(certificate, ct);
        }
        catch (Exception e)
        {
            TranslationInfo info;
            StatusCode result = StatusCodes.BadIdentityTokenRejected;
            if (e is ServiceResultException se && se.StatusCode == StatusCodes.BadCertificateUseNotAllowed)
            {
                info = new TranslationInfo(
                    "InvalidCertificate",
                    "en-US",
                    "'{0}' is an invalid user certificate.",
                    certificate.Subject
                );

                result = StatusCodes.BadIdentityTokenInvalid;
            }
            else
            {
                // construct translation object with default text.
                info = new TranslationInfo(
                    "UntrustedCertificate",
                    "en-US",
                    "'{0}' is not a trusted user certificate.",
                    certificate.Subject
                );
            }

            // create an exception with a vendor defined sub-code.
            throw new ServiceResultException(new ServiceResult(result, info.Key));
        }
    }

    protected bool VerifyPassword(UserNameIdentityToken userNameToken)
    {
        return m_userDatabase.CheckCredentials(userNameToken.UserName, userNameToken.DecryptedPassword);
    }

    /// <summary>
    /// Impersonates the current Session as ApplicationSelfAdmin
    /// </summary>
    /// <param name="session">the current session</param>
    /// <param name="args">the impersonateEventArgs</param>
    protected void ImpersonateAsApplicationSelfAdmin(Session session, ImpersonateEventArgs args)
    {
        string applicationUri = session.SessionDiagnostics.ClientDescription.ApplicationUri;
        ApplicationRecordDataType[] application = m_database.FindApplications(applicationUri);
        if (application == null || application.Length != 1)
        {
            m_logger.LogInformation(
                "Cannot login based on ApplicationInstanceCertificate, no unique result for Application with URI: {0}",
                applicationUri
            );
            return;
        }
        NodeId applicationId = application.FirstOrDefault()!.ApplicationId;
        m_logger.LogInformation(
            "Application {0} accepted based on ApplicationInstanceCertificate as ApplicationSelfAdmin",
            applicationUri
        );
        args.Identity = new GdsRoleBasedIdentity(
            new UserIdentity(),
            new List<Role> { GdsRole.ApplicationSelfAdmin },
            applicationId
        );
        return;
    }

    #endregion

    #region Private Fields
    private Dictionary<uint, ImpersonationContext> m_contexts = new Dictionary<uint, ImpersonationContext>();
    protected IApplicationsDatabase m_database;
    private ICertificateRequest m_request;
    private ICertificateGroup m_certificateGroup;
    protected IUserDatabase m_userDatabase;
    private bool m_autoApprove;
    private object m_lock = new();
    #endregion
}
