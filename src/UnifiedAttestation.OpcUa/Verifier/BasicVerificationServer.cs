using Opc.Ua;
using Opc.Ua.Server;
using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Entities;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.OpcUa;

namespace UnifiedAttestation.OpcUa.Verifier;

public sealed class BasicVerificationServer : StandardServer
{
    public BasicVerificationServer(
        IAttestingEnvironment attester,
        VerificationService<TpmEvidence, TpmEndorsement, TpmReferenceValues, TpmAttestationResult> verificationService
    )
    {
        AttestingEnvironment = attester;
        VerificationService = verificationService;
    }

    public IAttestingEnvironment AttestingEnvironment { get; }

    public VerificationService<
        TpmEvidence,
        TpmEndorsement,
        TpmReferenceValues,
        TpmAttestationResult
    > VerificationService { get; }

    protected override ServerProperties LoadServerProperties()
    {
        return new ServerProperties
        {
            ManufacturerName = "ABB",
            ProductName = "ABB.OPC.UA",
            ProductUri = "urn:abb:abbopcua",
            SoftwareVersion = "1.0.0",
            BuildNumber = "1",
            BuildDate = DateTime.UtcNow,
        };
    }

    protected override MasterNodeManager CreateMasterNodeManager(
        IServerInternal server,
        ApplicationConfiguration configuration
    )
    {
        var basicManager = new BasicVerifierNodeManager(
            server,
            configuration,
            AttestingEnvironment,
            VerificationService
        );
        return new MasterNodeManager(server, configuration, null, basicManager);
    }

    protected override void OnServerStarted(IServerInternal server)
    {
        base.OnServerStarted(server);
        server.SessionManager.ImpersonateUser += new ImpersonateEventHandler(SessionManager_ImpersonateUser);
    }

    private void SessionManager_ImpersonateUser(ISession session, ImpersonateEventArgs args)
    {
        if (args.NewIdentity is UserNameIdentityToken usernameToken)
        {
            args.Identity = VerifyPassword(usernameToken);
            Console.WriteLine($"Token accepted for {args.Identity?.DisplayName}");
            return;
        }

        if (args.NewIdentity is AnonymousIdentityToken or null)
        {
            args.Identity = new RoleBasedIdentity(new UserIdentity(), [Role.Anonymous]);
            Console.WriteLine($"Token accepted for anonymous user");
            return;
        }

        throw ServiceResultException.Create(
            StatusCodes.BadIdentityTokenInvalid,
            "The provided identity token is not supported on the server."
        );
    }

    private static RoleBasedIdentity VerifyPassword(UserNameIdentityToken userNameToken)
    {
        string username = userNameToken.UserName;
        string password = System.Text.Encoding.UTF8.GetString(userNameToken.DecryptedPassword);

        if (string.IsNullOrEmpty(username))
        {
            throw ServiceResultException.Create(
                StatusCodes.BadIdentityTokenInvalid,
                "Security token is not a valid username token. An empty username is not accepted."
            );
        }

        if (string.IsNullOrEmpty(password))
        {
            throw ServiceResultException.Create(
                StatusCodes.BadIdentityTokenInvalid,
                "Security token is not a valid username token. An empty password is not accepted."
            );
        }

        return (username, password) switch
        {
            ("admin", "demo") => new RoleBasedIdentity(new UserIdentity(userNameToken), [Role.SecurityAdmin]),
            ("user", "password") => new RoleBasedIdentity(new UserIdentity(userNameToken), [Role.AuthenticatedUser]),
            _ => throw ServiceResultException.Create(
                StatusCodes.BadIdentityTokenRejected,
                "Invalid credentials provided."
            ),
        };
    }
}
