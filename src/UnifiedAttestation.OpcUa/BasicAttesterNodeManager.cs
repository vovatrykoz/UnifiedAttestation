using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Gds.Server;
using Opc.Ua.Server;

namespace UnifiedAttestation.OpcUa;

public sealed class BasicAttesterNodeManager : CustomNodeManager2
{
    public BasicAttesterNodeManager(
        IServerInternal server,
        ApplicationConfiguration configuration,
        IAttestingEnvironment attestingEnvironment
    )
        : base(server, configuration, "urn:unifiedattestation:attester")
    {
        SystemContext.NodeIdFactory = this;
        AttestingEnvironment = attestingEnvironment;
    }

    public IAttestingEnvironment AttestingEnvironment { get; }

    private ServiceResult OnGetAttestationDataCall(
        ISystemContext context,
        MethodState method,
        IList<object> inputArguments,
        IList<object> outputArguments
    )
    {
        m_logger.LogInformation("GetAttestationData was called!");
        if (inputArguments.Count < 1)
        {
            m_logger.LogWarning("No nonce provided on GetAttestationData call");
            return new ServiceResult(StatusCodes.BadInternalError);
        }

        if (inputArguments[0] is not byte[] nonce)
        {
            m_logger.LogWarning("Nonce for GetAttestationData was invalid or not provided");
            return new ServiceResult(StatusCodes.BadInvalidArgument);
        }

        if (outputArguments.Count < 1)
        {
            m_logger.LogWarning("Output argument list for GetAttestationData was empty");
            return new ServiceResult(StatusCodes.BadInternalError);
        }

        try
        {
            Thread.Sleep(2000); // simulate work
            outputArguments[0] = AttestingEnvironment.GetAttestationData(nonce).ToBytes();
            return ServiceResult.Good;
        }
        catch (Exception ex)
        {
            m_logger.LogError(ex, "Exception during attestation data retrieval");
            return new ServiceResult(StatusCodes.BadInternalError);
        }
    }

    public override void CreateAddressSpace(IDictionary<NodeId, IList<IReference>> externalReferences)
    {
        base.CreateAddressSpace(externalReferences);

        var attestationObject = new BaseObjectState(null)
        {
            NodeId = new NodeId("Attestation", NamespaceIndex),
            BrowseName = new QualifiedName("Attestation", NamespaceIndex),
            DisplayName = "Attestation",
            TypeDefinitionId = ObjectTypeIds.BaseObjectType,
            RolePermissions =
            [
                new RolePermissionType
                {
                    RoleId = ObjectIds.WellKnownRole_SecurityAdmin,
                    Permissions =
                        (uint)PermissionType.Browse
                        | (uint)PermissionType.Read
                        | (uint)PermissionType.ReadRolePermissions
                        | (uint)PermissionType.ReadHistory,
                },
                new RolePermissionType
                {
                    RoleId = GdsRole.DiscoveryAdmin.RoleId,
                    Permissions =
                        (uint)PermissionType.Browse
                        | (uint)PermissionType.Call
                        | (uint)PermissionType.Read
                        | (uint)PermissionType.ReadRolePermissions
                        | (uint)PermissionType.ReadHistory,
                },
                new RolePermissionType
                {
                    RoleId = GdsRole.CertificateAuthorityAdmin.RoleId,
                    Permissions =
                        (uint)PermissionType.Browse
                        | (uint)PermissionType.Call
                        | (uint)PermissionType.Read
                        | (uint)PermissionType.ReadRolePermissions
                        | (uint)PermissionType.ReadHistory,
                },
            ],
        };

        if (!externalReferences.TryGetValue(ObjectIds.Server, out IList<IReference>? references))
        {
            references = [];
            externalReferences[ObjectIds.Server] = references;
        }
        references.Add(new NodeStateReference(ReferenceTypeIds.Organizes, false, attestationObject.NodeId));

        var getAttestationDataMethod = new MethodState(attestationObject)
        {
            NodeId = new NodeId("GetAttestationData", NamespaceIndex),
            BrowseName = new QualifiedName("GetAttestationData", NamespaceIndex),
            DisplayName = "Get Attestation Data",
            Description = "Requests attestation data",
            Executable = true,
            UserExecutable = true,
            OnCallMethod = new GenericMethodCalledEventHandler(OnGetAttestationDataCall),
            RolePermissions = new[]
            {
                new RolePermissionType
                {
                    RoleId = ObjectIds.WellKnownRole_SecurityAdmin,
                    Permissions =
                        (uint)PermissionType.Browse
                        | (uint)PermissionType.Call
                        | (uint)PermissionType.Read
                        | (uint)PermissionType.ReadRolePermissions
                        | (uint)PermissionType.ReadHistory,
                },
                new RolePermissionType
                {
                    RoleId = GdsRole.DiscoveryAdmin.RoleId,
                    Permissions =
                        (uint)PermissionType.Browse
                        | (uint)PermissionType.Call
                        | (uint)PermissionType.Read
                        | (uint)PermissionType.ReadRolePermissions
                        | (uint)PermissionType.ReadHistory,
                },
                new RolePermissionType
                {
                    RoleId = GdsRole.CertificateAuthorityAdmin.RoleId,
                    Permissions =
                        (uint)PermissionType.Browse
                        | (uint)PermissionType.Call
                        | (uint)PermissionType.Read
                        | (uint)PermissionType.ReadRolePermissions
                        | (uint)PermissionType.ReadHistory,
                },
            },
            InputArguments = new PropertyState<Argument[]>(attestationObject)
            {
                NodeId = new NodeId("GetAttestationData_InputArgs", NamespaceIndex),
                BrowseName = BrowseNames.InputArguments,
                DisplayName = "Input Arguments",
                TypeDefinitionId = VariableTypeIds.PropertyType,
                ReferenceTypeId = ReferenceTypeIds.HasProperty,
                ValueRank = ValueRanks.OneDimension,
                ArrayDimensions = new ReadOnlyList<uint>(new uint[] { 0 }),
                DataType = DataTypeIds.Argument,
                Value =
                [
                    new Argument
                    {
                        Name = "Nonce",
                        Description = "Nonce",
                        DataType = DataTypeIds.ByteString,
                        ValueRank = ValueRanks.Scalar,
                    },
                ],
            },
            OutputArguments = new PropertyState<Argument[]>(attestationObject)
            {
                NodeId = new NodeId("GetAttestationData_OutputArgs", NamespaceIndex),
                BrowseName = BrowseNames.OutputArguments,
                DisplayName = "Output Arguments",
                TypeDefinitionId = VariableTypeIds.PropertyType,
                ReferenceTypeId = ReferenceTypeIds.HasProperty,
                ValueRank = ValueRanks.OneDimension,
                ArrayDimensions = new ReadOnlyList<uint>(new uint[] { 0 }),
                DataType = DataTypeIds.Argument,
                Value =
                [
                    new Argument
                    {
                        Name = "Result",
                        Description = "Call result",
                        DataType = DataTypeIds.ByteString,
                        ValueRank = ValueRanks.Scalar,
                    },
                ],
            },
        };

        attestationObject.AddChild(getAttestationDataMethod);
        attestationObject.AddReference(ReferenceTypeIds.HasComponent, false, getAttestationDataMethod.NodeId);

        AddPredefinedNode(SystemContext, attestationObject);
        AddPredefinedNode(SystemContext, getAttestationDataMethod);
    }
}
