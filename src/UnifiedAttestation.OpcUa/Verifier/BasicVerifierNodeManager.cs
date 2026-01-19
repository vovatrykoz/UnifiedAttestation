using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Gds.Server;
using Opc.Ua.Server;
using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.OpcUa.Encoding;

namespace UnifiedAttestation.OpcUa.Verifier;

public sealed class BasicVerifierNodeManager : CustomNodeManager2
{
    public BasicVerifierNodeManager(
        IServerInternal server,
        ApplicationConfiguration configuration,
        IAttestingEnvironment attestingEnvironment,
        VerificationService<TpmEvidence, TpmEndorsement, TpmReferenceValues, TpmAttestationResult> verificationService
    )
        : base(server, configuration, "http://mycompany.com/MyOpcUa/")
    {
        AttestingEnvironment = attestingEnvironment;
        VerificationService = verificationService;
    }

    public IAttestingEnvironment AttestingEnvironment { get; }

    public VerificationService<
        TpmEvidence,
        TpmEndorsement,
        TpmReferenceValues,
        TpmAttestationResult
    > VerificationService { get; }

    private ServiceResult OnAppraiseEvidenceCall(
        ISystemContext context,
        MethodState method,
        IList<object> inputArguments,
        IList<object> outputArguments
    )
    {
        m_logger.LogInformation("AppraiseEvidence was called!");
        if (inputArguments.Count < 3)
        {
            m_logger.LogWarning(
                $"Not enough arguments provided for AppraiseEvidence method. Given {inputArguments.Count} but expect 2",
                inputArguments.Count
            );
            return new ServiceResult(StatusCodes.BadInternalError);
        }

        if (inputArguments[0] is not Uuid id)
        {
            m_logger.LogWarning("Entity ID was invalid or not provided");
            return new ServiceResult(StatusCodes.BadArgumentsMissing);
        }

        if (inputArguments[1] is not byte[] evidenceBytes)
        {
            m_logger.LogWarning("Evidence for AppraiseEvidence was invalid or not provided");
            return new ServiceResult(StatusCodes.BadArgumentsMissing);
        }

        if (inputArguments[2] is not byte[] nonce)
        {
            m_logger.LogWarning("Nonce for AppraiseEvidence was invalid or not provided");
            return new ServiceResult(StatusCodes.BadArgumentsMissing);
        }

        if (outputArguments.Count < 1)
        {
            m_logger.LogWarning("Output argument list for AppraiseEvidence was empty");
            return new ServiceResult(StatusCodes.BadInternalError);
        }

        try
        {
            CborCmw cborCmw = CborCmw.FromBytes(evidenceBytes);
            if (cborCmw.ContentId != 60)
            {
                m_logger.LogError("Only CBOR is supported (contentId = 60). Got: {Actual}", cborCmw.ContentId);
                return new ServiceResult(StatusCodes.BadNotSupported);
            }

            if (cborCmw.CmType != ConceptualMessageTypes.Evidence)
            {
                m_logger.LogError(
                    "Expected evidence ({Expected}). Got: {Actual}",
                    ConceptualMessageTypes.Evidence,
                    cborCmw.CmType
                );
                return new ServiceResult(StatusCodes.BadInvalidArgument);
            }

            var evidence = TpmEvidence.Decode(cborCmw.Value);
            TpmAttestationResult result = VerificationService.VerifyAsync(id, evidence, nonce).GetAwaiter().GetResult();
            byte[] resultBytes = result.Encode();
            var cborResult = new CborCmw(60, resultBytes, ConceptualMessageTypes.AttestationResult);

            outputArguments[0] = cborResult.ToBytes();
            return ServiceResult.Good;
        }
        catch (Exception ex)
        {
            m_logger.LogError(ex, "Exception during appraisal");
            return new ServiceResult(StatusCodes.BadInternalError);
        }
    }

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
            return new ServiceResult(StatusCodes.BadArgumentsMissing);
        }

        if (outputArguments.Count < 1)
        {
            m_logger.LogWarning("Output argument list for GetAttestationData was empty");
            return new ServiceResult(StatusCodes.BadInternalError);
        }

        try
        {
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
                new RolePermissionType
                {
                    RoleId = GdsRole.ApplicationSelfAdmin.RoleId,
                    Permissions =
                        (uint)PermissionType.Browse
                        | (uint)PermissionType.Call
                        | (uint)PermissionType.Read
                        | (uint)PermissionType.ReadRolePermissions
                        | (uint)PermissionType.ReadHistory,
                },
            },
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
                new RolePermissionType
                {
                    RoleId = GdsRole.ApplicationSelfAdmin.RoleId,
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

        var appraiseEvidenceMethod = new MethodState(attestationObject)
        {
            NodeId = new NodeId("AppraiseEvidence", NamespaceIndex),
            BrowseName = new QualifiedName("AppraiseEvidence", NamespaceIndex),
            DisplayName = "Appraise Evidence",
            Description = "Appraises evidence",
            Executable = true,
            UserExecutable = true,
            OnCallMethod = new GenericMethodCalledEventHandler(OnAppraiseEvidenceCall),
            RolePermissions =
            [
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
            ],
            InputArguments = new PropertyState<Argument[]>(attestationObject)
            {
                NodeId = new NodeId("AppraiseEvidence_InputArgs", NamespaceIndex),
                BrowseName = BrowseNames.InputArguments,
                DisplayName = "Input Arguments",
                TypeDefinitionId = VariableTypeIds.PropertyType,
                ReferenceTypeId = ReferenceTypeIds.HasProperty,
                ValueRank = ValueRanks.OneDimension,
                ArrayDimensions = new ReadOnlyList<uint>([0]),
                DataType = DataTypeIds.Argument,
                Value =
                [
                    new Argument
                    {
                        Name = "EntityId",
                        Description = "Entity Id",
                        DataType = DataTypeIds.Guid,
                        ValueRank = ValueRanks.Scalar,
                    },
                    new Argument
                    {
                        Name = "Evidence",
                        Description = "Evidence",
                        DataType = DataTypeIds.ByteString,
                        ValueRank = ValueRanks.Scalar,
                    },
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
                NodeId = new NodeId("AppraiseEvidence_OutputArgs", NamespaceIndex),
                BrowseName = BrowseNames.OutputArguments,
                DisplayName = "Output Arguments",
                TypeDefinitionId = VariableTypeIds.PropertyType,
                ReferenceTypeId = ReferenceTypeIds.HasProperty,
                ValueRank = ValueRanks.OneDimension,
                ArrayDimensions = new ReadOnlyList<uint>([0]),
                DataType = DataTypeIds.Argument,
                Value =
                [
                    new Argument
                    {
                        Name = "AppraisalResult",
                        Description = "Appraisal result",
                        DataType = DataTypeIds.ByteString,
                        ValueRank = ValueRanks.Scalar,
                    },
                ],
            },
        };

        attestationObject.AddChild(getAttestationDataMethod);
        attestationObject.AddReference(ReferenceTypeIds.HasComponent, false, getAttestationDataMethod.NodeId);

        attestationObject.AddChild(appraiseEvidenceMethod);
        attestationObject.AddReference(ReferenceTypeIds.HasComponent, false, appraiseEvidenceMethod.NodeId);

        AddPredefinedNode(SystemContext, attestationObject);
        AddPredefinedNode(SystemContext, getAttestationDataMethod);
        AddPredefinedNode(SystemContext, appraiseEvidenceMethod);
    }
}
