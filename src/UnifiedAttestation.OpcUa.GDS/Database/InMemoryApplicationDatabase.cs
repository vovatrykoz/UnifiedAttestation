using Newtonsoft.Json;
using Opc.Ua;
using Opc.Ua.Gds;
using Opc.Ua.Gds.Server;
using Opc.Ua.Gds.Server.Database;

namespace UnifiedAttestation.OpcUa.GDS.Database;

public class InMemoryApplicationsDatabase : ApplicationsDatabaseBase, ICertificateRequest
{
    #region IApplicationsDatabase Members

    public override void Initialize()
    {
        lock (m_lock)
        {
            m_applications.Clear();
            m_certificateRequests.Clear();
            m_lastCounterResetTime = DateTime.UtcNow;
            m_nextId = 1;
        }
    }

    public override NodeId RegisterApplication(ApplicationRecordDataType application)
    {
        NodeId appNodeId = base.RegisterApplication(application);
        if (NodeId.IsNull(appNodeId))
        {
            appNodeId = new NodeId(Guid.NewGuid(), NamespaceIndex);
        }

        Guid applicationId = GetNodeIdGuid(appNodeId);
        string capabilities = base.ServerCapabilities(application);

        lock (m_lock)
        {
            ApplicationRecord? record = null;

            if (applicationId != Guid.Empty && m_applications.ContainsKey(applicationId))
            {
                record = m_applications[applicationId];
                //If the application record already exists, clear it from the server endpoints and the applicaiton names
                record.ServerEndpoints.Clear();
                record.ApplicationNames.Clear();
            }

            bool isNew = false;

            if (record == null)
            {
                applicationId = Guid.NewGuid();
                record = new ApplicationRecord { ID = m_nextId++, ApplicationId = applicationId };
                isNew = true;
            }

            //Updating the record with the application data
            //Exact copy
            record.ApplicationUri = application.ApplicationUri;
            record.ApplicationName = application.ApplicationNames[0].Text;
            record.ApplicationType = (int)application.ApplicationType;
            record.ProductUri = application.ProductUri;
            record.ServerCapabilities = capabilities;

            if (isNew)
            {
                m_applications[applicationId] = record;
            }

            if (application.DiscoveryUrls != null)
            {
                foreach (var discoveryUrl in application.DiscoveryUrls)
                {
                    record.ServerEndpoints.Add(
                        new ServerEndpointRecord
                        {
                            ID = m_nextId++,
                            ApplicationId = record.ID,
                            DiscoveryUrl = discoveryUrl,
                        }
                    );
                }
            }

            if (application.ApplicationNames != null && application.ApplicationNames.Count >= 1)
            {
                foreach (var applicationName in application.ApplicationNames)
                {
                    record.ApplicationNames.Add(
                        new ApplicationNameRecord
                        {
                            ID = m_nextId++,
                            ApplicationId = record.ID,
                            Locale = applicationName.Locale,
                            Text = applicationName.Text,
                        }
                    );
                }
            }

            m_lastCounterResetTime = DateTime.UtcNow;
            return new NodeId(applicationId, NamespaceIndex);
        }
    }

    public override void UnregisterApplication(NodeId applicationId)
    {
        Guid id = GetNodeIdGuid(applicationId);

        //Isn't used in the original code?
        //List<byte[]> certificates = new List<byte[]>();

        lock (m_lock)
        {
            //Check if the application exists, otherwise not much to register.
            if (!m_applications.ContainsKey(id))
            {
                throw new ArgumentException(
                    "A record with the specified application id does not exist.",
                    nameof(applicationId)
                );
            }

            var application = m_applications[id];

            //Removing all certificate requests for application with the specified id!
            var requestsToRemove = m_certificateRequests
                .Values.Where(r => r.ApplicationId == application.ID)
                .Select(r => r.RequestId)
                .ToList();

            foreach (var requestId in requestsToRemove)
            {
                m_certificateRequests.Remove(requestId);
            }

            //Then just remove the application itself.
            m_applications.Remove(id);
            m_lastCounterResetTime = DateTime.UtcNow;
        }
    }

    public override ApplicationRecordDataType? GetApplication(NodeId applicationId)
    {
        Guid id = GetNodeIdGuid(applicationId);

        lock (m_lock)
        {
            //Return null if the application doesn't exist.
            if (!m_applications.ContainsKey(id))
            {
                return null;
            }

            //If the application exists, get the record.
            var result = m_applications[id];

            LocalizedTextCollection names = new LocalizedTextCollection();
            if (result.ApplicationNames != null && result.ApplicationNames.Count > 0)
            {
                foreach (var entry in result.ApplicationNames)
                {
                    if (entry.Text != null)
                    {
                        names.Add(new LocalizedText(entry.Locale ?? string.Empty, entry.Text));
                    }
                }
            }
            else if (result.ApplicationName != null)
            {
                names.Add(new LocalizedText(result.ApplicationName));
            }

            StringCollection? discoveryUrls = null;

            if (result.ServerEndpoints != null && result.ServerEndpoints.Count > 0)
            {
                discoveryUrls = new StringCollection();

                foreach (var endpoint in result.ServerEndpoints)
                {
                    if (endpoint.DiscoveryUrl != null)
                    {
                        discoveryUrls.Add(endpoint.DiscoveryUrl);
                    }
                }
            }

            //Exactly the same as the original code, but with null checks!
            string[]? capabilities = null;

            if (!string.IsNullOrEmpty(result.ServerCapabilities))
            {
                capabilities = result.ServerCapabilities.Split(',');
            }

            return new ApplicationRecordDataType
            {
                ApplicationId = new NodeId(result.ApplicationId, NamespaceIndex),
                ApplicationUri = result.ApplicationUri ?? string.Empty,
                ApplicationType = (ApplicationType)result.ApplicationType,
                ApplicationNames = names,
                ProductUri = result.ProductUri ?? string.Empty,
                DiscoveryUrls = discoveryUrls ?? new StringCollection(),
                ServerCapabilities = capabilities ?? Array.Empty<string>(),
            };
        }
    }

    public override ApplicationRecordDataType[] FindApplications(string applicationUri)
    {
        lock (m_lock)
        {
            //LINQ accomplishes the same functionality as the database query in the original code.
            //Essentially getting all instances with the specified application uri.
            var results = m_applications.Values.Where(x => x.ApplicationUri == applicationUri).ToList();

            List<ApplicationRecordDataType> records = new List<ApplicationRecordDataType>();

            foreach (var result in results)
            {
                LocalizedText[]? names = null;

                if (result.ApplicationName != null)
                {
                    names = new LocalizedText[] { new LocalizedText(result.ApplicationName) };
                }

                StringCollection? discoveryUrls = null;

                if (result.ServerEndpoints != null && result.ServerEndpoints.Count > 0)
                {
                    discoveryUrls = new StringCollection();

                    foreach (var endpoint in result.ServerEndpoints)
                    {
                        if (endpoint.DiscoveryUrl != null)
                        {
                            discoveryUrls.Add(endpoint.DiscoveryUrl);
                        }
                    }
                }

                string[]? capabilities = null;

                if (!string.IsNullOrEmpty(result.ServerCapabilities))
                {
                    capabilities = result.ServerCapabilities.Split(',');
                }

                records.Add(
                    new ApplicationRecordDataType
                    {
                        ApplicationId = new NodeId(result.ApplicationId, NamespaceIndex),
                        ApplicationUri = result.ApplicationUri ?? string.Empty,
                        ApplicationType = (ApplicationType)result.ApplicationType,
                        ApplicationNames = new LocalizedTextCollection(names),
                        ProductUri = result.ProductUri ?? string.Empty,
                        DiscoveryUrls = discoveryUrls ?? new StringCollection(),
                        ServerCapabilities = capabilities ?? Array.Empty<string>(),
                    }
                );
            }

            return records.ToArray();
        }
    }

    public override ApplicationDescription[] QueryApplications(
        uint startingRecordId,
        uint maxRecordsToReturn,
        string applicationName,
        string applicationUri,
        uint applicationType,
        string productUri,
        string[] serverCapabilities,
        out DateTime lastCounterResetTime,
        out uint nextRecordId
    )
    {
        lastCounterResetTime = DateTime.MinValue;
        nextRecordId = 0;
        var records = new List<ApplicationDescription>();

        lock (m_lock)
        {
            lastCounterResetTime = m_lastCounterResetTime;

            //Same here, LINQ is used!
            var results = m_applications
                .Values.Where(x => (int)startingRecordId == 0 || (int)startingRecordId <= x.ID)
                .OrderBy(x => x.ID)
                .ToList();

            int lastID = 0;

            foreach (var result in results)
            {
                //exactly the same as the original code.
                if (!String.IsNullOrEmpty(applicationName))
                {
                    if (!Match(result.ApplicationName, applicationName))
                    {
                        continue;
                    }
                }

                if (!String.IsNullOrEmpty(applicationUri))
                {
                    if (!Match(result.ApplicationUri, applicationUri))
                    {
                        continue;
                    }
                }

                if (!String.IsNullOrEmpty(productUri))
                {
                    if (!Match(result.ProductUri, productUri))
                    {
                        continue;
                    }
                }

                string[]? capabilities = null;
                if (!String.IsNullOrEmpty(result.ServerCapabilities))
                {
                    capabilities = result.ServerCapabilities.Split(',');
                }

                if (serverCapabilities != null && serverCapabilities.Length > 0)
                {
                    bool match = true;

                    for (int ii = 0; ii < serverCapabilities.Length; ii++)
                    {
                        if (capabilities == null || !capabilities.Contains(serverCapabilities[ii]))
                        {
                            match = false;
                            break;
                        }
                    }

                    if (!match)
                    {
                        continue;
                    }
                }

                // type filter, 0 and 3 returns all
                // filter for servers
                if (applicationType == 1 && result.ApplicationType == (int)ApplicationType.Client)
                {
                    continue;
                }
                else // filter for clients
                if (
                    applicationType == 2
                    && result.ApplicationType != (int)ApplicationType.Client
                    && result.ApplicationType != (int)ApplicationType.ClientAndServer
                )
                {
                    continue;
                }

                var discoveryUrls = new StringCollection();
                if (result.ServerEndpoints != null)
                {
                    //Original code have duplicated initializations of discoveryUrls?
                    //discoveryUrls = new StringCollection();

                    foreach (var endpoint in result.ServerEndpoints)
                    {
                        discoveryUrls.Add(endpoint.DiscoveryUrl);
                    }
                }

                if (lastID == 0)
                {
                    lastID = result.ID;
                }
                else
                {
                    if (maxRecordsToReturn != 0 && records.Count >= maxRecordsToReturn)
                    {
                        break;
                    }

                    lastID = result.ID;
                }

                records.Add(
                    new ApplicationDescription
                    {
                        ApplicationUri = result.ApplicationUri,
                        ProductUri = result.ProductUri,
                        ApplicationName = result.ApplicationName,
                        ApplicationType = (ApplicationType)result.ApplicationType,
                        GatewayServerUri = null,
                        DiscoveryProfileUri = null,
                        DiscoveryUrls = discoveryUrls,
                    }
                );
                nextRecordId = (uint)lastID + 1;
            }

            return records.ToArray();
        }
    }

    public override ServerOnNetwork[] QueryServers(
        uint startingRecordId,
        uint maxRecordsToReturn,
        string applicationName,
        string applicationUri,
        string productUri,
        string[] serverCapabilities,
        out DateTime lastCounterResetTime
    )
    {
        lock (m_lock)
        {
            lastCounterResetTime = m_lastCounterResetTime;

            var results = m_applications
                .Values.SelectMany(app =>
                    app.ServerEndpoints.Select(endpoint => new
                    {
                        ID = endpoint.ID,
                        ApplicationName = app.ApplicationName,
                        ApplicationUri = app.ApplicationUri,
                        ProductUri = app.ProductUri,
                        DiscoveryUrl = endpoint.DiscoveryUrl,
                        ServerCapabilities = app.ServerCapabilities,
                    })
                )
                .Where(item => (int)startingRecordId == 0 || (int)startingRecordId <= item.ID)
                .OrderBy(item => item.ID);

            List<ServerOnNetwork> records = new List<ServerOnNetwork>();
            int lastID = 0;

            //Exactly the same as the original code (with some additional null checks).
            foreach (var result in results)
            {
                if (!String.IsNullOrEmpty(applicationName))
                {
                    if (!Match(result.ApplicationName, applicationName))
                    {
                        continue;
                    }
                }

                if (!String.IsNullOrEmpty(applicationUri))
                {
                    if (!Match(result.ApplicationUri, applicationUri))
                    {
                        continue;
                    }
                }

                if (!String.IsNullOrEmpty(productUri))
                {
                    if (!Match(result.ProductUri, productUri))
                    {
                        continue;
                    }
                }

                string[]? capabilities = null;
                if (!String.IsNullOrEmpty(result.ServerCapabilities))
                {
                    capabilities = result.ServerCapabilities.Split(',');
                }

                if (serverCapabilities != null && serverCapabilities.Length > 0)
                {
                    bool match = true;

                    for (int ii = 0; ii < serverCapabilities.Length; ii++)
                    {
                        if (capabilities == null || !capabilities.Contains(serverCapabilities[ii]))
                        {
                            match = false;
                            break;
                        }
                    }

                    if (!match)
                    {
                        continue;
                    }
                }

                if (lastID == 0)
                {
                    lastID = result.ID;
                }
                else
                {
                    if (maxRecordsToReturn != 0 && lastID != result.ID && records.Count >= maxRecordsToReturn)
                    {
                        break;
                    }

                    lastID = result.ID;
                }

                records.Add(
                    new ServerOnNetwork
                    {
                        RecordId = (uint)result.ID,
                        ServerName = result.ApplicationName ?? string.Empty,
                        DiscoveryUrl = result.DiscoveryUrl ?? string.Empty,
                        ServerCapabilities = capabilities ?? Array.Empty<string>(),
                    }
                );
            }

            return records.ToArray();
        }
    }

    public override bool SetApplicationCertificate(NodeId applicationId, string certificateTypeId, byte[] certificate)
    {
        Guid id = GetNodeIdGuid(applicationId);

        if (
            certificateTypeId.Equals(
                nameof(Opc.Ua.ObjectTypeIds.UserCertificateType),
                StringComparison.OrdinalIgnoreCase
            )
        )
        {
            return false;
        }

        lock (m_lock)
        {
            if (!m_applications.ContainsKey(id))
            {
                return false;
            }

            var result = m_applications[id];

            if (
                certificateTypeId.Equals(
                    nameof(Opc.Ua.ObjectTypeIds.HttpsCertificateType),
                    StringComparison.OrdinalIgnoreCase
                )
            )
            {
                result.HttpsCertificate = certificate;
            }
            else
            {
                result.Certificate = certificate;
            }

            return true;
        }
    }

    public override bool GetApplicationCertificate(
        NodeId applicationId,
        string certificateTypeId,
        out byte[]? certificate
    )
    {
        certificate = null;

        Guid id = GetNodeIdGuid(applicationId);
        //same here, isn't used in the original code!
        //List<byte[]> certificates = new List<byte[]>();

        if (
            certificateTypeId.Equals(
                nameof(Opc.Ua.ObjectTypeIds.UserCertificateType),
                StringComparison.OrdinalIgnoreCase
            )
        )
        {
            return false;
        }

        lock (m_lock)
        {
            if (!m_applications.ContainsKey(id))
            {
                throw new ArgumentException(
                    "A record with the specified application id does not exist.",
                    nameof(applicationId)
                );
            }

            var result = m_applications[id];

            certificate = certificateTypeId.Equals(
                nameof(Opc.Ua.ObjectTypeIds.HttpsCertificateType),
                StringComparison.OrdinalIgnoreCase
            )
                ? result.HttpsCertificate
                : result.Certificate;

            return certificate != null;
        }
    }

    public override bool SetApplicationTrustLists(NodeId applicationId, string certificateTypeId, string trustListId)
    {
        Guid id = GetNodeIdGuid(applicationId);

        lock (m_lock)
        {
            if (!m_applications.ContainsKey(id))
            {
                return false;
            }

            var application = m_applications[id];

            if (certificateTypeId == null)
            {
                return false;
            }

            var existingCertificateStore = application.CertificateStores.FirstOrDefault(x =>
                x.CertificateType == certificateTypeId
            );

            if (existingCertificateStore != null)
            {
                existingCertificateStore.Path = trustListId;
            }
            else
            {
                application.CertificateStores.Add(
                    new CertificateStoreRecord
                    {
                        ID = m_nextId++,
                        ApplicationId = application.ID,
                        CertificateType = certificateTypeId,
                        Path = trustListId,
                    }
                );
            }

            return true;
        }
    }

    public override bool GetApplicationTrustLists(
        NodeId applicationId,
        string certificateTypeId,
        out string? trustListId
    )
    {
        Guid id = GetNodeIdGuid(applicationId);
        trustListId = null;

        lock (m_lock)
        {
            if (!m_applications.ContainsKey(id))
            {
                return false;
            }

            var application = m_applications[id];

            if (certificateTypeId == null)
            {
                return false;
            }

            var existingCertificateStore = application.CertificateStores.FirstOrDefault(x =>
                x.CertificateType == certificateTypeId
            );

            if (existingCertificateStore == null)
            {
                return false;
            }

            trustListId = existingCertificateStore.Path;
            return trustListId != null;
        }
    }

    #endregion

    #region ICertificateRequest

    public NodeId StartSigningRequest(
        NodeId applicationId,
        string certificateGroupId,
        string certificateTypeId,
        byte[] certificateRequest,
        string authorityId
    )
    {
        Guid id = GetNodeIdGuid(applicationId);

        lock (m_lock)
        {
            if (!m_applications.ContainsKey(id))
            {
                throw new ServiceResultException(StatusCodes.BadNodeIdUnknown);
            }

            var application = m_applications[id];

            var existingRequest = m_certificateRequests.Values.FirstOrDefault(x =>
                x.ApplicationId == application.ID && x.AuthorityId == authorityId
            );

            CertificateRequestRecord request;
            bool isNew = false;

            if (existingRequest == null)
            {
                request = new CertificateRequestRecord
                {
                    ID = m_nextId++,
                    RequestId = Guid.NewGuid(),
                    AuthorityId = authorityId,
                    ApplicationId = application.ID,
                };
                isNew = true;
            }
            else
            {
                request = existingRequest;
            }

            request.State = (int)CertificateRequestState.New;
            request.CertificateGroupId = certificateGroupId;
            request.CertificateTypeId = certificateTypeId;
            request.SubjectName = null;
            request.DomainNames = null;
            request.PrivateKeyFormat = null;
            request.PrivateKeyPassword = null;
            request.CertificateSigningRequest = certificateRequest;

            if (isNew)
            {
                m_certificateRequests[request.RequestId] = request;
            }

            return new NodeId(request.RequestId, NamespaceIndex);
        }
    }

    public NodeId StartNewKeyPairRequest(
        NodeId applicationId,
        string certificateGroupId,
        string certificateTypeId,
        string subjectName,
        string[] domainNames,
        string privateKeyFormat,
        string privateKeyPassword,
        string authorityId
    )
    {
        Guid id = GetNodeIdGuid(applicationId);

        lock (m_lock)
        {
            if (!m_applications.ContainsKey(id))
            {
                throw new ServiceResultException(StatusCodes.BadNodeIdUnknown);
            }

            var application = m_applications[id];

            var existingRequest = m_certificateRequests.Values.FirstOrDefault(x =>
                x.ApplicationId == application.ID && x.AuthorityId == authorityId
            );

            CertificateRequestRecord request;
            bool isNew = false;

            if (existingRequest == null)
            {
                request = new CertificateRequestRecord
                {
                    ID = m_nextId++,
                    RequestId = Guid.NewGuid(),
                    AuthorityId = authorityId,
                    ApplicationId = application.ID,
                };
                isNew = true;
            }
            else
            {
                request = existingRequest;
            }

            request.State = (int)CertificateRequestState.New;
            request.CertificateGroupId = certificateGroupId;
            request.CertificateTypeId = certificateTypeId;
            request.SubjectName = subjectName;
            request.DomainNames = JsonConvert.SerializeObject(domainNames);
            request.PrivateKeyFormat = privateKeyFormat;
            request.PrivateKeyPassword = privateKeyPassword;
            request.CertificateSigningRequest = null;

            if (isNew)
            {
                m_certificateRequests[request.RequestId] = request;
            }

            return new NodeId(request.RequestId, NamespaceIndex);
        }
    }

    public void ApproveRequest(NodeId requestId, bool isRejected)
    {
        Guid id = GetNodeIdGuid(requestId);

        lock (m_lock)
        {
            if (!m_certificateRequests.ContainsKey(id))
            {
                throw new ServiceResultException(StatusCodes.BadNodeIdUnknown);
            }

            var request = m_certificateRequests[id];

            if (isRejected)
            {
                request.State = (int)CertificateRequestState.Rejected;
                // erase information which is not required anymore
                request.CertificateSigningRequest = null;
                request.PrivateKeyPassword = null;
            }
            else
            {
                request.State = (int)CertificateRequestState.Approved;
            }
        }
    }

    public void AcceptRequest(NodeId requestId, byte[] certificate)
    {
        Guid id = GetNodeIdGuid(requestId);

        lock (m_lock)
        {
            if (!m_certificateRequests.ContainsKey(id))
            {
                throw new ServiceResultException(StatusCodes.BadNodeIdUnknown);
            }

            var request = m_certificateRequests[id];

            request.State = (int)CertificateRequestState.Accepted;

            // erase information which is not required anymore
            request.CertificateSigningRequest = null;
            request.PrivateKeyPassword = null;
        }
    }

    public CertificateRequestState FinishRequest(
        NodeId applicationId,
        NodeId requestId,
        out string? certificateGroupId,
        out string? certificateTypeId,
        out byte[]? signedCertificate,
        out byte[]? privateKey
    )
    {
        certificateGroupId = null;
        certificateTypeId = null;
        signedCertificate = null;
        privateKey = null;
        Guid reqId = GetNodeIdGuid(requestId);
        Guid appId = GetNodeIdGuid(applicationId);

        lock (m_lock)
        {
            if (!m_certificateRequests.ContainsKey(reqId))
            {
                throw new ServiceResultException(StatusCodes.BadInvalidArgument);
            }

            var request = m_certificateRequests[reqId];

            switch (request.State)
            {
                case (int)CertificateRequestState.New:
                    return CertificateRequestState.New;
                case (int)CertificateRequestState.Rejected:
                    return CertificateRequestState.Rejected;
                case (int)CertificateRequestState.Accepted:
                    return CertificateRequestState.Accepted;
                case (int)CertificateRequestState.Approved:
                    break;
                default:
                    throw new ServiceResultException(StatusCodes.BadInvalidArgument);
            }

            certificateGroupId = request.CertificateGroupId;
            certificateTypeId = request.CertificateTypeId;

            return CertificateRequestState.Approved;
        }
    }

    public CertificateRequestState ReadRequest(
        NodeId applicationId,
        NodeId requestId,
        out string? certificateGroupId,
        out string? certificateTypeId,
        out byte[]? certificateRequest,
        out string? subjectName,
        out string[]? domainNames,
        out string? privateKeyFormat,
        out string? privateKeyPassword
    )
    {
        certificateGroupId = null;
        certificateTypeId = null;
        certificateRequest = null;
        subjectName = null;
        domainNames = null;
        privateKeyFormat = null;
        privateKeyPassword = null;
        Guid reqId = GetNodeIdGuid(requestId);
        //Isn't used in the original code?
        //Guid appId = GetNodeIdGuid(applicationId);

        lock (m_lock)
        {
            if (!m_certificateRequests.ContainsKey(reqId))
            {
                throw new ServiceResultException(StatusCodes.BadInvalidArgument);
            }

            var request = m_certificateRequests[reqId];

            switch (request.State)
            {
                case (int)CertificateRequestState.New:
                    return CertificateRequestState.New;
                case (int)CertificateRequestState.Rejected:
                    return CertificateRequestState.Rejected;
                case (int)CertificateRequestState.Accepted:
                    return CertificateRequestState.Accepted;
                case (int)CertificateRequestState.Approved:
                    break;
                default:
                    throw new ServiceResultException(StatusCodes.BadInvalidArgument);
            }

            certificateGroupId = request.CertificateGroupId;
            certificateTypeId = request.CertificateTypeId;
            certificateRequest = request.CertificateSigningRequest;
            subjectName = request.SubjectName;
            domainNames =
                request.DomainNames != null ? JsonConvert.DeserializeObject<string[]>(request.DomainNames) : null;
            privateKeyFormat = request.PrivateKeyFormat;
            privateKeyPassword = request.PrivateKeyPassword;

            return CertificateRequestState.Approved;
        }
    }

    public NodeId StartNewKeyPairRequest(
        NodeId applicationId,
        string certificateGroupId,
        string certificateTypeId,
        string subjectName,
        string[] domainNames,
        string privateKeyFormat,
        ReadOnlySpan<char> privateKeyPassword,
        string authorityId
    )
    {
        Guid id = GetNodeIdGuid(applicationId);

        lock (m_lock)
        {
            if (!m_applications.ContainsKey(id))
            {
                throw new ServiceResultException(StatusCodes.BadNodeIdUnknown);
            }

            var application = m_applications[id];

            var existingRequest = m_certificateRequests.Values.FirstOrDefault(x =>
                x.ApplicationId == application.ID && x.AuthorityId == authorityId
            );

            CertificateRequestRecord request;
            bool isNew = false;

            if (existingRequest == null)
            {
                request = new CertificateRequestRecord
                {
                    ID = m_nextId++,
                    RequestId = Guid.NewGuid(),
                    AuthorityId = authorityId,
                    ApplicationId = application.ID,
                };
                isNew = true;
            }
            else
            {
                request = existingRequest;
            }

            request.State = (int)CertificateRequestState.New;
            request.CertificateGroupId = certificateGroupId;
            request.CertificateTypeId = certificateTypeId;
            request.SubjectName = subjectName;
            request.DomainNames = JsonConvert.SerializeObject(domainNames);
            request.PrivateKeyFormat = privateKeyFormat;
            request.PrivateKeyPassword = new(privateKeyPassword);
            request.CertificateSigningRequest = null;

            if (isNew)
            {
                m_certificateRequests[request.RequestId] = request;
            }

            return new NodeId(request.RequestId, NamespaceIndex);
        }
    }

    public CertificateRequestState ReadRequest(
        NodeId applicationId,
        NodeId requestId,
        out string certificateGroupId,
        out string certificateTypeId,
        out byte[] certificateRequest,
        out string subjectName,
        out string[] domainNames,
        out string privateKeyFormat,
        out ReadOnlySpan<char> privateKeyPassword
    )
    {
        Guid reqId = GetNodeIdGuid(requestId);
        //Isn't used in the original code?
        //Guid appId = GetNodeIdGuid(applicationId);

        lock (m_lock)
        {
            if (!m_certificateRequests.ContainsKey(reqId))
            {
                throw new ServiceResultException(StatusCodes.BadInvalidArgument);
            }

            CertificateRequestRecord request = m_certificateRequests[reqId];

            switch (request.State)
            {
                case (int)CertificateRequestState.Approved:
                    break;
                default:
                    throw new ServiceResultException(StatusCodes.BadInvalidArgument);
            }

            certificateGroupId =
                request.CertificateGroupId ?? throw new ArgumentNullException(nameof(request.CertificateGroupId));
            certificateTypeId =
                request.CertificateTypeId ?? throw new ArgumentNullException(nameof(request.CertificateTypeId));
            certificateRequest =
                request.CertificateSigningRequest
                ?? throw new ArgumentNullException(nameof(request.CertificateSigningRequest));
            subjectName = request.SubjectName ?? "SubjectName";
            domainNames =
                (request.DomainNames != null ? JsonConvert.DeserializeObject<string[]>(request.DomainNames) : null)
                ?? [];
            privateKeyFormat = request.PrivateKeyFormat ?? "";
            privateKeyPassword = request.PrivateKeyPassword ?? "";

            return CertificateRequestState.Approved;
        }
    }

    #endregion

    #region Private Fields

    //Ensure mutual exclusion.
    private readonly object m_lock = new object();
    private readonly Dictionary<Guid, ApplicationRecord> m_applications = new Dictionary<Guid, ApplicationRecord>();
    private readonly Dictionary<Guid, CertificateRequestRecord> m_certificateRequests =
        new Dictionary<Guid, CertificateRequestRecord>();
    private DateTime m_lastCounterResetTime = DateTime.UtcNow;
    private int m_nextId = 1;

    #endregion

    #region Data Structures (since using in memory database)

    //Based on database schema defined in gdsdb.edmx.sql
    internal class ApplicationRecord
    {
        public int ID { get; set; }
        public Guid ApplicationId { get; set; }
        public string? ApplicationUri { get; set; }
        public string? ApplicationName { get; set; }
        public int ApplicationType { get; set; }
        public string? ProductUri { get; set; }
        public string? ServerCapabilities { get; set; }
        public byte[]? Certificate { get; set; }
        public byte[]? HttpsCertificate { get; set; }
        public List<ApplicationNameRecord> ApplicationNames { get; set; } = new List<ApplicationNameRecord>();
        public List<ServerEndpointRecord> ServerEndpoints { get; set; } = new List<ServerEndpointRecord>();
        public List<CertificateStoreRecord> CertificateStores { get; set; } = new List<CertificateStoreRecord>();
    }

    internal class ApplicationNameRecord
    {
        public int ID { get; set; }
        public int ApplicationId { get; set; }
        public string? Locale { get; set; }
        public string? Text { get; set; }
    }

    internal class ServerEndpointRecord
    {
        public int ID { get; set; }
        public int ApplicationId { get; set; }
        public string? DiscoveryUrl { get; set; }
    }

    internal class CertificateStoreRecord
    {
        public int ID { get; set; }
        public int ApplicationId { get; set; }
        public string? CertificateType { get; set; }
        public string? Path { get; set; }
    }

    internal class CertificateRequestRecord
    {
        public int ID { get; set; }
        public Guid RequestId { get; set; }
        public int ApplicationId { get; set; }
        public int State { get; set; }
        public string? CertificateGroupId { get; set; }
        public string? CertificateTypeId { get; set; }
        public byte[]? CertificateSigningRequest { get; set; }
        public string? SubjectName { get; set; }
        public string? DomainNames { get; set; }
        public string? PrivateKeyFormat { get; set; }
        public string? PrivateKeyPassword { get; set; }
        public string? AuthorityId { get; set; }
    }

    #endregion

    #region Constructors
    public InMemoryApplicationsDatabase() { }

    #endregion
}
