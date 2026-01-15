using System.Security.Cryptography.X509Certificates;
using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core.Tpm;

public class TpmEndorsement(X509Certificate2 manufacturerCertificate) : IEndorsement
{
    public X509Certificate2 ManufacturerCertificate { get; } = manufacturerCertificate;
}
