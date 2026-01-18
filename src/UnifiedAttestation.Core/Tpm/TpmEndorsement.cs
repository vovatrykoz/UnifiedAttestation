using UnifiedAttestation.Core.Entities;

namespace UnifiedAttestation.Core.Tpm;

public class TpmEndorsement(byte[] manufacturerCertificate) : IEndorsement
{
    public byte[] ManufacturerCertificate { get; } = manufacturerCertificate;
}
