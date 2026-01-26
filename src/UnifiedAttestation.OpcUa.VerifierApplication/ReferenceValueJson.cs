using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace UnifiedAttestation.OpcUa.VerifierApplication;

public class ReferenceValueJson
{
    [JsonPropertyName("hash_algorithm")]
    public string HashAlgorithm { get; set; } = string.Empty;

    [JsonPropertyName("pcr_index")]
    public uint PcrIndex { get; set; }

    [JsonPropertyName("event")]
    public uint Event { get; set; }

    [JsonPropertyName("digests")]
    public byte[][] Digests { get; set; } = [];
}

public class ReferenceValuesJson
{
    [JsonPropertyName("reference_values")]
    public List<ReferenceValueJson>? ReferenceValues { get; set; }
}
