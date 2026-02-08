using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.Http.VerifierApplication;

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

public static class TpmReferenceValuesExtensions
{
    extension(TpmReferenceValues)
    {
        public static TpmReferenceValues ParseFromJson(string jsonString)
        {
            ReferenceValuesJson? referenceValuesJson = JsonSerializer.Deserialize<ReferenceValuesJson>(jsonString);
            if (referenceValuesJson is null || referenceValuesJson.ReferenceValues is null)
            {
                throw new InvalidOperationException(
                    $"Failed to parse TPM reference values from JSON string. "
                        + "The JSON is invalid or missing required ReferenceValues."
                );
            }

            var referenceValues = new TpmReferenceValues(
                referenceValuesJson.ReferenceValues.Select(jsonEntry => new TpmReferenceDigest(
                    new HashAlgorithmName(jsonEntry.HashAlgorithm),
                    jsonEntry.PcrIndex,
                    jsonEntry.Event,
                    jsonEntry.Digests
                ))
            );

            return referenceValues;
        }
    }
}
