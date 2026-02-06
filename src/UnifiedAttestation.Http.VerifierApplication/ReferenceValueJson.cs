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

public sealed class TpmAttestationResultConverter : JsonConverter<TpmAttestationResult>
{
    public override TpmAttestationResult Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options
    )
    {
        using var doc = JsonDocument.ParseValue(ref reader);
        JsonElement root = doc.RootElement;

        if (!root.TryGetProperty("type", out var typeProp))
            throw new JsonException("Missing type discriminator.");

        if (!root.TryGetProperty("value", out var valueProp))
            throw new JsonException("Missing value property.");

        string type = typeProp.GetString() ?? throw new JsonException("Type property is null.");

        return type switch
        {
            nameof(TpmNonceMismatch) => JsonSerializer.Deserialize<TpmNonceMismatch>(valueProp, options)!,

            nameof(TpmQuoteSignatureCheckFailed) => JsonSerializer.Deserialize<TpmQuoteSignatureCheckFailed>(
                valueProp,
                options
            )!,

            nameof(TpmReplayFailed) => JsonSerializer.Deserialize<TpmReplayFailed>(valueProp, options)!,

            nameof(TpmVerificationReport) => JsonSerializer.Deserialize<TpmVerificationReport>(valueProp, options)!,

            _ => throw new JsonException($"Unknown TpmAttestationResult type: {type}"),
        };
    }

    public override void Write(Utf8JsonWriter writer, TpmAttestationResult value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();

        writer.WriteString("type", value.GetType().Name);
        writer.WritePropertyName("value");

        var innerOptions = new JsonSerializerOptions(options);
        for (int i = innerOptions.Converters.Count - 1; i >= 0; i--)
        {
            if (innerOptions.Converters[i] is TpmAttestationResultConverter)
                innerOptions.Converters.RemoveAt(i);
        }

        // delegate to concrete serializer
        JsonSerializer.Serialize(writer, (object)value, value.GetType(), innerOptions);

        writer.WriteEndObject();
    }
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
