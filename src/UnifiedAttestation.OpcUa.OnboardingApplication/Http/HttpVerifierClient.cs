using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.OpcUa.OnboardingApplication.Http;

public record Wrapper(TpmAttestationResult Value);

public interface ICmwDecoder<T>
{
    string MediaType { get; }
    T Decode(byte[] data);
}

public class JsonCmwDecoder<T> : ICmwDecoder<T>
{
    public string MediaType => "application/json";

    public T Decode(byte[] data)
    {
        return JsonSerializer.Deserialize<T>(data)
            ?? throw new InvalidOperationException("Failed to deserialize JSON.");
    }
}

public class AttestationRequest
{
    [Required]
    public required CborCmw Evidence { get; set; }

    [Required]
    public required byte[] Nonce { get; set; }
}

public static class Base64Url
{
    public static string Encode(byte[] bytes)
    {
        string base64 = Convert.ToBase64String(bytes);
        return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static string Encode(string text)
    {
        return Encode(System.Text.Encoding.UTF8.GetBytes(text));
    }

    public static byte[] Decode(string base64Url)
    {
        string base64 = base64Url.Replace('-', '+').Replace('_', '/');

        switch (base64.Length % 4)
        {
            case 2:
                base64 += "==";
                break;
            case 3:
                base64 += "=";
                break;
        }

        return Convert.FromBase64String(base64);
    }
}

public class CmwDecoderRegistry<T>
{
    private readonly Dictionary<string, ICmwDecoder<T>> _decoders;

    public CmwDecoderRegistry(IEnumerable<ICmwDecoder<T>> decoders)
    {
        _decoders = decoders.ToDictionary(d => d.MediaType, StringComparer.OrdinalIgnoreCase);
    }

    public T Decode(string mediaType, byte[] data)
    {
        if (_decoders.TryGetValue(mediaType, out ICmwDecoder<T>? decoder))
        {
            return decoder.Decode(data);
        }

        throw new NotSupportedException($"No decoder registered for media type: {mediaType}");
    }
}

public class HttpVerifierClient : IVerifierClient<TpmAttestationResult>, IDisposable
{
    private readonly HttpClient _http;

    private readonly CmwDecoderRegistry<TpmAttestationResult> _decoderRegistry;

    public HttpVerifierClient(HttpClient httpClient)
    {
        _http = httpClient;

        _decoderRegistry = new CmwDecoderRegistry<TpmAttestationResult>(
            new ICmwDecoder<TpmAttestationResult>[] { new JsonCmwDecoder<TpmAttestationResult>() }
        );
    }

    public async Task<TpmAttestationResult> VerifyEvidenceAsync(
        Guid entityId,
        CborCmw evidence,
        byte[] nonce,
        CancellationToken cancellationToken = default
    )
    {
        var requestObj = new AttestationRequest { Evidence = evidence, Nonce = nonce };
        var serializationOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
        };

        using HttpResponseMessage response = await _http.PostAsJsonAsync(
            $"api/AttestationReferenceData/{entityId}",
            requestObj,
            serializationOptions,
            cancellationToken
        );

        response.EnsureSuccessStatusCode();

        JsonCmw envelope =
            await response.Content.ReadFromJsonAsync<JsonCmw>(serializationOptions, cancellationToken)
            ?? throw new InvalidOperationException("Attestation response was empty or invalid.");

        if (
            !StringComparer.OrdinalIgnoreCase.Equals(envelope.MediaType, "application/json")
            || envelope.CmType != ConceptualMessageTypes.AttestationResult
        )
        {
            throw new InvalidOperationException(
                $"Unexpected CMw content: type={envelope.MediaType}, contentType={envelope.CmType}"
            );
        }

        byte[] jsonBytes = Base64Url.Decode(envelope.Value);
        return _decoderRegistry.Decode(envelope.MediaType, jsonBytes);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            _http.Dispose();
        }
    }
}
