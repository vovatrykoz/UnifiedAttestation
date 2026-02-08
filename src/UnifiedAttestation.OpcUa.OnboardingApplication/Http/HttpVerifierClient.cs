using System;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.OpcUa.OnboardingApplication.Http;

public record Wrapper(TpmAttestationResult Value);

public class AttestationRequest
{
    [Required]
    public required CborCmw Evidence { get; set; }

    [Required]
    public required byte[] Nonce { get; set; }
}

public class HttpVerifierClient(HttpClient http) : IVerifierClient<TpmAttestationResult>, IDisposable
{
    private readonly HttpClient _http = http;

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

        HttpResponseMessage response = await _http.PostAsJsonAsync(
            $"api/AttestationReferenceData/{entityId}",
            requestObj,
            serializationOptions,
            cancellationToken
        );

        response.EnsureSuccessStatusCode();

        string res = await response.Content.ReadAsStringAsync(cancellationToken);

        Wrapper result =
            await response.Content.ReadFromJsonAsync<Wrapper>(serializationOptions, cancellationToken)
            ?? throw new InvalidOperationException("Attestation response was empty or invalid.");

        return result.Value;
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
