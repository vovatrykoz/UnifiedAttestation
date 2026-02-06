using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;
using UnifiedAttestation.Http.VerifierApplication;
using UnifiedAttestation.Http.VerifierApplication.Controllers;

namespace UnifiedAttestation.OpcUa.OnboardingApplication.Http;

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
        var serializationOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        serializationOptions.Converters.Add(new TpmAttestationResultConverter());

        HttpResponseMessage response = await _http.PostAsJsonAsync(
            $"api/AttestationReferenceData/{entityId}",
            requestObj,
            serializationOptions,
            cancellationToken
        );

        response.EnsureSuccessStatusCode();

        TpmAttestationResult? result =
            await response.Content.ReadFromJsonAsync<TpmAttestationResult>(serializationOptions, cancellationToken)
            ?? throw new InvalidOperationException("Attestation response was empty or invalid.");

        return result;
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
