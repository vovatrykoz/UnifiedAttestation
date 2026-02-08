using System.ComponentModel.DataAnnotations;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using UnifiedAttestation.Core;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.Http.VerifierApplication.Controllers;

public record Wrapper(TpmAttestationResult Value);

[ApiController]
[Route("api/[controller]")]
public class AttestationReferenceDataController(
    ReferenceValueDatabase database,
    VerificationOrchestrator<
        TpmEvidence,
        TpmEndorsement,
        TpmReferenceValues,
        TpmAttestationResult
    > verificationOrchestrator
) : ControllerBase
{
    private readonly ReferenceValueDatabase _database = database;

    private readonly VerificationOrchestrator<
        TpmEvidence,
        TpmEndorsement,
        TpmReferenceValues,
        TpmAttestationResult
    > _verificationOrchestrator = verificationOrchestrator;

    [HttpPost("{id:guid}")]
    public async Task<IActionResult> Attest([FromRoute] Guid id, [FromBody] AttestationRequest request)
    {
        var evidence = TpmEvidence.Decode(request.Evidence.Value);
        TpmAttestationResult result = await _verificationOrchestrator.VerifyAsync(id, evidence, request.Nonce);
        byte[] serialziedResult = JsonSerializer.SerializeToUtf8Bytes(result);

        var cmw = new JsonCmw(
            "application/json",
            WebEncoders.Base64UrlEncode(serialziedResult),
            ConceptualMessageTypes.AttestationResult
        );

        return Ok(cmw);
    }

    [HttpGet("{id:guid}")]
    public IActionResult Get(Guid id)
    {
        DatabaseEntry? value = _database.GetReferenceValues(id);

        if (value is null)
            return NotFound();

        return Ok(value);
    }

    [HttpGet]
    public IActionResult GetMany([FromQuery] int count = 10)
    {
        DatabaseEntry[] values = _database.GetManyReferenceValues(count);
        return Ok(values);
    }

    [HttpPost]
    public IActionResult Add([FromBody] ReferenceValueDto dto)
    {
        try
        {
            _database.Add(dto.Id, dto.Name, dto.JsonData);
            return CreatedAtAction(nameof(Get), new { id = dto.Id }, dto);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            return Conflict($"Reference data with Id '{dto.Id}' already exists.");
        }
    }

    [HttpPut("{id:guid}")]
    public IActionResult Replace(Guid id, [FromBody] ReferenceValueDto dto)
    {
        try
        {
            _database.Replace(id, dto.Name, dto.JsonData);
            return NoContent();
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            return NotFound(ex.Message);
        }
    }

    [HttpDelete("{id:guid}")]
    public IActionResult Delete(Guid id)
    {
        bool deleted = _database.Delete(id);
        return deleted ? NoContent() : NotFound();
    }

    private static string ConvertToTypeName(TpmAttestationResult result) =>
        result switch
        {
            TpmNonceMismatch => nameof(TpmNonceMismatch),
            TpmQuoteSignatureCheckFailed => nameof(TpmQuoteSignatureCheckFailed),
            TpmReplayFailed => nameof(TpmReplayFailed),
            TpmEntryCheckPassed => nameof(TpmEntryCheckPassed),
            TpmEntryCheckFailed => nameof(TpmEntryCheckFailed),
            TpmEntryCheckUnknown => nameof(TpmEntryCheckUnknown),
            TpmVerificationReport => nameof(TpmVerificationReport),
            _ => throw new ArgumentException($"Unknown TpmAttestationResult type: {result.GetType()}"),
        };
}

public class TpmAttestationResponse
{
    [Required]
    public required string Type { get; set; }

    [Required]
    public required TpmAttestationResult Value { get; set; }
}

public class AttestationRequest
{
    [Required]
    public required CborCmw Evidence { get; set; }

    [Required]
    public required byte[] Nonce { get; set; }
}

public class ReferenceValueDto
{
    [Required]
    public required Guid Id { get; set; }

    [Required]
    public required string Name { get; set; }

    [Required]
    public required string JsonData { get; set; }
}

public static class TpmEvidenceEncodingExtensions
{
    extension(TpmEvidence evidence)
    {
        public byte[] Encode()
        {
            if (evidence.Quote is not Tpm20Quote tpmQuote)
            {
                throw new NotSupportedException(
                    $"Unsupported quote type '{evidence.Quote?.GetType().Name ?? "<null>"}'. "
                        + $"Only 'Tpm20Quote' is currently supported."
                );
            }

            if (evidence.Log is not TcgEventLog eventLog)
            {
                throw new NotSupportedException(
                    $"Unsupported event log type '{evidence.Log?.GetType().Name ?? "<null>"}'. "
                        + $"Only 'TcgEventLog' is currently supported."
                );
            }

            byte[] quoteBytes = tpmQuote.GetRawBytes();
            byte[] logBytes = eventLog.Encode();

            var writer = new CborWriter();

            writer.WriteStartArray(3);

            writer.WriteByteString(quoteBytes);
            writer.WriteByteString(evidence.QuoteSignature);
            writer.WriteByteString(logBytes);

            writer.WriteEndArray();

            return writer.Encode();
        }

        public static TpmEvidence Decode(ReadOnlyMemory<byte> encoding)
        {
            var reader = new CborReader(encoding);

            int? length = reader.ReadStartArray();
            if (length is not 3)
                throw new FormatException($"Expected CBOR array of length 3 but got {length}.");

            byte[] quoteBytes = reader.ReadByteString();
            var quote = Tpm20Quote.FromRawBytes(quoteBytes);

            byte[] signature = reader.ReadByteString();

            byte[] logBytes = reader.ReadByteString();
            TcgEventLog eventLog = TcgEventLog.Decode(logBytes);

            return new TpmEvidence(quote, signature, eventLog);
        }
    }
}

public static class TcgEventLogEncodingExtensions
{
    extension(TcgEventLog log)
    {
        public byte[] Encode()
        {
            var writer = new CborWriter(CborConformanceMode.Canonical);

            writer.WriteStartArray(log.Entries.Count);

            foreach (TcgEventLogEntry entry in log.Entries)
            {
                WriteEntry(writer, entry);
            }

            writer.WriteEndArray();
            return writer.Encode();
        }

        public static TcgEventLog Decode(byte[] cbor)
        {
            var reader = new CborReader(cbor, CborConformanceMode.Canonical);

            int entryCount =
                reader.ReadStartArray() ?? throw new InvalidOperationException("Entry array size was null");
            var entries = new List<TcgEventLogEntry>(entryCount);

            for (int i = 0; i < entryCount; i++)
            {
                entries.Add(ReadEntry(reader));
            }

            reader.ReadEndArray();
            return new TcgEventLog(entries);
        }
    }

    private static void WriteEntry(CborWriter writer, TcgEventLogEntry entry)
    {
        writer.WriteStartArray(4);

        writer.WriteUInt32(entry.PcrIndex);
        writer.WriteUInt32(entry.EventType);

        writer.WriteStartArray(entry.Digests.Length);
        foreach (Digest digest in entry.Digests)
        {
            WriteDigest(writer, digest);
        }
        writer.WriteEndArray();

        writer.WriteByteString(entry.Event);

        writer.WriteEndArray();
    }

    private static void WriteDigest(CborWriter writer, Digest digest)
    {
        writer.WriteStartArray(2);

        writer.WriteTextString(
            digest.AlgorithmName.Name ?? throw new InvalidOperationException("HashAlgorithmName has no Name")
        );

        writer.WriteByteString(digest.Bytes);

        writer.WriteEndArray();
    }

    private static TcgEventLogEntry ReadEntry(CborReader reader)
    {
        reader.ReadStartArray();

        uint pcrIndex = reader.ReadUInt32();
        uint eventType = reader.ReadUInt32();

        int digestCount = reader.ReadStartArray() ?? throw new InvalidOperationException("Digest array size was null");
        var digests = new Digest[digestCount];

        for (int i = 0; i < digestCount; i++)
        {
            digests[i] = ReadDigest(reader);
        }

        reader.ReadEndArray();

        byte[] evt = reader.ReadByteString();

        reader.ReadEndArray();

        return new TcgEventLogEntry(pcrIndex, eventType, digests, evt);
    }

    private static Digest ReadDigest(CborReader reader)
    {
        reader.ReadStartArray();

        string algorithmName = reader.ReadTextString();
        byte[] bytes = reader.ReadByteString();

        reader.ReadEndArray();

        return new Digest(new HashAlgorithmName(algorithmName), bytes);
    }
}
