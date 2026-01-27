using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using UnifiedAttestation.Core.Tpm;

namespace UnifiedAttestation.Http.VerifierApplication.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AttestationReferenceDataController(ReferenceValueDatabase database) : ControllerBase
{
    private readonly ReferenceValueDatabase _database = database;

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
}

public class ReferenceValueDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = null!;
    public string JsonData { get; set; } = null!;
}
