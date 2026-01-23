using System.Text.Json.Serialization;

namespace UnifiedAttestation.OpcUa.AttesterApplication;

public class BootComponent
{
    [JsonPropertyName("event_type")]
    public uint EventType { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("content")]
    public string Content { get; set; } = string.Empty;

    [JsonPropertyName("pcr")]
    public uint Pcr { get; set; }
}

public class BootComponents
{
    [JsonPropertyName("boot_components")]
    public List<BootComponent>? Components { get; set; }
}
