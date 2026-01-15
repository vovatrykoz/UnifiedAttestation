using System.Collections.Immutable;

namespace UnifiedAttestation.Core.Tpm;

public abstract class EventLog;

public record Digest(HashAlgorithm HashAlgorithm, byte[] DigestBytes);

public record TcgEventLogEntry(uint PcrIndex, uint EventType, Digest[] Digests, byte[] Event);

public class TcgEventLog(IEnumerable<TcgEventLogEntry> entries)
{
    public ImmutableArray<TcgEventLogEntry> Entries { get; } = entries.ToImmutableArray();
}
