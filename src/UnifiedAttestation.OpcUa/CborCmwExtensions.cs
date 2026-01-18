using System.Formats.Cbor;

namespace UnifiedAttestation.OpcUa;

public static class CborRecordExtensions
{
    extension(CborCmw cborRecord)
    {
        public byte[] ToBytes()
        {
            var writer = new CborWriter();

            writer.WriteStartMap(3);

            writer.WriteTextString("type");
            writer.WriteUInt32(cborRecord.ContentId);

            writer.WriteTextString("value");
            writer.WriteByteString(cborRecord.Value);

            writer.WriteTextString("ind");
            writer.WriteInt32((int)cborRecord.CmType);

            writer.WriteEndMap();

            return writer.Encode();
        }

        public static CborCmw FromBytes(byte[] bytes)
        {
            var reader = new CborReader(bytes);

            int? length = reader.ReadStartMap();
            if (length != 3)
            {
                throw new ArgumentException(
                    "The provided byte sequence was not recognized as a cbor cmw record",
                    nameof(bytes)
                );
            }

            ushort contentId = default;
            byte[] value = [];
            ConceptualMessageTypes cmType = default;

            for (int i = 0; i < 3; i++)
            {
                string key = reader.ReadTextString();

                switch (key)
                {
                    case "type":
                        contentId = (ushort)reader.ReadUInt32();
                        break;
                    case "value":
                        value = reader.ReadByteString();
                        break;
                    case "ind":
                        cmType = (ConceptualMessageTypes)reader.ReadInt32();
                        break;
                    default:
                        throw new InvalidOperationException($"Unknown key: {key}");
                }
            }

            reader.ReadEndMap();

            return new CborCmw(contentId, value, cmType);
        }
    }

    extension(byte[] bytes)
    {
        public CborCmw ToCborCmwRecord() => CborCmw.FromBytes(bytes);
    }
}
