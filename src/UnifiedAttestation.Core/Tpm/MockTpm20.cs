using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace UnifiedAttestation.Core.Tpm;

public record QuoteCommandResponse(Tpm20Quote Quote, byte[] Signature);

public class MockTpm20
{
    public Dictionary<HashAlgorithmName, Digest[]> _pcrBanks = [];

    public ImmutableHashSet<HashAlgorithmName> EnabledAlgorithms;

    public static uint PcrCount { get; } = 24U;

    private readonly string _privateKeyPath;

    private readonly string _publicKeyPath;

    private MockTpm20(IEnumerable<HashAlgorithmName> enabledAlgorithms, string privateKeyPath, string publicKeyPath)
    {
        _privateKeyPath = Path.GetFullPath(privateKeyPath);
        _publicKeyPath = Path.GetFullPath(publicKeyPath);

        EnabledAlgorithms = [.. enabledAlgorithms];

        foreach (HashAlgorithmName algorithm in EnabledAlgorithms)
        {
            _pcrBanks[algorithm] = Enumerable
                .Range(0, (int)PcrCount)
                .Select(_ => Digest.CreateZero(algorithm))
                .ToArray();
        }

        string? privateDirPath = Path.GetDirectoryName(_privateKeyPath);
        if (privateDirPath is not null && !Directory.Exists(privateDirPath))
        {
            Directory.CreateDirectory(privateDirPath);
        }

        string? publicDirPath = Path.GetDirectoryName(_publicKeyPath);
        if (publicDirPath is not null && !Directory.Exists(publicDirPath))
        {
            Directory.CreateDirectory(publicDirPath);
        }

        if (!File.Exists(_privateKeyPath))
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            string privateKey = ecdsa.ExportPkcs8PrivateKeyPem();
            File.WriteAllText(_privateKeyPath, privateKey);
        }

        if (!File.Exists(_publicKeyPath))
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            string publicKey = ecdsa.ExportSubjectPublicKeyInfoPem();
            File.WriteAllText(_publicKeyPath, publicKey);
        }
    }

    public static MockTpm20 Initialize(
        IEnumerable<HashAlgorithmName> enabledAlgorithms,
        string privateKeyPath,
        string publicKeyPath
    ) => new(enabledAlgorithms, privateKeyPath, publicKeyPath);

    public void Extend(HashAlgorithmName algorithmName, uint pcrIndex, byte[] value)
    {
        ThrowIfNotInRange(pcrIndex);
        Digest[] digests = GetDigestsForAlgorithm(algorithmName);

        byte[] concatenated = digests[pcrIndex].Bytes.Concat(value).ToArray();
        using HashAlgorithm algorithm = GetHashAlgorithm(algorithmName);
        byte[] newDigest = algorithm.ComputeHash(concatenated);
        digests[pcrIndex] = new Digest(algorithmName, newDigest);
    }

    public QuoteCommandResponse GetQuote(byte[] keyName, HashAlgorithmName algorithmName, int[] selection, byte[] nonce)
    {
        Digest[] digests = GetDigestsForAlgorithm(algorithmName);

        (int pcrIndex, int i)[] invalidIndices = selection
            .Select((pcrIndex, i) => (pcrIndex, i))
            .Where(pcrIndexPair => pcrIndexPair.pcrIndex < 0 || pcrIndexPair.pcrIndex >= PcrCount)
            .ToArray();

        if (invalidIndices.Length > 0)
        {
            var builder = new StringBuilder();
            builder.Append("One or more invalid pcr indices provided ");

            foreach ((int pcrIndex, int i) in invalidIndices)
            {
                builder.Append($"{i}: {pcrIndex}\n");
            }

            throw new InvalidOperationException(builder.ToString());
        }

        List<byte> selectedDigests = [];
        int selectionMask = 0;
        foreach (int index in selection)
        {
            selectionMask |= 1 << index;
            selectedDigests.AddRange(digests[index].Bytes);
        }

        using HashAlgorithm algorithm = GetHashAlgorithm(algorithmName);
        byte[] digestHash = algorithm.ComputeHash(selectedDigests.ToArray());
        var pcrSelection = new PcrSelection(algorithmName, selectionMask);
        var quote = new Tpm20Quote(keyName, nonce, pcrSelection, digestHash);

        using var ecdsa = ECDsa.Create();
        string pemString = File.ReadAllText(_privateKeyPath);
        ecdsa.ImportFromPem(pemString);
        byte[] signature = ecdsa.SignData(quote.GetRawBytes(), algorithmName);

        return new QuoteCommandResponse(quote, signature);
    }

    public CertificateRequest GetCsr(HashAlgorithmName hashAlgorithmName)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(_privateKeyPath);

        var subject = new X500DistinguishedName("CN=acmetpm.com, O=ACME TPM, C=SE");
        return new CertificateRequest(subject, ecdsa, hashAlgorithmName);
    }

    private static void ThrowIfNotInRange(uint pcrIndex)
    {
        if (pcrIndex < 0 || pcrIndex >= PcrCount)
        {
            throw new IndexOutOfRangeException($"PCR index must be between 0 and {PcrCount - 1}. Got {pcrIndex}");
        }
    }

    private Digest[] GetDigestsForAlgorithm(HashAlgorithmName algorithmName)
    {
        if (!_pcrBanks.TryGetValue(algorithmName, out Digest[]? digests))
        {
            throw new InvalidOperationException($"Hash algorithm {algorithmName.Name} was not enabled");
        }

        return digests;
    }

    private static HashAlgorithm GetHashAlgorithm(HashAlgorithmName algorithm) =>
        algorithm switch
        {
            var a when a == HashAlgorithmName.MD5 => MD5.Create(),
            var a when a == HashAlgorithmName.SHA1 => SHA1.Create(),
            var a when a == HashAlgorithmName.SHA256 => SHA256.Create(),
            var a when a == HashAlgorithmName.SHA384 => SHA384.Create(),
            var a when a == HashAlgorithmName.SHA512 => SHA512.Create(),
            var a when a == HashAlgorithmName.SHA3_256 => SHA3_256.Create(),
            var a when a == HashAlgorithmName.SHA3_384 => SHA3_384.Create(),
            var a when a == HashAlgorithmName.SHA3_512 => SHA3_512.Create(),
            _ => throw new NotSupportedException($"Hash algorithm '{algorithm.Name ?? "<null>"}' is not supported."),
        };
}
