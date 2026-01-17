namespace UnifiedAttestation.Tests.Tpm

open System.Collections
open System.Security.Cryptography
open UnifiedAttestation.Core.Tpm
open UnifiedAttestation.Tests
open NUnit.Framework
open FsCheck.NUnit

module ``Tpm Tests`` =
    //
    [<Properties(Arbitrary = [| typeof<Generators> |])>]
    module ``PCR Replay Tests`` =
        //
        [<Test>]
        let ``Replay with no entries results in zeroed PCR of correct size`` () =
            let sha256 = HashAlgorithmName.SHA256
            let log = TcgEventLog.Empty
            let result = log.Replay(sha256, 0u)
            let allZeroes = Array.zeroCreate<byte> SHA256.HashSizeInBytes

            Assert.Multiple(fun _ ->
                Assert.That(result.Length, Is.EqualTo SHA256.HashSizeInBytes)
                Assert.That(result, Is.EqualTo<IEnumerable> allZeroes))

        [<Property>]
        let ``Replay with a single entry is correct`` (hash: Sha256Array) =
            let sha256 = HashAlgorithmName.SHA256
            let log = TcgEventLog.Empty
            let digest = Digest(HashAlgorithmName.SHA256, hash.Get)
            let newEntry = TcgEventLogEntry(0u, 42u, [| digest |], [||])
            log.Entries.Add newEntry

            let actual = log.Replay(sha256, 0u)

            let allZeroes = Array.zeroCreate<byte> SHA256.HashSizeInBytes
            use hashAlgo = SHA256.Create()
            let combined = hash.Get |> Array.append allZeroes
            let expected = hashAlgo.ComputeHash combined

            Assert.That(actual, Is.EqualTo<IEnumerable> expected)

        [<Property>]
        let ``Replay with multiple entries is correct``
            (pcrIndex: uint32)
            (evenType: uint32)
            (hashes: Sha256ArrayCollection)
            (event: byte array)
            =
            let sha256 = HashAlgorithmName.SHA256

            let log =
                hashes.Get
                |> Array.map (fun hash ->
                    let digest = new Digest(HashAlgorithmName.SHA256, hash)
                    new TcgEventLogEntry(pcrIndex, evenType, [| digest |], event))
                |> TcgEventLog

            let actual = log.Replay(sha256, pcrIndex)

            let allZeroes = Array.zeroCreate<byte> SHA256.HashSizeInBytes
            use hashAlgo = SHA256.Create()

            let expected =
                hashes.Get
                |> Array.fold
                    (fun arr hash ->
                        let combArr = hash |> Array.append arr
                        hashAlgo.ComputeHash combArr)
                    allZeroes

            Assert.That(actual, Is.EqualTo<IEnumerable> expected)
