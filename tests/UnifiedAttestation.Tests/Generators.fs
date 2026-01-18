namespace UnifiedAttestation.Tests

open FsCheck.FSharp
open System
open System.Security.Cryptography
open UnifiedAttestation.Core.Tpm

type Sha256Array(arr: byte[]) =
    member _.Get = arr

type Sha256ArrayCollection(arr: byte array array) =
    member _.Get = arr

type MismatchingArrays(arr1: byte array, arr2: byte array) =
    member _.Arr1 = arr1

    member _.Arr2 = arr2

type MismatchingLogDigest(selectionMask: int, log: TcgEventLog, digest: byte array) =
    member _.SelectionMask = selectionMask

    member _.Log = log

    member _.Digest = digest

type MatchingLogDigest(selectionMask: int, log: TcgEventLog, digest: byte array) =
    member _.SelectionMask = selectionMask

    member _.Log = log

    member _.Digest = digest

module TpmGen =
    open System.Collections.Generic

    let sha256ArrayGen () =
        ArbMap.defaults.ArbFor<byte>()
        |> Arb.toGen
        |> Gen.arrayOfLength SHA256.HashSizeInBytes
        |> Gen.map Sha256Array

    let sha256ArrayArb () = sha256ArrayGen () |> Arb.fromGen

    let sha256ArrayCollectionGen () =
        ArbMap.defaults.ArbFor<byte>()
        |> Arb.toGen
        |> Gen.arrayOfLength SHA256.HashSizeInBytes
        |> Gen.arrayOf
        |> Gen.map Sha256ArrayCollection

    let sha256ArrayCollectionArb () =
        sha256ArrayCollectionGen () |> Arb.fromGen

    let mismatchingArraysGen () =
        ArbMap.defaults.ArbFor<byte array * byte array>()
        |> Arb.toGen
        |> Gen.filter (fun (arr1, arr2) -> arr1 <> arr2)
        |> Gen.map MismatchingArrays

    let mismatchingArraysArb () = mismatchingArraysGen () |> Arb.fromGen

    let createSelfSignedCert (subjectName: string) =
        use ecdsa = ECDsa.Create()

        let certReq =
            X509Certificates.CertificateRequest($"CN={subjectName}", ecdsa, HashAlgorithmName.SHA256)

        certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays -1.0, DateTimeOffset.UtcNow.AddMinutes 1)

    let inline isValidSubjectName (str: string) =
        not (String.IsNullOrWhiteSpace(str)) && str |> Seq.forall Char.IsLetter

    let selfSignedCertArb () =
        ArbMap.defaults.ArbFor<string>()
        |> Arb.toGen
        |> Gen.filter isValidSubjectName
        |> Gen.map createSelfSignedCert
        |> Arb.fromGen

    let extractPcrIndices bitmask =
        let positions = List<uint>()

        for i in 0u .. 31u do
            if bitmask &&& (1 <<< int i) <> 0 then
                positions.Add i

        positions

    let replay (hashAlgorithm: HashAlgorithm) (entries: seq<TcgEventLogEntry>) (pcrIndex: uint32) : byte[] =
        let initialPcr = Array.zeroCreate<byte> (hashAlgorithm.HashSize / 8)

        entries
        |> Seq.filter (fun e -> e.PcrIndex = pcrIndex)
        |> Seq.fold
            (fun pcr entry ->
                match
                    entry.Digests
                    |> Seq.tryFind (fun d -> d.AlgorithmName = HashAlgorithmName.SHA256)
                with
                | Some digest -> digest.Bytes |> Array.append pcr |> hashAlgorithm.ComputeHash
                | None -> pcr)
            initialPcr

    let mismatchingDigestEventLogGen () =
        gen {
            let! selectionMask = ArbMap.defaults.ArbFor<int>() |> Arb.toGen
            let pcrIndices = extractPcrIndices selectionMask
            let log = TcgEventLog.Empty

            for index in pcrIndices do
                let! generatedDigests = sha256ArrayCollectionGen ()

                let digests =
                    generatedDigests.Get |> Array.map (fun d -> Digest(HashAlgorithmName.SHA256, d))

                let! eventType = ArbMap.defaults.ArbFor<uint>() |> Arb.toGen
                let! event = ArbMap.defaults.ArbFor<byte array>() |> Arb.toGen
                let newEntry = new TcgEventLogEntry(index, eventType, digests, event)
                log.Entries.Add newEntry

            let digests = new List<byte array>()

            use hashAlgorithm = SHA256.Create()

            for index in pcrIndices do
                let newDigest = replay hashAlgorithm log.Entries index
                digests.Add newDigest

            let combined = digests |> Seq.concat |> Seq.toArray
            let hash = hashAlgorithm.ComputeHash combined

            let! mismatchingHash =
                ArbMap.defaults.ArbFor<byte array>()
                |> Arb.toGen
                |> Gen.filter (fun h -> h <> hash)

            return new MismatchingLogDigest(selectionMask, log, mismatchingHash)
        }

    let mismatchingDigestEventLogArb () =
        mismatchingDigestEventLogGen () |> Arb.fromGen

    let matchingDigestEventLogGen () =
        gen {
            let! selectionMask = ArbMap.defaults.ArbFor<int>() |> Arb.toGen
            let pcrIndices = extractPcrIndices selectionMask
            let log = TcgEventLog.Empty

            for index in pcrIndices do
                let! generatedDigests = sha256ArrayCollectionGen ()

                let digests =
                    generatedDigests.Get |> Array.map (fun d -> Digest(HashAlgorithmName.SHA256, d))

                let! eventType = ArbMap.defaults.ArbFor<uint>() |> Arb.toGen
                let! event = ArbMap.defaults.ArbFor<byte array>() |> Arb.toGen
                let newEntry = new TcgEventLogEntry(index, eventType, digests, event)
                log.Entries.Add newEntry

            let digests = new List<byte array>()

            use hashAlgorithm = SHA256.Create()

            for index in pcrIndices do
                let newDigest = replay hashAlgorithm log.Entries index
                digests.Add newDigest

            let combined = digests |> Seq.concat |> Seq.toArray
            let digest = hashAlgorithm.ComputeHash combined

            return new MatchingLogDigest(selectionMask, log, digest)
        }

    let matchingDigestEventLogArb () =
        matchingDigestEventLogGen () |> Arb.fromGen

type Generators() =

    static member Sha256Array() = TpmGen.sha256ArrayArb ()

    static member Sha256ArrayCollection() = TpmGen.sha256ArrayArb ()

    static member MismatchingArrays() = TpmGen.mismatchingArraysArb ()

    static member X509Certificate2() = TpmGen.selfSignedCertArb ()

    static member MismatchingLogDigest() = TpmGen.mismatchingDigestEventLogArb ()

    static member MatchingLogDigest() = TpmGen.matchingDigestEventLogArb ()
