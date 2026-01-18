namespace UnifiedAttestation.Tests.Tpm

open System
open System.Collections
open System.Security.Cryptography
open UnifiedAttestation.Core.Tpm
open UnifiedAttestation.Tests
open NUnit.Framework
open FsCheck.NUnit

type UnsupportedTpmQuote() =
    interface ITpmQuote with
        member _.GetRawBytes() = failwith "Not Implemented"

type UnsupportedEventLog() =
    interface IEventLog with
        member _.Replay(_, _) = failwith "Not Implemented"

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

    [<Properties(Arbitrary = [| typeof<Generators> |])>]
    module ``Appraisal Policy Tests`` =
        open System.Security.Cryptography.X509Certificates
        open System.Collections.Generic
        //
        [<Test>]
        let ``Appraisal policy throws on unsupported TPM quote type`` () =
            let policy = new TpmEvidenceAppraisalPolicy()

            let evidence =
                new TpmEvidence(new UnsupportedTpmQuote(), Array.empty, new UnsupportedEventLog())

            let nonce = Array.empty

            let endorsement = new TpmEndorsement(Array.empty)
            let referenceValues = new TpmReferenceValues(Seq.empty)

            let ex =
                Assert.Throws<AggregateException>(fun () ->
                    policy.AppraiseAsync(evidence, nonce, endorsement, referenceValues)
                    |> Async.AwaitTask
                    |> Async.RunSynchronously
                    |> ignore)

            Assert.That(ex.InnerException, Is.TypeOf<NotSupportedException>())

        [<Test>]
        let ``Appraisal policy throws on unsupported event log types`` () =
            let policy = new TpmEvidenceAppraisalPolicy()

            let pcrSelection = new PcrSelection(HashAlgorithmName.SHA256, 0)
            let qoute = new Tpm20Quote(Array.empty, Array.empty, pcrSelection, Array.empty)

            let evidence = new TpmEvidence(qoute, Array.empty, new UnsupportedEventLog())

            let nonce = Array.empty

            let endorsement = new TpmEndorsement(Array.empty)
            let referenceValues = new TpmReferenceValues(Seq.empty)

            let ex =
                Assert.Throws<AggregateException>(fun () ->
                    policy.AppraiseAsync(evidence, nonce, endorsement, referenceValues)
                    |> Async.AwaitTask
                    |> Async.RunSynchronously
                    |> ignore)

            Assert.That(ex.InnerException, Is.TypeOf<NotSupportedException>())

        [<Property>]
        let ``TpmNonceMismatch is returned when nonces do not match`` (arrays: MismatchingArrays) =
            let policy = new TpmEvidenceAppraisalPolicy()

            let quoteNonce = arrays.Arr1
            let pcrSelection = new PcrSelection(HashAlgorithmName.SHA256, 0)
            let qoute = new Tpm20Quote(Array.empty, quoteNonce, pcrSelection, Array.empty)
            let eventLog = new TcgEventLog(Seq.empty)

            let evidence = new TpmEvidence(qoute, Array.empty, eventLog)
            let endorsement = new TpmEndorsement(Array.empty)
            let referenceValues = new TpmReferenceValues(Seq.empty)

            let receivedNonce = arrays.Arr2

            let result =
                policy.AppraiseAsync(evidence, receivedNonce, endorsement, referenceValues)
                |> Async.AwaitTask
                |> Async.RunSynchronously

            Assert.That(result, Is.TypeOf<TpmNonceMismatch>())

        [<Property>]
        let ``Mismatching certs cause TpmQuoteSignatureCheckFailed``
            (selectionMask: int)
            (keyName: byte[])
            (pcrDigest: byte[])
            (nonce: byte[])
            (cert1: X509Certificate2)
            (cert2: X509Certificate2)
            =
            let policy = new TpmEvidenceAppraisalPolicy()

            let pcrSelection = new PcrSelection(HashAlgorithmName.SHA256, selectionMask)
            let quote = new Tpm20Quote(keyName, nonce, pcrSelection, pcrDigest)
            let ecdsa = cert1.GetECDsaPrivateKey()
            let quoteBytes = quote.GetRawBytes()
            let quoteSignature = ecdsa.SignData(quoteBytes, HashAlgorithmName.SHA256)
            ecdsa.Dispose()

            let eventLog = new TcgEventLog(Seq.empty)

            let certBytes = cert2.Export X509ContentType.Cert
            let evidence = new TpmEvidence(quote, quoteSignature, eventLog)
            let endorsement = new TpmEndorsement(certBytes)
            let referenceValues = new TpmReferenceValues(Seq.empty)

            let result =
                policy.AppraiseAsync(evidence, nonce, endorsement, referenceValues)
                |> Async.AwaitTask
                |> Async.RunSynchronously

            cert1.Dispose()
            cert2.Dispose()

            Assert.That(result, Is.TypeOf<TpmQuoteSignatureCheckFailed>())

        [<Property>]
        let ``Differences between recieved and signed quotes produce TpmQuoteSignatureCheckFailed``
            (selectionMask: int)
            (keyName: byte[])
            (pcrDigests: MismatchingArrays)
            (nonce: byte[])
            (cert: X509Certificate2)
            =
            let policy = new TpmEvidenceAppraisalPolicy()

            let tpmDigest = pcrDigests.Arr1
            let substitutedDigest = pcrDigests.Arr2

            let pcrSelection = new PcrSelection(HashAlgorithmName.SHA256, selectionMask)
            let actualQuote = new Tpm20Quote(keyName, nonce, pcrSelection, tpmDigest)
            let ecdsa = cert.GetECDsaPrivateKey()
            let quoteBytes = actualQuote.GetRawBytes()
            let quoteSignature = ecdsa.SignData(quoteBytes, HashAlgorithmName.SHA256)
            ecdsa.Dispose()

            let eventLog = new TcgEventLog(Seq.empty)

            let certBytes = cert.Export X509ContentType.Cert
            let fakeQuote = new Tpm20Quote(keyName, nonce, pcrSelection, substitutedDigest)
            let evidence = new TpmEvidence(fakeQuote, quoteSignature, eventLog)
            let endorsement = new TpmEndorsement(certBytes)
            let referenceValues = new TpmReferenceValues(Seq.empty)

            let result =
                policy.AppraiseAsync(evidence, nonce, endorsement, referenceValues)
                |> Async.AwaitTask
                |> Async.RunSynchronously

            cert.Dispose()

            Assert.That(result, Is.TypeOf<TpmQuoteSignatureCheckFailed>())

        [<Property>]
        let ``Differences between event logs and pcr digests result in TpmReplayFailed``
            (mismatchingLogDigest: MismatchingLogDigest)
            (keyName: byte[])
            (nonce: byte[])
            (cert: X509Certificate2)
            =
            let policy = new TpmEvidenceAppraisalPolicy()

            let pcrSelection =
                new PcrSelection(HashAlgorithmName.SHA256, mismatchingLogDigest.SelectionMask)

            let quote =
                new Tpm20Quote(keyName, nonce, pcrSelection, mismatchingLogDigest.Digest)

            let ecdsa = cert.GetECDsaPrivateKey()
            let quoteBytes = quote.GetRawBytes()
            let quoteSignature = ecdsa.SignData(quoteBytes, HashAlgorithmName.SHA256)
            ecdsa.Dispose()

            let eventLog = mismatchingLogDigest.Log

            let certBytes = cert.Export X509ContentType.Cert
            let evidence = new TpmEvidence(quote, quoteSignature, eventLog)
            let endorsement = new TpmEndorsement(certBytes)
            let referenceValues = new TpmReferenceValues(Seq.empty)

            let result =
                policy.AppraiseAsync(evidence, nonce, endorsement, referenceValues)
                |> Async.AwaitTask
                |> Async.RunSynchronously

            cert.Dispose()

            Assert.That(result, Is.TypeOf<TpmReplayFailed>())

        [<Property>]
        let ``If all else is ok, a TpmVerificationReport is returend``
            (mismatchingLogDigest: MatchingLogDigest)
            (keyName: byte[])
            (nonce: byte[])
            (cert: X509Certificate2)
            =
            let policy = new TpmEvidenceAppraisalPolicy()

            let pcrSelection =
                new PcrSelection(HashAlgorithmName.SHA256, mismatchingLogDigest.SelectionMask)

            let quote =
                new Tpm20Quote(keyName, nonce, pcrSelection, mismatchingLogDigest.Digest)

            let ecdsa = cert.GetECDsaPrivateKey()
            let quoteBytes = quote.GetRawBytes()
            let quoteSignature = ecdsa.SignData(quoteBytes, HashAlgorithmName.SHA256)
            ecdsa.Dispose()

            let eventLog = mismatchingLogDigest.Log

            let certBytes = cert.Export X509ContentType.Cert
            let evidence = new TpmEvidence(quote, quoteSignature, eventLog)
            let endorsement = new TpmEndorsement(certBytes)
            let referenceValues = new TpmReferenceValues(Seq.empty)

            let result =
                policy.AppraiseAsync(evidence, nonce, endorsement, referenceValues)
                |> Async.AwaitTask
                |> Async.RunSynchronously

            cert.Dispose()

            Assert.That(result, Is.TypeOf<TpmVerificationReport>())
