namespace UnifiedAttestation.Tests

open System
open Moq
open UnifiedAttestation.Core
open UnifiedAttestation.Core.Entities
open NUnit.Framework

type FakeEvidence() =
    interface IEvidence

type FakeResult() =
    interface IAttestationResult

type FakeEndorsement() =
    interface IEndorsement

type FakeReferenceValue() =
    interface IReferenceValue

module ``Core Logic Tests`` =
    open System.Collections
    open System.Threading.Tasks

    [<Test>]
    let ``VerifyAsync should call components in correct order`` () =
        let calls = ResizeArray<string>()

        let entityId = Guid.NewGuid()
        let nonce = [| 1uy; 2uy; 3uy |]
        let evidence = [| 4uy; 5uy; 6uy |]
        let result = FakeResult()

        let nonceProvider = Mock<INonceProvider>()

        nonceProvider.Setup(fun np -> np.GetFreshNonceAsync()).Callback(fun () -> calls.Add("nonce")).ReturnsAsync nonce
        |> ignore

        let attester = Mock<IAttesterClient>()

        attester
            .Setup(fun a -> a.RequestEvidenceAsync(entityId, nonce))
            .Callback(fun _ -> calls.Add("attest"))
            .ReturnsAsync
            evidence
        |> ignore

        let verifier = Mock<IVerifierClient<FakeResult>>()

        verifier
            .Setup(fun v -> v.VerifyEvidenceAsync(entityId, evidence, nonce))
            .Callback(fun _ -> calls.Add("verify"))
            .ReturnsAsync
            result
        |> ignore

        let appraisal = Mock<IResultAppraisalPolicy<FakeResult>>()

        appraisal.Setup(fun ap -> ap.AppraiseAsync(entityId, result)).Callback(fun _ -> calls.Add("appraise")).Returns
            Task.CompletedTask
        |> ignore

        let client =
            RelyingClient(attester.Object, verifier.Object, appraisal.Object, nonceProvider.Object)

        entityId |> client.VerifyAsync |> Async.AwaitTask |> Async.RunSynchronously

        let expected = [ "nonce"; "attest"; "verify"; "appraise" ]

        Assert.That(calls, Is.EqualTo<IEnumerable> expected)

    [<Test>]
    let ``VerifyAsync should call providers and appraisal in correct order`` () =
        let calls = ResizeArray<string>()

        let entityId = Guid.NewGuid()
        let evidence = FakeEvidence()
        let nonce = [| 7uy; 8uy; 9uy |]
        let endorsements = FakeEndorsement()
        let referenceValues = FakeReferenceValue()
        let result = FakeResult()

        let endorsementProvider = Mock<IEndorsementProvider<FakeEndorsement>>()

        endorsementProvider
            .Setup(fun ep -> ep.GetEndorsementAsync(entityId))
            .Callback(fun _ -> calls.Add("endorsements"))
            .ReturnsAsync(endorsements)
        |> ignore

        let referenceValueProvider = Mock<IReferenceValueProvider<FakeReferenceValue>>()

        referenceValueProvider
            .Setup(fun rp -> rp.GetReferenceValuesAsync(entityId))
            .Callback(fun _ -> calls.Add("reference values"))
            .ReturnsAsync(referenceValues)
        |> ignore

        let appraisalPolicy =
            Mock<IEvidenceAppraisalPolicy<FakeEvidence, FakeEndorsement, FakeReferenceValue, FakeResult>>()

        appraisalPolicy
            .Setup(fun ap -> ap.AppraiseAsync(evidence, nonce, endorsements, referenceValues))
            .Callback(fun _ -> calls.Add("appraise"))
            .ReturnsAsync(result)
        |> ignore

        let service =
            VerificationService(endorsementProvider.Object, referenceValueProvider.Object, appraisalPolicy.Object)

        service.VerifyAsync(entityId, evidence, nonce)
        |> Async.AwaitTask
        |> Async.RunSynchronously
        |> ignore

        let expected = [ "endorsements"; "reference values"; "appraise" ]

        Assert.That(calls, Is.EqualTo<IEnumerable> expected)
