namespace UnifiedAttestation.Tests

open FsCheck.FSharp
open System.Security.Cryptography

type Sha256Array(arr: byte[]) =
    member _.Get = arr

type Sha256ArrayCollection(arr: byte array array) =
    member _.Get = arr

module TpmGen =

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

type Generators() =

    static member Sha256Array() = TpmGen.sha256ArrayArb ()

    static member Sha256ArrayCollection() = TpmGen.sha256ArrayArb ()
