#!/usr/bin/env -S dotnet fsi

#r "../src/UnifiedAttestation.Core/bin/Debug/net10.0/UnifiedAttestation.Core.dll"
#r "../src/UnifiedAttestation.OpcUa.AttesterApplication/bin/Debug/net10.0/UnifiedAttestation.OpcUa.AttesterApplication.dll"

open System.Text.Json
open UnifiedAttestation.OpcUa.AttesterApplication
open System
open UnifiedAttestation.Core.Tpm
open System.Security.Cryptography
open System.Text
open System.IO

let args = fsi.CommandLineArgs

if args.Length < 2 then
    printfn "Please provide the path to the boot config .json file"
    Environment.Exit 1

let pathToBootConfig = args.[1]
let inputJson = File.ReadAllText pathToBootConfig
let jsonString = JsonSerializer.Deserialize<BootComponents> inputJson

if jsonString = null then
    printfn $"Failed to deserialize {pathToBootConfig}"
    Environment.Exit 1

if jsonString.Components = null then
    printfn $"Succesfully deserialized {pathToBootConfig}, but the boot componens were null"
    Environment.Exit 1

let referenceValues = new TpmReferenceValues([])

let random = new Random()

jsonString.Components
|> Seq.iter (fun bootComponent ->

    let baseDigest = bootComponent.Content |> Encoding.UTF8.GetBytes |> SHA256.HashData

    let randomDigest () =
        random.Next() |> BitConverter.GetBytes |> SHA256.HashData

    let additionalDigestsCount = random.Next(0, 4)

    let digests =
        baseDigest :: [ for _ in 1..additionalDigestsCount -> randomDigest () ]
        |> List.randomShuffle
        |> List.toArray

    let referenceEntry =
        TpmReferenceDigest(HashAlgorithmName.SHA256, bootComponent.Pcr, bootComponent.EventType, digests)

    referenceValues.Digests.Add referenceEntry)

let options = new JsonSerializerOptions(WriteIndented = true)
let json = JsonSerializer.Serialize(referenceValues, options)
File.WriteAllText("generated.json", json)

printfn "Generated reference values at ./generated.json"
