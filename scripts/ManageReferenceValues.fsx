#!/usr/bin/env -S dotnet fsi

#r "../src/UnifiedAttestation.Core/bin/Debug/net10.0/UnifiedAttestation.Core.dll"
#r "../src/UnifiedAttestation.Http.VerifierApplication/bin/Debug/net10.0/UnifiedAttestation.Http.VerifierApplication.dll"

open System
open System.IO
open System.Net.Http
open System.Net.Http.Json
open System.Text.Json

type Operations =
    | Get of id: Guid
    | GetMany of count: int
    | Add of id: Guid * name: string * json: string
    | Replace of id: Guid * name: string * json: string
    | Delete of id: Guid
    | Help

let printHelp () =
    printfn
        """
ReferenceValues CLI (API client)

Usage:
  get --id <guid>                      Get a reference value by ID
  get-many --count <n>                 Get multiple reference values
  add [--id <guid>] --name <name> --json <file>   
                                       Add a new reference value (ID optional; generated if not provided)
                                       --json should be the path to a JSON file
  replace --id <guid> --name <name> --json <file>  
                                       Replace an existing reference value
                                       --json should be the path to a JSON file
  delete --id <guid>                   Delete a reference value by ID
  help                                 Show this help message
"""

let rec tryFindArgValue (argName: string) (args: string[]) =
    match args |> Array.tryFindIndex ((=) argName) with
    | Some i when i + 1 < args.Length -> Some args.[i + 1]
    | _ -> None

let parseGuid (s: string) =
    match Guid.TryParse s with
    | true, g -> g
    | false, _ -> failwithf "Invalid GUID: %s" s

let parseInt (s: string) =
    match Int32.TryParse s with
    | true, i -> i
    | false, _ -> failwithf "Invalid integer: %s" s

let printFormattedJson (json: string) =
    try
        let doc = JsonDocument.Parse json
        let options = JsonSerializerOptions(WriteIndented = true)
        let formatted = JsonSerializer.Serialize(doc, options)
        printfn "%s" formatted
    with ex ->
        printfn "Failed to parse JSON: %s" ex.Message
        printfn "Original content:\n%s" json

let args = fsi.CommandLineArgs |> Array.skip 1

let operation =
    if args.Length = 0 || args.[0].ToLower() = "help" then
        Help
    else
        match args.[0].ToLower() with
        | "get" ->
            match tryFindArgValue "--id" args with
            | Some id -> Get(parseGuid id)
            | None -> Help
        | "get-many" ->
            match tryFindArgValue "--count" args with
            | Some count -> GetMany(parseInt count)
            | None -> Help
        | "add" ->
            let id =
                match tryFindArgValue "--id" args with
                | Some idStr -> parseGuid idStr
                | None -> Guid.NewGuid()

            match tryFindArgValue "--name" args, tryFindArgValue "--json" args with
            | Some name, Some jsonFilePath when File.Exists jsonFilePath ->
                let json = File.ReadAllText jsonFilePath
                printfn "Using ID: %O" id
                Add(id, name, json)
            | Some _, Some jsonFilePath ->
                printfn "JSON file not found: %s" jsonFilePath
                Help
            | _ -> Help
        | "replace" ->
            match tryFindArgValue "--id" args, tryFindArgValue "--name" args, tryFindArgValue "--json" args with
            | Some id, Some name, Some jsonFilePath when File.Exists jsonFilePath ->
                let json = File.ReadAllText jsonFilePath
                Replace(parseGuid id, name, json)
            | Some _, Some _, Some jsonFilePath ->
                printfn "JSON file not found: %s" jsonFilePath
                Help
            | _ -> Help
        | "delete" ->
            match tryFindArgValue "--id" args with
            | Some id -> Delete(parseGuid id)
            | None -> Help
        | _ -> Help

let apiBase = "http://localhost:5000/api/AttestationReferenceData"

type ReferenceValueDto = {
    Id: Guid
    Name: string
    JsonData: string
} with

    static member create id name jsonData = {
        Id = id
        Name = name
        JsonData = jsonData
    }

let client = new HttpClient()

let runOperation operation =
    match operation with
    | Help -> async { printHelp () }
    | Get id ->
        async {
            let! response = client.GetAsync $"{apiBase}/{id}" |> Async.AwaitTask

            if response.IsSuccessStatusCode then
                let! content = response.Content.ReadAsStringAsync() |> Async.AwaitTask
                printFormattedJson content
            else
                printfn "Error: %s" response.ReasonPhrase
        }
    | GetMany count ->
        async {
            let! response = client.GetAsync $"{apiBase}?count={count}" |> Async.AwaitTask

            if response.IsSuccessStatusCode then
                let! content = response.Content.ReadAsStringAsync() |> Async.AwaitTask
                printFormattedJson content
            else
                printfn "Error: %s" response.ReasonPhrase
        }
    | Add(id, name, json) ->
        async {
            let dto = ReferenceValueDto.create id name json

            let content = JsonContent.Create dto
            let! response = client.PostAsync(apiBase, content) |> Async.AwaitTask

            if response.IsSuccessStatusCode then
                printfn "Added successfully!"
            else
                let! err = response.Content.ReadAsStringAsync() |> Async.AwaitTask
                printfn "Error: %s" err
        }
    | Replace(id, name, json) ->
        async {
            let dto = ReferenceValueDto.create id name json

            let content = JsonContent.Create dto
            let! response = client.PutAsync($"{apiBase}/{id}", content) |> Async.AwaitTask

            if response.IsSuccessStatusCode then
                printfn "Replaced successfully!"
            else
                let! err = response.Content.ReadAsStringAsync() |> Async.AwaitTask
                printfn "Error: %s" err
        }
    | Delete id ->
        async {
            let! response = client.DeleteAsync $"{apiBase}/{id}" |> Async.AwaitTask

            if response.IsSuccessStatusCode then
                printfn "Deleted successfully!"
            else
                let! err = response.Content.ReadAsStringAsync() |> Async.AwaitTask
                printfn "Error: %s" err
        }

runOperation operation |> Async.RunSynchronously
