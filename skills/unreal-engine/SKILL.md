---
name: unreal-engine
description: Reverse engineer the game logic of an Unreal Engine 4 game from its pak files, going from the text a player sees to the map or blueprint that runs it and reading the blueprint bytecode with kismet-trace. Use when you need to know why a mission, trigger or NPC behaves the way it does, what a level script does after a save is loaded, or where a game keeps a piece of data.
---

# Unreal Engine game logic

Much of the gameplay logic of an Unreal Engine game (missions, triggers, NPC routes, what happens
when the player walks into a volume) is written in blueprints. A packaged game keeps them as Kismet
bytecode inside `.uasset` and `.umap` files in the paks. The rest is native C++ in the executable. A
blueprint can call a native function, but only the function's name is visible in the assets.

[CUE4Parse](https://github.com/FabianFG/CUE4Parse) reads the paks and exports assets as JSON. From
this repo's `bin/`, `kismet-trace` reads the bytecode in that JSON, `ue-locres` the localized
strings and `ue-save` the save files.

## Setup

CUE4Parse is a .NET library. Clone it and build a small exporter against it with the .NET SDK.
`CUE4PARSE_SKIP_NATIVE=1` skips its optional native part, which needs CMake.

```sh
git clone --depth 1 https://github.com/FabianFG/CUE4Parse
dotnet new console -o ue-export
dotnet add ue-export reference CUE4Parse/CUE4Parse/CUE4Parse.csproj
CUE4PARSE_SKIP_NATIVE=1 dotnet build -c Release ue-export
```

Replace `ue-export/Program.cs` with this before building. The program ends up in
`ue-export/bin/Release/net10.0/`.

```csharp
// ue-export GAME_DIR EGAME list PATTERN...       file paths that contain a pattern
// ue-export GAME_DIR EGAME json OUTDIR PATH...   exports of each package as JSON, with bytecode
// ue-export GAME_DIR EGAME raw OUTDIR PATTERN... decompressed bytes of matching files
using CUE4Parse.Compression;
using CUE4Parse.FileProvider;
using CUE4Parse.UE4.Versions;
using Newtonsoft.Json;

var (dir, game, cmd, rest) = (args[0], Enum.Parse<EGame>(args[1]), args[2], args[3..]);
// Downloads oodle-data-shared.dll next to the program on the first run.
OodleHelper.Initialize(Path.Combine(AppContext.BaseDirectory, OodleHelper.OodleFileName));

var provider = new DefaultFileProvider(dir, SearchOption.AllDirectories, new VersionContainer(game), StringComparer.OrdinalIgnoreCase);
provider.ReadScriptData = true; // without it functions come out with no ScriptBytecode
provider.Initialize();
provider.Mount();

bool Matches(string path, IEnumerable<string> patterns) =>
    patterns.Any(p => path.Contains(p, StringComparison.OrdinalIgnoreCase));

switch (cmd)
{
    case "list":
        foreach (var path in provider.Files.Keys.Where(p => Matches(p, rest)).Order())
            Console.WriteLine(path);
        break;
    case "json":
        foreach (var path in rest[1..])
        {
            var dest = Path.Combine(rest[0], path + ".json");
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            try
            {
                File.WriteAllText(dest, JsonConvert.SerializeObject(provider.LoadPackage(path).GetExports(), Formatting.Indented));
                Console.WriteLine($"ok {path}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"FAIL {path}: {e.Message}");
            }
        }
        break;
    case "raw":
        foreach (var (path, file) in provider.Files.Where(f => Matches(f.Key, rest[1..])))
        {
            var dest = Path.Combine(rest[0], path);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            File.WriteAllBytes(dest, file.Read());
            Console.WriteLine(path);
        }
        break;
}
```

- `GAME_DIR` is the folder that holds `Content/Paks`. `EGAME` is a value of CUE4Parse's `EGame` enum
  (`UE4/Versions/EGame.cs`). Pick the game's own entry when it has one, because some games change the
  asset format, otherwise `GAME_UE4_<minor>` for the engine version.
- Oodle compression (method 4 in older paks) needs `oodle-data-shared.dll`. `OodleHelper.Initialize`
  downloads it from the OodleUE releases on GitHub the first time.
- Paks with an encrypted index need the AES key, passed with `provider.SubmitKey(new FGuid(), new
  FAesKey("0x..."))` before `Mount`. That path hasn't been tried with this skill, nor IoStore
  containers (`.utoc`/`.ucas`).
- A single asset can fail with a message from CUE4Parse while the rest export fine. In a sample of
  400 assets of one game, 43 failed on the game's own structures.
- Keep the game files and the exports out of any repository.

## Method

1. **Look at the layout.** `Content/Paks` holds the main pak. Games may add folders of smaller paks
   (per region or mission) and a pak per language. An unencrypted index lists every path, and
   `ue-export ... list` is the quickest way to see what the game has. Map scripts usually live in
   `.umap` files under `Content/Maps`, and data assets (mission definitions, tables) in `.uasset`
   files next to the blueprints.

2. **Go from the text to the asset.** The player sees a title or a message, and the assets use keys
   and internal names. The strings live in `Content/Localization/<target>/<culture>/<target>.locres`.
   Extract it with `ue-export ... raw` and search it with `ue-locres`, which prints namespace, key and
   text per line and reads every format version:

   ```sh
   ue-locres Content/Localization/Game/en/Game.locres "old door"   # entries whose key or text match
   ```

   CUE4Parse's own culture lookup can fail on a game's custom localization folders, which is why the
   file is read directly. The key can carry the internal code of what it labels (a mission title key
   holding the mission's code), which leads to its data asset, and a mission data asset names the map
   that runs it.

3. **Export the map or blueprint as JSON** with `ue-export ... json`, using the path as `list`
   prints it. A map export holds the level script (`<map>_C`, with an `ExecuteUbergraph` function),
   every placed actor and its components.

4. **Read the logic with `kismet-trace`.**

   ```sh
   kismet-trace events Level.umap.json                 # each event and where its code starts
   kismet-trace follow Level.umap.json OnDoorOpened    # what one event runs, branch by branch
   kismet-trace list Level.umap.json --hide DoOnce     # everything as pseudocode, minus the noise
   ```

   A blueprint compiles all its event graphs into one `ExecuteUbergraph` function full of jumps, so
   reading `list` from top to bottom doesn't work. Start from the event that matters and `follow` it.
   Each `if not (...)` prints its target as its own branch afterwards, and a latent action such as
   `Delay` or `Wait` prints where the event resumes later. Statements already shown are not repeated.
   `--hide` takes a regular expression for bookkeeping that repeats everywhere, such as the arrays
   behind a project's own DoOnce macros. Check what a pattern hides before trusting the output,
   because a broad one can drop the call you are looking for.

5. **Connect events to actors in the JSON.** Events bound to a placed actor are named
   `BndEvt__<Actor>_K2Node_..._<Delegate>`, with the actor name from when the event was created. If
   the actor was renamed later, the name in the function is stale. The binding that counts is in the
   actor itself, in the `InvocationList` of its delegate property (`OnActorBeginOverlap`, for
   example), which names the function. Component positions (`RelativeLocation`) are
   relative to their `AttachParent`, so add up the chain to place a trigger or waypoint in the world.

## Bugs that appear after loading a save

A level script runs its normal flow once, and a different path when a checkpoint is restored. Look
for state that the normal flow builds and the restore path doesn't:

- When the game saves actors through Unreal's SaveGame flag, the properties with `SaveGame` in their
  `PropertyFlags` are the blueprint variables that come back from the save. Everything else starts
  from its default after a load.
- Compare what the events the game calls on a restore run with the normal start. They are the game's
  own (one game named them `OnRestoreCheckpoint` and `ReceivePreSaveGameLoaded`), so look for them
  in `kismet-trace events`. A delegate bound only in the normal flow (`+=` or
  `bind` in `follow`) is never bound after a load, and whatever waits on it never fires.
- An overlap event that doesn't check which actor entered fires for NPCs and vehicles too. Combined
  with a DoOnce gate, one wrong overlap can use up the only trigger.
- A step that only continues when another event succeeds (a conversation, an animation) has no way
  forward when that event fails, unless the script retries.

Native code decides part of the outcome. What a called C++ function does, and when it reports
failure, isn't in the assets. Before concluding, check that the symptom the code predicts matches
what players report, including where it happens. A plausible chain that predicts the wrong place is
the wrong chain.

## Save files

Saves written through Unreal's SaveGame system are GVAS files. They start with the magic `GVAS`, the
save and package versions, the engine version and the save class name, followed by tagged properties
until `None`. Games may wrap them in their own header and compress them in Unreal's chunk format (a
64-bit tag `0x9E2A83C1`, the block size, compressed and uncompressed totals, then the size of each
block) with zlib or Oodle. `ue-save` reads both:

```sh
ue-save props slot1.sav --oodle oodle-data-shared.dll              # header and top-level properties
ue-save props slot1.sav --oodle oodle-data-shared.dll --depth 2    # fields of structs and struct arrays
ue-save unpack slot1.sav slot1.gvas --oodle oodle-data-shared.dll  # the plain GVAS, for a hex editor
```

Use the Oodle library the exporter downloaded. `ue-save` works out from the bytes whether a save has
the custom version block and the tag before the items of struct arrays, because the header can't be
trusted for them. One game built on UE 4.11 declared package version 500, from which Unreal writes
that tag, but its saves had none, and its header had no custom version block. Games can also append
their own data after the property list, and `props` says how many bytes follow it. Property tags of
UE 5.4 and newer use a different layout and are refused.

Work on copies. Before putting a save from elsewhere in the game's folder, back up the folder and
turn off Steam Cloud for the game, or the swapped save can be uploaded over the real one.
