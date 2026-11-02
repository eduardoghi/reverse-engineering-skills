# reverse-engineering-skills

[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/eduardoghi/badge.svg)](https://hub.xerj.org/contributors/eduardoghi)

Skills and helper scripts for Claude Code reverse-engineering work. New skills get added as they're needed.

## Skills

- `skills/java-decompile`: decompile JAR and class files with Vineflower, CFR as a second opinion and
  `javap` bytecode to settle disagreements.
- `skills/delphi-bpl`: reverse engineer 32-bit Delphi packages and binaries, from exported names and
  string literals to decompiled functions with rz-ghidra or Ghidra and ReVa.
- `skills/binary-diff`: compare two builds of a native binary with ghidriff and read which functions
  were added, removed or changed.
- `skills/binary-patch`: patch the machine code of a 32-bit PE file in place, add new code through
  trampolines in unused space, test it with unicorn and describe the patch as byte patterns.
- `skills/wine-debugging`: find why a Windows program is slow or dies under Wine on Linux, measure what
  a network share and the font engine cost, and capture a silent crash.
- `skills/unreal-engine`: go from what a player sees in an Unreal Engine 4 game to the map or blueprint
  behind it, export it with CUE4Parse and read its bytecode with `kismet-trace`.
- `skills/native-memory-tracing` finds what keeps growing in a native program on Linux without its source,
  including GPU memory per DRM client, stacks of each allocation and isolation by layers.
- `skills/dotnet-decompile`: decompile .NET assemblies to C# and XAML with ilspycmd, list the native
  functions they call and read the configuration and Entity Framework model of the program.
- `skills/installer-triage`: decide whether a Windows installer or the programs inside it look malicious
  without running anything, from what the installer declares to tampering in each binary.

## Scripts

- `bin/gem-log.c` is an `LD_PRELOAD` library for the `native-memory-tracing` skill that records the size and
  stack of each i915 buffer a program creates.
- `bin/java-decompile`: wrapper around Vineflower used by the `java-decompile` skill. Run it with `--help`
  for the options.
- `bin/bpl-xref`: cross-references for 32-bit PE files, used by the `delphi-bpl` skill. Finds the code
  that uses a string literal or a resourcestring (`str`), the calls and pointers to an address
  (`calls`), prints rizin flags that name import thunks and string literals in the disassembly
  (`flags`), lists every literal and resourcestring in a form `diff` can compare between builds
  (`strings`), reads the form resources to map each event to its method (`dfm`) and lists the
  published methods and fields of each class from its VMT, which also works on EXEs without exports
  (`vmt`).
- `bin/pe-stacks`: call stacks of 32-bit Windows code from a `perf` recording of a Wine process, used by
  the `wine-debugging` skill. Under wow64 `perf` can't unwind those frames, so it scans the raw user
  stack that `--call-graph=dwarf` copies for return addresses into the PE images and names them from
  the export tables.
- `ghidra_scripts/ApplyNames.java`: Ghidra script that names functions from `bpl-xref vmt --names`,
  creating the ones Ghidra missed, used by the `binary-diff` skill before diffing Delphi executables.
- `bin/kismet-trace`: reads Unreal Engine blueprint bytecode from a CUE4Parse JSON export. Prints the
  functions as pseudocode with the start of each event marked (`list`), lists the events (`events`)
  and follows one event through the jumps of the ubergraph, branch by branch (`follow`).
- `bin/ue-locres`: prints the strings of an Unreal Engine `.locres` file, any format version, and
  filters them by key or text.
- `bin/ue-save`: reads Unreal Engine save files (GVAS), also inside Unreal's compressed chunk format
  with zlib or Oodle, and lists the header and the properties with their values (`props`) or writes
  the plain GVAS (`unpack`).
- `bin/inno-unpack` reads Inno Setup installers from version 6.0 to 7.1 without running them. Prints
  the format and how the data is stored (`info`), the files with size and hash (`list`), what the
  installer does besides copying files (`actions`), the names and strings in the compiled `[Code]`
  script (`code`) and its disassembly with every external function it can reach (`disasm`), writes the
  setup engine with the call filter undone (`engine`) and the embedded files after checking each hash
  (`extract`). `--password` decrypts formats from 6.4 on, including `Encryption=full`. A modified build
  is reported as such, and the fork of 6.4.2 that uses XXH32 is read in full. Anything older than 6.0
  still needs innoextract, except 5.5.7 (u), and so do the ARC4 formats before 6.4.
- `bin/nsis-script` prints what an NSIS 3 Unicode installer does without running it, such as the files it
  extracts, what it runs and the registry keys it writes. 7-Zip extracts the files but doesn't show this.
- `bin/hsp-unpack` reads programs written in HSP without running them. Lists the DPMX archive that follows
  the runtime (`list`), decodes `start.ax` and prints the DLLs and functions it declares and its strings
  (`script`) and writes the files (`extract`).

## Setup

Install it as a plugin, inside Claude Code 2.1.275 or later:

```text
/plugin install reverse-engineering-skills --marketplace eduardoghi/reverse-engineering-skills
```

On older versions, add the marketplace first:

```text
/plugin marketplace add eduardoghi/reverse-engineering-skills
/plugin install reverse-engineering-skills@reverse-engineering-skills
```

The skills show up as `reverse-engineering-skills:java-decompile` and so on, and the scripts in `bin/` are on `PATH`
inside Claude Code. To use the scripts outside it, or to work on a clone, link them instead.

Claude Code loads personal skills from `~/.claude/skills`. Link each skill there and put the scripts on
`PATH`. The links can be re-run safely:

```sh
mkdir -p ~/.claude/skills ~/.local/bin
ln -sfn "$PWD/skills/java-decompile" ~/.claude/skills/java-decompile
ln -sfn "$PWD/bin/java-decompile" ~/.local/bin/java-decompile
ln -sfn "$PWD/skills/delphi-bpl" ~/.claude/skills/delphi-bpl
ln -sfn "$PWD/bin/bpl-xref" ~/.local/bin/bpl-xref
ln -sfn "$PWD/bin/kismet-trace" ~/.local/bin/kismet-trace
ln -sfn "$PWD/bin/ue-locres" ~/.local/bin/ue-locres
ln -sfn "$PWD/bin/ue-save" ~/.local/bin/ue-save
ln -sfn "$PWD/skills/binary-diff" ~/.claude/skills/binary-diff
ln -sfn "$PWD/skills/binary-patch" ~/.claude/skills/binary-patch
ln -sfn "$PWD/skills/wine-debugging" ~/.claude/skills/wine-debugging
ln -sfn "$PWD/bin/pe-stacks" ~/.local/bin/pe-stacks
ln -sfn "$PWD/skills/unreal-engine" ~/.claude/skills/unreal-engine
ln -sfn "$PWD/skills/dotnet-decompile" ~/.claude/skills/dotnet-decompile
ln -sfn "$PWD/skills/native-memory-tracing" ~/.claude/skills/native-memory-tracing
ln -sfn "$PWD/bin/inno-unpack" ~/.local/bin/inno-unpack
ln -sfn "$PWD/bin/nsis-script" ~/.local/bin/nsis-script
ln -sfn "$PWD/bin/hsp-unpack" ~/.local/bin/hsp-unpack
ln -sfn "$PWD/skills/installer-triage" ~/.claude/skills/installer-triage
java-decompile --check
bpl-xref --help > /dev/null && echo 'bpl-xref ok'   # fails if pefile is missing
```

Requirements for `java-decompile`:

- Java 17+ with the JDK tools (`javap`, `jar`)
- Vineflower (AUR package `vineflower` on Arch)
- CFR (`pacman -S cfr`)
- `unzip`, for the `--only` fallback

Requirements for `delphi-bpl`:

- Python 3 with `pefile` (`pacman -S python-pefile`)
- rizin with the rz-ghidra plugin (`pacman -S rizin rz-ghidra`)
- Optional, for long sessions: Ghidra 12.1.3 or newer and the ReVa extension

Requirements for `unreal-engine`:

- The .NET 10 SDK to build CUE4Parse and the small exporter the skill shows
- `kismet-trace`, below, and `ue-locres` and `ue-save`, which need only Python 3. `ue-save` needs the
  Oodle library the exporter downloads for Oodle-compressed saves

Requirements for `dotnet-decompile`:

- The .NET SDK and `ilspycmd` (`dotnet tool install -g ilspycmd`), tried with version 11.1 on .NET 10
- The .NET Framework reference assemblies from NuGet, for .NET Framework programs (see the skill)
- `jq` to list the native calls, and Python 3 with `pefile` to sort an install folder

Requirements for `kismet-trace`:

- Python 3, standard library only
- A JSON export from [CUE4Parse](https://github.com/FabianFG/CUE4Parse) made with `ReadScriptData`
  set on the provider, so the functions carry their bytecode

Requirements for `inno-unpack`:

- Python 3, standard library only
- Optional, `pycryptodome` to decrypt large installers, since plain Python manages about half a megabyte
  per second
- Optional, `xxhash` to verify the files of a modified build, which are otherwise written but reported
  as not verified

Requirements for `nsis-script` and `hsp-unpack`:

- Python 3, standard library only

Requirements for `installer-triage`:

- `inno-unpack`, `nsis-script` and `hsp-unpack`, above
- Python 3 with `pefile`, and `capstone` to read machine code when a finding calls for it

Requirements for `binary-diff`:

- Ghidra 12.1.3 or newer, with the PyGhidra wheel it ships
- `uv` to install the ghidriff fork into its own venv (see the skill) and `jq` to read its JSON

Requirements for `binary-patch`:

- Python 3 with `pefile`
- `keystone` to assemble the new code and `unicorn` to run it before patching
  (`pacman -S python-keystone python-unicorn` on Arch, or `pip install keystone-engine unicorn` in a venv)

Requirements for `native-memory-tracing`:

- `strace` and `perf`, `gcc` and the kernel DRM headers for the allocation shim
- `binutils` for `readelf` and `addr2line`

Requirements for `wine-debugging`:

- `strace` and `perf` (`pacman -S strace perf`)
- `mingw-w64-gcc`, only for the text width measurement

## Examples

```sh
java-decompile app.jar                          # -> /tmp/app-src.XXXXXX
java-decompile app.jar /tmp/app-src
java-decompile --clean app.jar /tmp/app-src     # replace an earlier java-decompile run
java-decompile --only=com/vendor/product app.jar /tmp/product-src
java-decompile --check

bpl-xref str app.bpl 'CustomerName' 'Invalid order'
bpl-xref calls app.bpl 0x0045a1c0
bpl-xref flags app.bpl 0x0045a1c0 0x0045b000 > flags.rz
bpl-xref dfm app.bpl TFORDEREDIT
bpl-xref dfm --events app.bpl
bpl-xref dfm --all --no-geometry app.bpl > app.dfm
bpl-xref strings app.bpl > app.txt

kismet-trace events Level.umap.json
kismet-trace list Level.umap.json --hide DoOnce
kismet-trace follow Level.umap.json OnDoorOpened

ue-locres Game.locres "old door"
ue-save props slot1.sav --oodle oodle-data-shared.dll --depth 1
bpl-xref vmt app.exe TFORDEREDIT

inno-unpack info setup.exe
inno-unpack actions setup.exe
inno-unpack code setup.exe --dump script.bin
inno-unpack disasm setup.exe --proc CurPageChanged
inno-unpack engine setup.exe engine.bin
inno-unpack extract setup.exe /tmp/setup-files --only '*.exe'
inno-unpack extract setup.exe /tmp/setup-files --password secret

nsis-script setup.exe --strings

hsp-unpack list keygen.exe
hsp-unpack script keygen.exe --dump start.ax
hsp-unpack extract keygen.exe /tmp/keygen-files
```

`--clean` only empties directories that java-decompile created or initialized while they were empty
(they have a `.java-decompile-output` marker). It refuses any other non-empty folder.

## Tests

```sh
python3 -m unittest discover -s tests
```

The tests build their inputs in code (small PE files for `bpl-xref`, a blueprint export for
`kismet-trace`, localization files and saves for `ue-locres` and `ue-save`, installers of every
format for `inno-unpack` and `nsis-script`, DPMX archives for `hsp-unpack`), so no real binaries or
games are needed. The `bpl-xref` tests need `pefile` and are
skipped without it, and the `inno-unpack` tests that check XXH128 digests need `xxhash`.

## License

MIT, see `LICENSE`.
