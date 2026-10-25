# reverse-engineering-skills

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

## Scripts

- `bin/java-decompile`: wrapper around Vineflower used by the `java-decompile` skill. Run it with `--help`
  for the options.
- `bin/bpl-xref`: cross-references for 32-bit PE files, used by the `delphi-bpl` skill. Finds the code
  that uses a string literal or a resourcestring (`str`), the calls and pointers to an address
  (`calls`), prints rizin flags that name import thunks and string literals in the disassembly
  (`flags`), reads the form resources to map each event to its method (`dfm`) and lists the published
  methods and fields of each class from its VMT, which also works on EXEs without exports (`vmt`).

## Setup

Claude Code loads personal skills from `~/.claude/skills`. Link each skill there and put the scripts on
`PATH`. The links can be re-run safely:

```sh
mkdir -p ~/.claude/skills ~/.local/bin
ln -sfn "$PWD/skills/java-decompile" ~/.claude/skills/java-decompile
ln -sfn "$PWD/bin/java-decompile" ~/.local/bin/java-decompile
ln -sfn "$PWD/skills/delphi-bpl" ~/.claude/skills/delphi-bpl
ln -sfn "$PWD/bin/bpl-xref" ~/.local/bin/bpl-xref
ln -sfn "$PWD/skills/binary-diff" ~/.claude/skills/binary-diff
ln -sfn "$PWD/skills/binary-patch" ~/.claude/skills/binary-patch
ln -sfn "$PWD/skills/wine-debugging" ~/.claude/skills/wine-debugging
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

Requirements for `binary-diff`:

- Ghidra 12.1.3 or newer, with the PyGhidra wheel it ships
- `uv` to install the ghidriff fork into its own venv (see the skill) and `jq` to read its JSON

Requirements for `binary-patch`:

- Python 3 with `pefile`
- `keystone` to assemble the new code and `unicorn` to run it before patching
  (`pacman -S python-keystone python-unicorn` on Arch, or `pip install keystone-engine unicorn` in a venv)

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
bpl-xref vmt app.exe TFORDEREDIT
```

`--clean` only empties directories that java-decompile created or initialized while they were empty
(they have a `.java-decompile-output` marker). It refuses any other non-empty folder.

## License

MIT, see `LICENSE`.
