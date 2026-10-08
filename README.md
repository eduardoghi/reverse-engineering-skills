# reverse-engineering-skills

Skills and helper scripts for Claude Code reverse-engineering work. New skills get added as they're needed.

## Skills

- `skills/java-decompile`: decompile JAR and class files with Vineflower, CFR as a second opinion and
  `javap` bytecode to settle disagreements.
- `skills/delphi-bpl`: reverse engineer 32-bit Delphi packages and binaries, from exported names and
  string literals to decompiled functions with rz-ghidra or Ghidra and ReVa.

## Scripts

- `bin/java-decompile`: wrapper around Vineflower used by the `java-decompile` skill. Run it with `--help`
  for the options.
- `bin/bpl-xref`: cross-references for 32-bit PE files, used by the `delphi-bpl` skill. Finds the code
  that uses a string literal (`str`), the calls and pointers to an address (`calls`), and prints rizin
  flags that name import thunks and string literals in the disassembly (`flags`).

## Setup

Claude Code loads personal skills from `~/.claude/skills`. Link each skill there and put the scripts on
`PATH`. The links can be re-run safely:

```sh
mkdir -p ~/.claude/skills ~/.local/bin
ln -sfn "$PWD/skills/java-decompile" ~/.claude/skills/java-decompile
ln -sfn "$PWD/bin/java-decompile" ~/.local/bin/java-decompile
ln -sfn "$PWD/skills/delphi-bpl" ~/.claude/skills/delphi-bpl
ln -sfn "$PWD/bin/bpl-xref" ~/.local/bin/bpl-xref
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
```

`--clean` only empties directories that java-decompile created or initialized while they were empty
(they have a `.java-decompile-output` marker). It refuses any other non-empty folder.

## License

MIT, see `LICENSE`.
