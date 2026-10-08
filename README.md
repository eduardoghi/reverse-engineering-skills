# reverse-engineering-skills

Skills and helper scripts for Claude Code reverse-engineering work. New skills get added as they're needed.

## Skills

- `skills/java-decompile`: decompile JAR and class files with Vineflower, CFR as a second opinion and
  `javap` bytecode to settle disagreements.

## Scripts

- `bin/java-decompile`: wrapper around Vineflower used by the `java-decompile` skill. Run it with `--help`
  for the options.

## Setup

Claude Code loads personal skills from `~/.claude/skills`. Link each skill there and put the scripts on
`PATH`. The links can be re-run safely:

```sh
mkdir -p ~/.claude/skills ~/.local/bin
ln -sfn "$PWD/skills/java-decompile" ~/.claude/skills/java-decompile
ln -sfn "$PWD/bin/java-decompile" ~/.local/bin/java-decompile
java-decompile --check
```

Requirements:

- Java 17+ with the JDK tools (`javap`, `jar`)
- Vineflower (AUR package `vineflower` on Arch)
- CFR (`pacman -S cfr`)
- `unzip`, for the `--only` fallback

## Examples

```sh
java-decompile app.jar                          # -> /tmp/app-src.XXXXXX
java-decompile app.jar /tmp/app-src
java-decompile --clean app.jar /tmp/app-src     # replace an earlier java-decompile run
java-decompile --only=com/vendor/product app.jar /tmp/product-src
java-decompile --check
```

`--clean` only empties directories that java-decompile created itself (they have a
`.java-decompile-output` marker). It refuses any other non-empty folder.
