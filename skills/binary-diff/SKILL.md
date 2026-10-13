---
name: binary-diff
description: Compare two builds of a native binary (PE, ELF or Mach-O executable or library) with ghidriff to find the functions that were added, removed or changed. Use when you need to know what changed between versions, whether a fix landed in a newer build, or where a patch touched the code.
---

# Binary diffing with ghidriff

[ghidriff](https://github.com/eduardoghi/ghidriff), a fork of
[clearbluejar/ghidriff](https://github.com/clearbluejar/ghidriff) with matching and report fixes,
imports both files into a Ghidra project, analyzes them, matches functions (by symbol name first, then
by bytes, instructions, graph structure, strings and BSim similarity) and writes a Markdown report plus
JSON with every match and a decompiled diff of each changed function.

A function marked as changed is a lead, not a conclusion. The diff comes from decompiled code, so
register allocation, stack layout and moved callees all show up as changes. Read the diff, and when
the question depends on one branch or one store, confirm it in the disassembly of both builds.

## Setup

Install the fork from its `main` branch, which is not on PyPI, together with the PyGhidra wheel that
ships with the Ghidra install, so the Python package matches the Ghidra version.

```sh
uv venv ~/.venvs/ghidriff
uv pip install --python ~/.venvs/ghidriff/bin/python \
    /opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*-py3-none-any.whl \
    git+https://github.com/eduardoghi/ghidriff
```

The PyPI release (1.0.0) crashes at the end of a run on Python 3.14 when a function failed to
decompile, misses changes in functions matched by name that kept their size, and can pair one
function with two others through implied matches.

## Run

Give the two files different names, because ghidriff names the programs and the project after them.

```sh
GHIDRA_INSTALL_DIR=/opt/ghidra ~/.venvs/ghidriff/bin/ghidriff --no-symbols \
    -p diff/proj -o diff/out --log-path diff/ghidriff.log app_1.0.bin app_1.1.bin
```

- `--no-symbols` skips the symbol server lookup. Leave it out only for Windows binaries that have
  public PDBs.
- A 14 MB 32-bit library with 56,000 functions took 17 to 19 minutes on 20 cores the first time
  (import and analysis of both files) and 3 to 7 minutes on a rerun with the same `-p`, which reuses
  the analyzed programs. The project used 420 MB. Keep it while you iterate and delete it afterwards.
- Ghidra refuses a project path with any element that starts with a dot, such as `~/.cache/...`, so
  keep `-p` out of hidden directories.
- ghidriff turns on Ghidra's Decompiler Parameter ID analyzer, and turns off
  `Shared Return Calls.Assume Contiguous Functions Only` when a binary already has more than 1000
  functions before analysis, which in practice means a PDB was loaded. Override either with
  `--program-options opts.json`, for example
  `{"program_options": {"Analyzers": {"Decompiler Parameter ID": false}}}`. Both builds need the same
  options, so don't mix a `.gzf` analyzed elsewhere with a fresh import.
- Run it in the background and watch the log for `| ghidriff |` lines and `Traceback`. Ghidra prints a
  lot of harmless warnings.
- Both files are analyzed in parallel. An `OverlappingFileLockException` from
  `WindowsResourceReferenceAnalyzer` only means that analyzer was skipped on one side and doesn't
  affect the function matching.
- `Failed to decompile ... Low-level Error` warnings usually come from data that the loader turned into
  functions, such as exported type info or vtables. They don't stop the run.

## Read the results

The Markdown report lists at most 200 functions per section (`--max-section-funcs`), so a large diff
gets cut. The JSON in `out/json/*.ghidriff.json` has everything. Start from the counts:

```sh
jq '.stats | {added_funcs_len, deleted_funcs_len, matched_funcs_with_code_changes_len, func_match_overall_percent}' \
    diff/out/json/*.ghidriff.json
```

List functions whose code changed, most changed first, with the address in the old build:

```sh
jq -r '.functions.modified[] | select(.diff_type | index("code"))
       | "\(.ratio)\t\(.old.address)\t\(.old.name)"' diff/out/json/*.ghidriff.json | sort -n
```

Then narrow down by name (a class, module or namespace) and read one function's decompiled diff:

```sh
jq -r '.functions.modified[] | select(.old.name | test("Order")) | .diff' diff/out/json/*.ghidriff.json
jq -r '.functions.added[].name, .functions.deleted[].name' diff/out/json/*.ghidriff.json
```

- `ratio` is the similarity of the decompiled code without the signature. Near 1.0 is a small change,
  near 0 a rewrite.
- `diff_type` lists what changed. `address` alone means the function only moved. `called` means its
  callees changed, which can be the whole difference, so check the diff before assuming the body
  changed.
- Functions with the same size and reference count are compared instruction by instruction, with
  addresses masked, so a changed constant or field offset shows up even when nothing else moved. A
  pair sent to the diff that way is dropped when only its address changed.
- A function can appear more than once in `modified` when two correlators matched it.
- Functions in `added` and `deleted` had no match. A renamed or split function shows up as one deleted
  and one or more added, so search the new build for its strings before concluding it was removed.
- `strings` in the JSON lists added and removed string literals, a quick way to spot new features and
  new error messages.

Delphi packages have their own notes in the `delphi-bpl` skill.
