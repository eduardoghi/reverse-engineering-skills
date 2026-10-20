---
name: delphi-bpl
description: Reverse engineer 32-bit Delphi binaries, especially BPL runtime packages, by going from exported names and string literals to the code that uses them and decompiling it with rz-ghidra or Ghidra (ReVa). Use when you need to know what a function in a .bpl, Delphi .dll or Delphi .exe does, which code reads a field or string, or how a value is calculated.
---

# Delphi BPL reverse engineering

A BPL (Borland Package Library) is a regular 32-bit PE DLL built by Delphi or C++Builder. It exports
every symbol of every unit in the package with Borland name mangling, so most functions already have
their real names. Start from those names and from string literals, not from a blank disassembly.

Decompiled Delphi code is rougher than decompiled Java. Delphi's register calling convention, `Extended`
floats and string helpers confuse every decompiler, so read the output as a lead and check anything
important in the disassembly.

Tools: `bpl-xref` (from this repo's `bin/`, needs `python-pefile`), `rizin` with the `rz-ghidra`
plugin, and Ghidra 12.1.3 or newer with the ReVa extension for long sessions.

## Method

1. **Read the exports and imports.** They cost about a second even on a 30 MB package.

   ```sh
   rz-bin -E app.bpl > exports.txt                       # vaddr in column 3, name last
   grep -i 'TOrder@' exports.txt | awk '{print $3, $NF}'
   rz-bin -l app.bpl                                     # other packages and DLLs it imports
   ```

   The imported packages tell you which BPLs hold the code it calls. Repeat step 1 on them when a call
   leaves the file.

2. **Go from a string to the code** when you know a field name, message, SQL fragment or key but not
   the function:

   ```sh
   bpl-xref str app.bpl 'CustomerName' 'Invalid order'
   ```

   For each match it prints the literal kind guessed from the bytes before it (AnsiString,
   UnicodeString, ShortString), every relocated pointer to it in code, the nearest
   `push ebp; mov ebp, esp` before each reference and the exports around it. Nested procedures are
   not exported and sit right before their parent, so when the reference is between two exports the
   "next" one is often the owner.

   A `ptr` line instead of `ref` means the pointer sits in a data section, usually a table (package
   names, resource strings, initialized records). The code reads the table slot, not the string, so
   run `bpl-xref calls` on the `ptr` address to reach it.

   An EXE usually has no exports, so there are no "prev"/"next" lines. Start from the entry point
   (`rz-bin -e app.exe`) and from the import thunks, which `flags` names.

3. **Go from a screen to the code** when you know what the user clicks but not which method runs.
   Delphi stores each form as a binary DFM in an RCDATA resource named after the form class, and the
   form maps every event to a method name.

   ```sh
   bpl-xref dfm app.bpl                          # every form, its class and number of events
   bpl-xref dfm app.bpl TFORDEREDIT              # one form as text .dfm
   bpl-xref dfm --events app.bpl | grep -i -A1 'btnSave'
   ```

   Find the form by a caption or label in the text output, then take the component's `OnClick`,
   `OnChange` or other event. `--events` prints each handler with the exported method it names
   (`@Unit@TForm@BtnSaveClick$qqrp14System@TObject`), so the address is ready for steps 4 to 6.
   Events inside collection items show up as `Edit1.Buttons[0].OnClick`. A handler marked `?` was
   not found in the form's class, usually because an ancestor form declares it, and every method
   with that name is listed as a candidate.

4. **Find who calls a function**, especially a nested procedure, which has no export and no name:

   ```sh
   bpl-xref calls app.bpl 0x0045a1c0 '@Uorders@TOrder@Post$qqrv'
   ```

   It takes hex addresses or exact export names and lists `call`/`jmp rel32` instructions plus
   relocated pointers (VMT slots, event handler tables). The rel32 hits come from a byte scan, not
   from disassembly, so treat them as candidates and check each one with `pd 1 @ addr`. Virtual and
   interface calls go through `call dword [reg + offset]` and don't show up. For those, find the VMT
   slot that points at the method (a `ptr` hit) and search for its offset.

5. **Read the disassembly with names.** Plain `pd` shows `call 0x00401f30` and `mov edx, 0x0045c6fc`.
   Generate rizin flags for the import thunks and for the string literals the range uses, then save
   the disassembly to a file:

   ```sh
   bpl-xref flags app.bpl 0x0045a1c0 0x0045b000 > flags.rz
   rizin -e scr.color=0 -e asm.comments=false -e asm.lines=false -e asm.bytes=false -q \
       -i flags.rz -c 'pD 0xe40 @ 0x0045a1c0' app.bpl 2>rizin.err > func.asm
   ```

   The same lines then read `call thunk.Uorders_TOrder_Post_qqrv` and `mov edx, str.CustomerName`.
   Use the next export or the parent function's start as the end of the range, and give `pD` the
   size in bytes. A 3.5 KB function is about a thousand lines, so grep the file
   (`grep -n 'call\|0x4b8\]' func.asm`) or read it in pieces instead of printing it whole.

   Always pass `asm.comments=false` to `pd`/`pD` on large files. The comments rizin computes for
   each instruction get slower the longer the listing: on a 60 MB package, 4 KB took 10 s, 16 KB
   didn't finish in 5 minutes, and with comments off 93 KB took 7 s, most of it startup.
   `asm.lines=false` drops the jump arrows, which only get in the way of grep. Flag names are
   cut at 48 characters. Print the full text of a literal with `ps ascii @ addr` (AnsiString),
   `psw @ addr` (UnicodeString) or `psp @ addr` (ShortString, from its length byte). Read
   `fcomp dword [addr]` style constants with `pf f @ addr` (Single) or `pf F @ addr` (Double).

   Without a range, `flags` names every literal in the file. A large package has hundreds of
   thousands, which adds about 7 s to each rizin start. Every start also parses all the exports
   (around 5 s for 60k), so batch addresses with several `-c` options or `-i cmds.rz` in one run.
   rizin warns `bin_file_strings: search interval size ... exceeds max region size` on large files.
   That warning is harmless, but stderr also carries real errors (a flags file that fails to parse,
   a bad command), so send it to a file instead of `/dev/null` and check it when the output is
   empty or the names are missing.

   For a quick look at a wide range without names, `objdump -d -M intel --no-show-raw-insn
   --start-address=0x0045a1c0 --stop-address=0x0045b000 app.bpl` takes a fraction of a second.

6. **Decompile one function with rz-ghidra** when the control flow is hard to follow in the
   disassembly. A small function takes a few seconds, a 2,000-instruction one around 20.

   ```sh
   rizin -e scr.color=0 -e analysis.cc=borland -q \
       -c 'af @ 0x0045a1c0' -c 'pdg @ 0x0045a1c0' app.bpl 2>rizin.err
   ```

   `analysis.cc=borland` only changes `pdg`. `pd` and `pD` ignore it.

7. **Make register arguments visible.** Calls to other Delphi functions come out as `Foo()` with no
   arguments, because the arguments travel in `eax`, `edx` and `ecx`. Give the callee a signature with
   `afs`, keeping `-e analysis.cc=borland` on the command line:

   ```sh
   rizin -e scr.color=0 -e analysis.cc=borland -q \
       -c 'af @ 0x00401f30' \
       -c 'afs void set_value(int self, char *name, double v) @ 0x00401f30' \
       -c 'af @ 0x0045a1c0' -c 'pdg @ 0x0045a1c0' app.bpl 2>rizin.err
   ```

   The call then reads `set_value(self, "CustomerName")`. Both settings are needed. Without `afs` the
   arguments stay hidden, and `afs` without `analysis.cc=borland` reads them from the stack, which
   gives wrong values (`set_value(iVar3, (char *)iVar2, ...)`). `afc borland` adds nothing.
   rz-ghidra warns `Matching calling convention borland ... failed, args may be inaccurate`, which is
   expected. `double` arguments are still shown as two `uStack_*` stores before the call.

8. **Use Ghidra with ReVa for anything longer** than a few functions: cross-references across the
   whole file, call graphs, renaming as you go. See the Ghidra section for import and the time it
   takes.

9. **Confirm in the disassembly** when a conclusion depends on a branch, an offset, a constant or the
   argument order, and always when the decompiled output has `unkfloat10`, `in_EAX` or stack variables
   with no clear source. Quote the address and instruction for each conclusion.

10. **Check the conclusion against what the program does** when it depends on a runtime value (a
    setting, a record, a mode flag) or when someone will act on it. Look for the effect in the data the
    program writes, or run the smallest input that takes the branch in question. When the reading and
    the observed behaviour disagree, one of the assumptions is wrong. Say so and find which one instead
    of reporting either result.

    A branch that depends on a setting read by name needs two answers: where stored values come from
    and what the default is. The loader's query or file read gives the first. The default is usually
    an argument of the call that registers the setting, so search for the setting's name and read the
    arguments around that call. When no stored value exists, the default applies.

## Reading Delphi code

- **Mangled names.** `@Unit@TClass@Method$qqr<params>`. `$qqr` is the register convention, `$qqs`
  stdcall (COM methods). `$bctr` is a constructor, `$bdtr` a destructor. `@$xp$...` is RTTI and
  `@Unit@TClass@` (ending in `@`) is the class VMT, both data even when they sit in the code section.
  The return type is not encoded.
- **Parameter codes.** `x` const, `r` var (by reference), `p` pointer, `v` no parameters, `i` Integer,
  `o` Boolean, `us` Word, `uc` Byte, `d` Double, `g` Extended, and a length-prefixed type name such as
  `17System@AnsiString`. `$qqrx17System@AnsiStringd` is `(const s: AnsiString; d: Double)`.
- **Register convention.** Self goes in `eax` for methods. The first three integer, pointer or string
  parameters go in `eax`, `edx`, `ecx`, and the rest are pushed left to right. `Double` and
  `Extended` always go on the stack, so the decompiler numbers them in reverse (`param_7` is the
  first one). Ordinal results come back in `eax`, floats in `ST(0)`, and strings and records through
  a hidden last `var` parameter.
- **Strings.** An AnsiString literal has a `-1` reference count and a 32-bit length right before the
  first character, and code points at that character. A UnicodeString literal (Delphi 2009 and later)
  is UTF-16 with the same layout plus a code page and element size. ShortString constants and RTTI
  names are referenced through their length byte. Exports such as `@System@@UStrCat` mean Delphi 2009
  or later, `@System@@LStrCat` alone means an older compiler.
- **Calls to other packages** go through a `jmp dword [import]` thunk. rizin names it
  `sub.<package>.bpl__<Unit>_<Func>`, so the thunk name is the callee.
- **Object fields** are offsets from Self (`[eax + 0x480]`). Ghidra may type Self as a pointer and
  scale the offset, so `(ushort *)p + 0x240` is byte offset `0x480`. Getter and setter exports
  (`GetFoo`/`SetFoo`) are a cheap way to map offsets to field names: decompile a few and read the
  offset each one touches.
- **Unit initialization** is in `@Unit@initialization$qqrv` and `@Unit@Finalization$qqrv`. Global
  registrations (class factories, lookup tables) often happen there.
- **try blocks** start with `xor eax, eax; push ebp; push <handler>; push dword fs:[eax];
  mov fs:[eax], esp` and end by restoring `fs:[0]`. The handler jumps to `@System@@HandleFinally`
  for try/finally and to `@System@@HandleAnyException` or `@System@@HandleOnException` for
  try/except. When a literal shows up only in the except block, usually in an error message that
  names the operation, the code you want is the protected block right before it. Script interpreters
  embedded in Delphi programs often dispatch built-in functions this way, so the function's name
  leads to its error handler and the implementation sits just above.
- **Floating point width.** `fld`/`fstp` with `tbyte` is `Extended` (10 bytes), `qword` is `Double`
  and `dword` is `Single`. A value that passes through a `Double` parameter or result is no longer
  equal to the same decimal literal held as `Extended`. Compare against a small range when a test
  checks a computed float.
- **Class references.** A `mov eax, [abs]` before a constructor, an `IsClass` or a factory call loads a
  class pointer from a cell. For an imported class the cell is the import slot. For a class defined in
  the package the cell is the `vmtSelfPtr` at VMT minus 0x4C, which holds the VMT's own address, and the
  class name is the ShortString just before the VMT. The class pointer is the VMT address.
  `IsClass(obj, cls)` takes the object in `eax` and the class in `edx` and answers in `al`.
- **Library objects that the package doesn't import methods for.** The fields of VCL classes sit at fixed
  offsets for a given compiler, so code you inject can read them directly. In the Delphi 7 era layout a
  `TTreeNode` has the text at +8 and `Data` at +0xC, and a `TStrings` descendant answers `IndexOf`, `Add`
  and `Delete` through virtual slots. Confirm each offset in code that already touches it (a handler that
  reads `[node+0xC]` before using `Data`) rather than trusting a table.
- **Exceptions with extra fields.** In an `on E: Exception do` handler the exception object is kept in a
  frame slot, saved right after the handler starts (`mov [ebp-0x30], eax`). A factory such as
  `CreateDet(cls, message, details)` stores the extra strings in fields after the standard ones. Code that
  logs only `E.Message` discards the rest, and `@System@@DoneExcept` frees the object, so read the field
  before that call. Find its offset in the factory, where the extra argument is stored with `LStrAsg`.
- **Objects created in a loop and kept only under a condition.** A loop that creates an object, hands it
  to a routine that fills it and adds it to a parent only when it ended up non-empty (`Length > 0`)
  leaks every empty one, because the path that skips the `Add` has no `Free`. In the disassembly look
  for a constructor call, then a size test, then a conditional jump over the call that stores the object
  with nothing that releases it on the other side. Confirm with memory growth per iteration (see below),
  and after the fix compare the program's output before and after.
- **Reference counting bugs.** Assigning a string goes through `@System@@LStrAsg` (or `UStrAsg`),
  which adds a reference. A plain `mov [obj + x], reg` of a string pointer does not. If the source
  is then released with `LStrClr` or `LStrArrayClr` before the field is used, the field points at
  freed memory and the result depends on whether that memory was reused. Interface variables are
  released with `@System@@IntfClear`. `TObject.Free` or `FreeAndNil` on one calls through the wrong
  table and usually crashes. An object created and then overwritten without a `Free` is a leak.

## Comparing two builds

Export names stay the same between builds of a package and addresses don't. Match exported
functions by name, and nested procedures through the literals they reference (`bpl-xref str` on
both files). Then compare only the instructions the question depends on. A function that was
rewritten may also have been renamed or split, so when an export disappears, look for the same
literals in the new file before concluding the code is gone.

To see everything that changed between two builds, run ghidriff as described in the `binary-diff`
skill. On a BPL it matches most functions by their export names. Filter the JSON by unit
(`test("@Unitname@")`) to find what changed in the area you care about. The exported RTTI
(`@$xp$...`) and VMTs (`@Unit@TClass@`) come out as functions that fail to decompile or decompile
to nonsense, and many of them land in `modified`. Skip names that start with `@$xp$`.

For a first pass over one unit, before running ghidriff, compare its exported functions instruction by
instruction. Take each export of the unit and the next export as the range, so the nested procedures
that sit before the next export are included. Disassemble both builds with `objdump`, mask what moves
between builds, and compare the lists. It takes seconds for a few hundred functions.

```python
import re, subprocess
def body(path, start, end):
    out = subprocess.run(['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
                          f'--start-address={start}', f'--stop-address={end}', path],
                         capture_output=True, text=True).stdout
    ins = [l.split('\t', 1)[1] for l in out.splitlines() if re.match(r'\s*[0-9a-f]+:\t', l)]
    ins = [re.sub(r'0x[0-9a-f]{5,}', 'ADDR', i) for i in ins]          # absolute addresses
    ins = [re.sub(r'([+-])0x[0-9a-f]+\]', r'\1OFF]', i) for i in ins]  # field offsets
    return [re.sub(r'^(call|j\w+)\s+[0-9a-f]+\b.*', r'\1 X', i) for i in ins]
```

- Check that the lists are not empty before trusting an "equal". `objdump` prints 8 digit addresses
  without leading spaces, and a pattern that required them matched nothing, so every function came
  out "equal" between two builds that had in fact changed.
- When a class gains fields, every method that touches the fields after the new ones changes its
  offsets, so almost the whole unit shows up as different with the same function sizes. Masking the
  displacements removes most of that. What is left at the same size is usually small constants that
  also moved with the layout. Read the diff of the functions the question depends on before calling
  the change a logic change, and use ghidriff when you need the full picture.

## Inspecting a running process

When the code reads the same in every build and the behaviour still differs, look at the objects in
memory. On Linux, including programs running under Wine, `/proc/PID/mem` can be read from Python
without attaching a debugger, and the process keeps running.

```python
mem = open(f'/proc/{pid}/mem', 'rb', 0)
for line in open(f'/proc/{pid}/maps'):
    lo, hi = (int(x, 16) for x in line.split()[0].split('-'))
    if 'r' not in line.split()[1] or lo >= 0x80000000:
        continue
    try:
        mem.seek(lo); data = mem.read(hi - lo)
    except OSError:
        continue      # guard pages and unreadable mappings
    ...
```

- Reading another process needs ptrace permission. With `kernel.yama.ptrace_scope = 1` (the usual
  default) only a parent can read its child, and the read fails with `Permission denied`. Set it to
  0 with `sudo sysctl kernel.yama.ptrace_scope=0` for the session and back to 1 when done.
- The first dword of every Delphi object is its class pointer, which is the address of the exported
  VMT symbol `@Unit@TClass@` (adjusted by the rebase delta if the package didn't load at its
  preferred base, which `/proc/PID/maps` shows). Scanning readable memory for aligned dwords equal
  to that address lists the instances. Expect false hits inside the VMT itself, in RTTI and in freed
  objects, so check a few fields before trusting one.
- To find which field holds a sub-object when you don't know the offset, scan the object for
  pointers whose target starts with the VMT of the class you expect. Then read the container. Get the
  layout from the getters (`TList.GetCount`, `TCollection.GetCount`) in the build you are looking
  at, since field offsets change between compiler versions.
- An AnsiString field points at the first character, with the length in the dword before it and the
  reference count before that.
- Comparing instances answers questions that the code alone doesn't. For example, when the same data
  exists in a runtime object and in an edit copy, counting the items each one holds shows which copy
  lost them.

- **Growth per unit of work.** To compare variants of a patched binary, sample the resident size and a
  counter that a hook increments once per unit, then divide the growth by the units over the same
  range for every variant. The cost of a unit depends on its content, so the cumulative average of runs
  of different lengths misleads. One variant looked like 0.77 MB per item that way and was 1.14 over the
  range the other runs shared. Disabling one callee at a time narrows a leak down quickly, but a variant
  that skips only the allocation's consumer may not change anything, because the leaked object is created
  before it.
- **Where the time goes.** Sampling `/proc/PID/task/TID/stat` (the state letter) and
  `/proc/PID/task/TID/syscall` shows whether the main thread is running or blocked, and in which system
  call. `perf record -e cpu-clock:u -g -p PID` counts CPU only, so a program that spends most of its time
  waiting looks almost idle, and the wall clock is the number that matters to the user. Under Wine the
  packages have no names in `/proc/PID/maps`. Build the module table by reading the first bytes of each
  candidate image at its preferred base from `/proc/PID/mem` and comparing the `TimeDateStamp` with the
  file's header, then name each sampled address with the nearest export from `rz-bin -E`. The
  `wine-debugging` skill has the rest.

Debuggers under Wine are fragile. `winedbg --gdb` on a 32-bit program in Wine's new WoW64 mode
reports the target as i386, but its break-in thread runs at a 64-bit address. gdb truncates that
address, reports a SIGSEGV, and detaching then can leave the program dead or frozen. The gdb proxy
also accepts a single connection, so a failed session can't be resumed. Prefer reading memory as
above, or a GUI debugger such as x32dbg running inside the same Wine prefix, and warn whoever is
using the program that it may close.

## Ghidra and ReVa

- **Use Ghidra 12.1.3 or newer.** Up to 12.1.2 the PE loader read the export ordinal table as signed
  16-bit values, so every name whose index is 32768 or above came out unnamed. A package with 63k
  exports lost almost half its names. Re-import files loaded by an older version, since upgrading the
  project keeps the wrong symbols.
- Import headless and let Ghidra pick the `borlanddelphi` compiler spec on its own. The script is
  `ghidra-analyzeHeadless` in the Arch package and `support/analyzeHeadless` in the release zip.

  ```sh
  ghidra-analyzeHeadless ~/ghidra-projects/app app -import app.bpl -loader PeLoader \
      -analysisTimeoutPerFile 7200
  ```

  A 30 MB BPL with 63k exports took about 5 minutes to import and 15 to analyze on 20 cores, and the
  project used 700 MB. Name matching in the PE loader grows with the square of the export count, so
  import time climbs fast with very large packages. Reopening an analyzed project with
  `-process app.bpl -noanalysis -readOnly` takes seconds.
- **ReVa in assistant mode** (Ghidra GUI open, ReVa Application Plugin enabled, MCP server on
  `http://localhost:8080/mcp/message`) works on the persistent, already analyzed project. That's the
  mode to use for large packages.

  ```sh
  claude mcp add --scope user --transport http ReVa -- http://localhost:8080/mcp/message
  ```

- **ReVa in headless/stdio mode** (`mcp-reva`) creates a temporary project for every session and has
  to import and analyze from scratch. With a large BPL the import passes its 120 s default timeout and
  ReVa falls back to another loader, which yields a 16-bit MZ program at `0x1000:0000`. If you see
  that address, the import is wrong. Fine for small DLLs, not for big packages.
- ReVa's `run-script` only works when Ghidra was started through PyGhidra (`pyghidra` in the Arch
  package, `support/pyghidraRun` in the release zip), not through the plain `ghidra` launcher.

## Other tools

- **pefile** stops at 8192 exports and calls the rest corrupt. Pass the limit to the constructor,
  `pefile.PE(path, max_symbol_exports=1 << 20)`. Changing `pefile.MAX_SYMBOL_EXPORT_COUNT` has no
  effect, because the constructor reads it only as a default. Its import list is also incomplete for
  large BPLs. It stops after 8192 symbols and silently drops names with characters such as `%`,
  which Delphi uses in `System@%SmallString$iuc$255%`. `bpl-xref` reads the import table itself.
- **IDR** (Interactive Delphi Reconstructor) recovers class and form data from EXEs, but it's
  GUI-only on Windows and supports up to Delphi XE4. For BPLs the exports already give the names it
  would recover. Dhrake needs IDR's output.
- `strings -a` and `strings -el` (UTF-16) are quick to check that a literal exists before running
  `bpl-xref str`.

Keep binaries, Ghidra projects and decompiled output out of git repositories.
