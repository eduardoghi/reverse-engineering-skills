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

## Reference files

Read only the file that matches the problem. Each one is self-contained.

- **A crash log names a module and an address.** See
  [references/crash-logs.md](references/crash-logs.md).
- **The code runs, but data leaks, is lost or never changes.** See
  [references/bug-patterns.md](references/bug-patterns.md).
- **What changed between two builds.** See
  [references/comparing-builds.md](references/comparing-builds.md).
- **The program has to be inspected while it runs** (objects in memory, growth, time). See
  [references/running-process.md](references/running-process.md).
- **A file written by `TWriter` or read by `TReader`.** See
  [references/stream-formats.md](references/stream-formats.md).

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

   A fragment works too. It is reported as `'Customer' in 'CustomerName' at 0x...`, with the references
   of the literal that holds it. For each match it prints the literal kind guessed from the bytes before it (AnsiString,
   UnicodeString, ShortString), every relocated pointer to it in code, the nearest
   `push ebp; mov ebp, esp` before each reference and the exports around it. Nested procedures are
   not exported and sit right before their parent, so when the reference is between two exports the
   "next" one is often the owner.

   A `ptr` line instead of `ref` means the pointer sits in a data section, usually a table (package
   names, resource strings, initialized records). The code reads the table slot, not the string, so
   run `bpl-xref calls` on the `ptr` address to reach it.

   Messages declared as `resourcestring` live in the string table resource as UTF-16 without a
   terminator, and code never points at the text. It loads a record of a module handle pointer and
   the string ID (`mov eax, offset rec; call LoadResString`). `str` also searches the string table,
   matching any string that contains the text, and prints `(resourcestring ID)`, the record with
   its exported name when there is one (`@Uorders@SInvalidOrder`) and the code that
   references the record. A record without references in a package is usually loaded by other
   packages through that export.

   An EXE usually has no exports, so there are no "prev"/"next" lines. Start from the entry point
   (`rz-bin -e app.exe`), from the import thunks, which `flags` names, and from the event handlers
   that `dfm --events` finds through the VMTs (step 3).

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
   Events inside collection items show up as `Edit1.Buttons[0].OnClick`. Without an export, as in
   an EXE or for a handler an ancestor form declares, it looks the name up in the published method
   tables of the form's class and its ancestors and prints `0x... TFOrderEdit.BtnSaveClick
   (published)`. When the ancestry continues in another package it names the imported ancestor
   instead, and the method is in that package's exports. A handler marked `?` was found neither way,
   and every exported method with that name is listed as a candidate. A form whose class has no VMT
   in the file is usually one the linker kept after dropping its class, so no code runs it.

   `bpl-xref vmt` reads the same VMTs without exports, in the layout of Delphi 2 to 2007 or of Delphi
   2009 and later, which it picks from the file. Without a class it lists every class with its parent. With one it prints the published methods and the published
   fields with their offsets, so `mov eax, [ebx+0x3a0]` in a form method is `edtCustomer: TEdit`:

   ```sh
   bpl-xref vmt app.exe | grep -i order          # classes, parents, size of the published tables
   bpl-xref vmt app.exe TFOrderEdit              # methods, then +offset name: type for each field
   ```

   Only components with a field declared in the class show up. Pages of a `TNotebook` and
   components of an ancestor form from another package don't.

4. **Find who calls a function**, especially a nested procedure, which has no export and no name:

   ```sh
   bpl-xref calls app.bpl 0x0045a1c0 '@Uorders@TOrder@Post$qqrv'
   ```

   It takes hex addresses or exact export names and lists `call`/`jmp rel32` instructions plus
   relocated pointers (VMT slots, event handler tables). The rel32 hits come from a byte scan, not
   from disassembly, so treat them as candidates and check each one with `pd 1 @ addr`. Virtual and
   interface calls go through `call dword [reg + offset]` and don't show up. For those, find the VMT
   slot that points at the method (a `ptr` hit) and search for its offset.

   A call on an interface pointer (`mov ebx, [eax]; call dword [ebx + 0x74]`) doesn't use the class
   VMT. Its slot holds a stub that adjusts `Self` and jumps to the method (`add eax, -0x1c; jmp
   Method`, or `add dword [esp+4], -0x18; jmp Method` for a stdcall method), and the tables of all
   the interfaces of a class sit one after another. To name the method behind an offset, take a
   method you know the interface has, find its stub (the `jmp` that `bpl-xref calls` lists for the
   method), then the pointer to the stub (a `ptr` hit), and walk back to the start of that table.
   The table starts with the stubs of `QueryInterface`, `AddRef` and `Release`, three in a row with
   one adjustment, and the offset in the call counts from the first of them. Walking back over
   everything that looks like a code pointer goes past it into the table of the previous interface
   and shifts every slot. One table read that way came out four entries off.

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
   cut at 48 characters, and a literal of one or two characters gets a name that doesn't show the
   character (`str.` for a space, `str..` for a dot, `str.__1` for an asterisk). When the reading
   depends on which separator a `Pos` or a concatenation uses, print the bytes at the address
   instead of trusting the name. Print the full text of a literal with `ps ascii @ addr` (AnsiString),
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

## Which file actually runs

An EXE can contain the units of a package that it never imports. The package is then a copy built from
the same source and loaded by something else, so analyzing or patching it changes nothing for the EXE.
Check this before reading any code.

- `rz-bin -l app.exe` lists the packages the EXE imports. A package missing from that list is not
  loaded by it.
- `bpl-xref vmt app.exe | grep -i ClassName` shows whether the classes you care about are inside the
  EXE. They then have their own VMT address in the EXE's range.
- The module named in a crash log or a profiler is the file that ran. An exception address inside
  `app.exe` for a class that you found in `lib.bpl` means the EXE has its own copy.
- On Linux or Wine, `/proc/PID/maps` lists the images that the process loaded. On Windows,
  `EnumProcessModulesEx` does (see [references/running-process.md](references/running-process.md)).

When both files hold the class, they share the logic, so a reading of one carries over to the other.
The copies are separate builds, so addresses and thunk targets differ and small details can too.
Find the same function in the file that runs and confirm the instructions there before patching.

**Naming functions in an EXE that embeds the units.** Such an EXE exports nothing, but its functions
have the same bytes as the package exports apart from addresses. Mask the 4 bytes of every relocation
and the operand of every `call`/`jmp rel32` on both sides, take the call targets and relocated code
pointers of the EXE as function starts, and compare the first bytes of each package export against
them. Overloads often share their first bytes. A unit keeps its layout, so place an ambiguous function
at the same distance from a uniquely matched neighbour and check the bytes there. Code that matches no
package belongs to units only the EXE has, and that is where its own behaviour lives.

## Reading Delphi code

- **Mangled names.** `@Unit@TClass@Method$qqr<params>`. `$qqr` is the register convention, `$qqs`
  stdcall (COM methods). `$bctr` is a constructor, `$bdtr` a destructor. `@$xp$...` is RTTI and
  `@Unit@TClass@` (ending in `@`) is the class VMT, both data even when they sit in the code section.
  The return type is not encoded.
- **Parameter codes.** `x` const, `r` var (by reference), `p` pointer, `v` no parameters, `i` Integer,
  `o` Boolean, `us` Word, `uc` Byte, `d` Double, `g` Extended, and a length-prefixed type name such as
  `17System@AnsiString`. `$qqrx17System@AnsiStringd` is `(const s: AnsiString; d: Double)`. An open
  array parameter travels as two arguments, the pointer and the highest index.
  `px17System@AnsiStringxi` is `const a: array of AnsiString`, and `-1` as the index means an empty
  array. An open array built for a call shows up as `lea eax, [ebp - X]; push eax; push N`, and its
  elements are locals written just before. In a function without an `ebp` frame the locals are
  addressed through `esp`, which moves with every push, so add the bytes pushed between the write and
  the `lea` before matching them.
- **Register convention.** Self goes in `eax` for methods. The first three integer, pointer or string
  parameters go in `eax`, `edx`, `ecx`, and the rest are pushed left to right. `Double` and
  `Extended` always go on the stack, so the decompiler numbers them in reverse (`param_7` is the
  first one). Ordinal results come back in `eax`, floats in `ST(0)`, and strings and records through
  a hidden last `var` parameter. The callee removes its own stack parameters, so a call that builds
  an argument can sit between the pushes of the outer call, with pushes of its own that it removes.
  When you read pushed arguments, count them per call and account for `pop` into registers, or
  recognize the argument by its content.
- **Strings.** An AnsiString literal has a `-1` reference count and a 32-bit length right before the
  first character, and code points at that character. A UnicodeString literal (Delphi 2009 and later)
  is UTF-16 with the same layout plus a code page and element size. ShortString constants and RTTI
  names are referenced through their length byte. Exports such as `@System@@UStrCat` mean Delphi 2009
  or later, `@System@@LStrCat` alone means an older compiler.
- **Calls to other packages** go through a `jmp dword [import]` thunk. rizin names it
  `sub.<package>.bpl__<Unit>_<Func>`, so the thunk name is the callee.
- **`case` statements** compile to `jmp dword [eax*4 + table]` with the table of addresses inline
  after the jump. Linear disassembly reads the table as instructions and loses sync, so read the
  dwords at the table address and disassemble from each target. The jump is preceded by
  `cmp eax, N; ja <default>`, so values above the table go to the default branch. They are not unknown
  cases.
- **A value chosen in a `case` and passed on.** Code often assigns a literal to a local in each branch
  (`LStrLAsg` into `[ebp - X]`) and passes the local afterwards. Collect every literal assigned to that
  local in the function. When two locals are filled per branch, pair each value with the one assigned
  just before it in the same branch.
- **Global variables.** An imported variable is read as `mov eax, [slot]; mov eax, [eax]`, and the
  import name of the slot says which one it is. An argument read from `Sysutils.EmptyStr` is an empty
  string, not a value you need to trace. An initialized typed constant is read as `mov edx, [address]`
  with a data address that holds a pointer to the literal, so it can be read statically.
- **Nested procedures** get the parent's frame pointer as a hidden parameter and read the parent's
  locals through it, so a negative offset from a pointer loaded from `[ebp+8]` is a local of the
  enclosing function.
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
- **Handlers outside the function in Ghidra.** Ghidra doesn't follow the handler address that the
  `try` prologue pushes. The function body comes out as two ranges with the handler in the gap
  between them, the handler belongs to no function and its code isn't disassembled, so the
  decompiled code shows it only as `&LAB_<handler>` stored in a stack slot. An error message used
  only in the except block is missing from the decompiled code and Ghidra lists no references to
  it, while `bpl-xref str` still finds the reference. Disassemble from the `LAB_` address to read
  the handler. For `on E: EClass do` the handler is `jmp @System@@HandleOnException` followed by a
  count and pairs of class cell and branch address, so each branch starts at the address in its
  pair, not after the jump. Checked with Ghidra 12.1.4 on packages.
- **Floating point width.** `fld`/`fstp` with `tbyte` is `Extended` (10 bytes), `qword` is `Double`
  and `dword` is `Single`. A value that passes through a `Double` parameter or result is no longer
  equal to the same decimal literal held as `Extended`. Compare against a small range when a test
  checks a computed float.
- **Class references.** A `mov eax, [abs]` before a constructor, an `IsClass` or a factory call loads a
  class pointer from a cell. For an imported class the cell is the import slot. For a class defined in
  the package the cell is the `vmtSelfPtr` at VMT minus 0x4C (0x58 from Delphi 2009 on), which holds
  the VMT's own address, and the class name is the ShortString just before the VMT. The class pointer is the VMT address.
  `IsClass(obj, cls)` takes the object in `eax` and the class in `edx` and answers in `al`.
- **Which method a virtual call reaches.** `call dword [ecx + 0x34]` after `mov ecx, [eax]` calls slot 0x34 of
  the object's VMT. To list what that slot runs in each class, search the file for the address of each candidate
  method as a dword. The match is the VMT slot, and its offset is the match address minus the class VMT export
  (`@Unit@TClass@`). Methods that are only reached through a slot show no `call` references, so this is also how
  to find who runs them. The other way works too. To name the method behind a slot, read the dword at the class
  VMT export plus the slot offset and look the address up in the exports. When the class comes from another
  package, do this in that package, where its VMT and methods are exported.
- **`TTreeNode.MoveTo` expands the new parent.** After the move it calls `SetChildren(True)` and
  `SetExpanded(True)` on the destination, which fires the tree's `OnExpanding`. In a program that asks for a
  password or loads data on expansion, that runs for every node moved. Switch the event off during the moves
  and collapse again the nodes that were closed before.
- **Code that finds nodes by position.** Before removing or moving nodes of a `TTreeView`, read how the
  program finds them. Getters like `GetFirstNode` followed by `getNextSibling`, and event handlers that
  compare the selected node with them, break or dereference nil when a group node disappears.

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
  which Delphi uses in `System@%SmallString$iuc$255%`. The 8192-symbol cut drops whole DLL
  descriptors, not just names. A script that walks `pe.DIRECTORY_ENTRY_IMPORT` and reads each thunk
  table by hand still misses every DLL after the cut. Walk the descriptors from the import data
  directory instead, as `bpl-xref` does.
- **IDR** (Interactive Delphi Reconstructor) recovers class and form data from EXEs, but it's
  GUI-only on Windows and supports up to Delphi XE4. For BPLs the exports already give the names it
  would recover. Dhrake needs IDR's output.
- `strings -a` and `strings -el` (UTF-16) are quick to check that a literal exists before running
  `bpl-xref str`.

Keep binaries, Ghidra projects and decompiled output out of git repositories.
