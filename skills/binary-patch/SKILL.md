---
name: binary-patch
description: Patch the machine code of a 32-bit Windows PE file (EXE, DLL or Delphi BPL) in place, without the source, and test the new code before it runs in the real program. Use when a bug or slow path has to be fixed in a vendor binary, when new code has to be added through a trampoline, or when a patch has to be described as byte patterns that a tool applies to many copies of the file.
---

# Patching PE binaries

A patch replaces bytes in the file. Nothing moves, so every patch point keeps its size, and any new
code goes into unused space inside an existing section. Find and understand the code first (the
`delphi-bpl` skill covers that for Delphi). This skill is about writing the change so it loads, runs
and can be applied again to another copy of the same build.

The tools are Python 3 with `pefile`, `keystone` to assemble new code, `rizin` or `objdump` to check
the result, and `unicorn` to run the new code in isolation. Arch packages them as `python-keystone`
and `python-unicorn`. Elsewhere use `pip install keystone-engine unicorn` in a venv.

## Addresses and file offsets

Work with virtual addresses, as the disassembler shows them, and convert to file offsets only when
reading or writing. A small helper avoids mistakes:

```python
import pefile

class Pe:
    def __init__(self, path):
        self.pe = pefile.PE(path, fast_load=True)
        self.data = bytearray(self.pe.__data__)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase

    def off(self, va):
        return self.pe.get_offset_from_rva(va - self.base)

    def read(self, va, n):
        o = self.off(va)
        return bytes(self.data[o:o + n])

    def write(self, va, b):
        o = self.off(va)
        self.data[o:o + len(b)] = b

    def save(self, path):
        open(path, 'wb').write(self.data)
```

Check `DllCharacteristics & 0x40` (dynamic base). Even without it, a DLL is rebased when its
preferred range is taken, so treat every absolute address as something the loader may change.

## Patch points

- Replace an instruction sequence with one of the same total length. Pad with `nop` (`0x90`), or end
  with a short `jmp` over the leftover bytes when they are many.
- A `call` or `jmp rel32` to new code takes 5 bytes. When the original call is 5 bytes too, only the
  displacement changes.
- Never overwrite a dword listed in `.reloc` with something else. The loader adds the rebase delta
  to it and corrupts your code. List the relocations that fall inside the bytes you change
  (`pe.parse_data_directories(directories=[5])`, then `DIRECTORY_ENTRY_BASERELOC`). When an
  instruction you need to remove contains a relocated address, keep those 4 bytes as they are and
  jump over them.
- Keep the patch inside one function and check every branch that lands inside the replaced range.
  A jump into the middle of your new bytes executes garbage.
- Some fixes need no new code. Turning `lea eax, [ebp-x]` into `mov eax, [ebp-x]` (passing the value
  instead of the address of a local) is a one-byte change.
- Removing a call needs no cave. When a call only does harm, such as a cleanup that runs on a path
  where its argument is already nil, replace the instructions that set it up and make it with `nop`s of
  the same total length. An `xor edx, edx` plus `call rel32` is 7 bytes, so 7 `nop`s. Before doing it,
  search for the readers of whatever the removed call writes. A call that fills or clears a field can
  look like the cause of a crash while another routine depends on that field being filled, and removing
  the writer leaves it empty.

## New code in a cave

- **Where.** Look for a run of zeros at the end of the code section that is still inside
  `Misc_VirtualSize`. Bytes past `VirtualSize` exist in the file but you can't count on them being
  mapped as code. Zero runs in the middle of the code are usually padding or data tables. Use one
  only after checking that no `rel32` call or jump targets it and no relocated pointer points into
  it.
- **Relative only.** New code may use `call rel32`, `jmp rel32` and short jumps to anything in the
  same file. An absolute address (`mov eax, 0x...`, `push 0x...`, `call [0x...]`) would need a new
  `.reloc` entry, and adding one means rebuilding the relocation directory. Avoid it.
- **Imports.** Call the existing import thunk (`jmp dword [IAT slot]`) with a relative call. Find it
  among the thunks the disassembler names, and confirm by finding an existing call to it.
- **State.** For a few bytes of data that must survive between calls, use the slack at the end of
  the last page of a writable section (between its `VirtualSize` and the next page boundary). The
  loader maps the whole page, zero filled and writable. Reach it without a relocation:

  ```asm
  call next          ; pushes the address of next
  next:
  pop edi            ; edi = address of next
  add edi, DATA - next
  ```

  The state starts at zero in every process, so the code must treat zero as "nothing stored yet".
- **Conventions.** A trampoline that replaces a call must behave like the callee. Read the arguments
  from the same registers, return in the same register, keep `ebx`, `esi`, `edi` and `ebp`, and leave
  the stack balanced. In Delphi's register convention the first three arguments are `eax`, `edx`,
  `ecx`. A Delphi method's Self is `eax`.
- **Virtual methods.** A call to an exported or imported method runs that exact class's version, whatever
  the object really is. If a descendant overrides it, the program may crash far from your code. One injected call to
  a base class `SetBounds` on a windowed control sent a message with a null parameter, and the access violation
  showed up inside the message handler. Look the method up in the VMT of the object's class, and when the slots
  differ between base and descendant, call through the object (`mov ecx, [eax]`, then `call [ecx + slot]`).
- **Registers across calls.** A callee may change `eax`, `ecx` and `edx`. Keep a value that must survive a
  call on the stack or in a preserved register, and compute it after the calls that would destroy it.
- **Replacing the start of a function.** Overwrite the prologue (`push ebp`, `mov ebp, esp`,
  `add esp, N`, usually 6 bytes) with a `jmp` and `nop`s. The cave replays those same instructions,
  does its work and jumps back to the first instruction after the replaced bytes. At that point
  `eax`, `edx` and `ecx` still hold the arguments, so save what the cave clobbers and restore it before
  the jump back. Replace whole instructions only, and check that no branch targets the middle of the
  replaced range.
- **Constants that the loader relocates.** A class pointer, a table address or an import slot that the
  code loads with `mov eax, [abs]` is relocated by the loader, so the cave can't hold its own copy of
  the address. Read the operand of the existing instruction instead. The operand sits inside the
  code, already relocated, and the cave reaches it with the same `call`/`pop` trick:

  ```asm
  call next
  next:
  pop ebx                        ; ebx = address of next
  mov eax, [ebx + (OPERAND - next)]   ; the relocated dword, OPERAND = address of the imm32
  mov eax, [eax]                 ; the value the original instruction would have loaded
  ```

  Keep `ebx` as the base, since a call to another function clobbers `ecx` and `edx`. Push and pop `ebx`
  around the cave when the host expects it preserved.
- **Several patches in one cave.** Give each patch its own fixed part of the cave, for example one
  growing from the start and another placed just before the end of the section, so they can be
  applied in any order and each can be removed alone.
- **A hook for one caller only.** When a routine has several callers and the change must apply to one of
  them, compare the return address with the caller's range instead of setting a flag around the call. Inside the
  callee's frame the return address is `[ebp+4]`. A flag set before the call and cleared after stays set when an
  exception skips the clearing, and the next unrelated call takes the wrong path. The range check keeps no state:

  ```asm
  push ebx
  call next
  next:
  pop ebx
  mov ecx, [ebp+4]               ; return address of the routine whose frame this is
  sub ecx, ebx
  sub ecx, CALLER - next         ; ecx = offset of the return address inside the caller
  cmp ecx, CALLER_SIZE
  jb from_that_caller
  ```

  `CALLER_SIZE` is the distance to the next function, and it changes between builds.
- **Calling your own DLL.** Logic too long for assembly, such as parsing a file format, can live in a DLL the
  cave loads by name. Call the `LoadLibraryA` and `GetProcAddress` thunks the module already imports, and keep
  the DLL name and the function name as zero terminated strings at the end of the cave, reached with
  `call`/`pop`. Store the function pointer in the state slack, with zero meaning "not loaded yet" and 1
  meaning "failed, don't try again", so a missing DLL costs one failed load per process. Export the functions
  with the C convention (`cdecl`, the caller removes the arguments), which a 32-bit Rust or C DLL produces
  without decoration. Give each function a way to say "don't know" (a negative result) and send the cave back
  to the original code in that case, and also when the DLL or the function is missing. A function's name and
  arguments never change after it ships. A new contract is a new function, so an old DLL next to new code, or
  the other way around, falls back instead of misbehaving.
  - A Delphi `AnsiString` parameter needs a real string with its header, not a bare `char *`, because the
    callee may add a reference. Build one with `System.@LStrFromPChar(var Dest, Source)` into a zeroed local,
    and release the locals with `@LStrClr` or `@LStrArrayClr` (address of the first, count) before leaving.
    Locals for `@LStrArrayClr` must be contiguous and in increasing address order.
  - Paths the program passes are in the ANSI code page. Convert them with `MultiByteToWideChar(CP_ACP)` in the
    DLL instead of assuming UTF-8.
- **Exception handling in a cave.** When the cave calls host code that may raise, such as an export routine
  that fails for an object that doesn't exist yet, protect the call the way Delphi compiles `try ... except`.
  The handler address goes through `call`/`pop`, so it needs no relocation:

  ```asm
  xor eax, eax
  push ebp
  lea ecx, [ebx + (handler - next)]
  push ecx
  push dword fs:[eax]
  mov fs:[eax], esp
  ; ... calls that may raise ...
  xor eax, eax
  pop edx
  pop ecx
  pop ecx
  mov fs:[eax], edx
  jmp after
  handler:
  jmp System.@HandleAnyException   ; the except block starts right after this jmp
  mov dword [ebp - FAILED], 1
  call System.@DoneExcept
  after:
  ```

  The cave needs its own `ebp` frame, because the handler restores `ebp` from the registration. `esp` is back
  to its value before the `try` on both paths, but `ebx`, `esi` and `edi` are not. Keep what you need in frame
  locals and recompute the `call`/`pop` base after `after:`. Whatever the cave changed on the host object before
  the call (a path, a flag) has to be restored on both paths.

## Assembling with keystone

Hand-encoded bytes are fine for a 5-byte `jmp`. For anything with branches, write assembly and let
keystone encode it at the address it will live at, so `call` and `jmp` to absolute targets come out
as the right `rel32`:

```python
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

ks = Ks(KS_ARCH_X86, KS_MODE_32)

def assemble(src, addr):
    code, _ = ks.asm(src, addr)
    return bytes(code)

code = assemble(f"""
    push ebx
    mov ebx, eax
    test eax, eax
    je skip
    call {TARGET:#x}          # rel32 computed from CAVE
skip:
    pop ebx
    jmp {BACK:#x}
""", CAVE)
```

- Assemble at the final address. The same source assembled at another address gives different
  `rel32` values.
- Comments start with `#`. A `;` separates instructions, so `push ebx ; save` fails with
  `KS_ERR_ASM_MNEMONICFAIL` on `save`.
- A memory operand without a register of known size needs `dword ptr`, `word ptr` or `byte ptr`.
  `cmp [eax], 0` is rejected with `KS_ERR_ASM_INVALIDOPERAND`.
- A label inside an expression becomes a memory operand. `add edi, DATA - next` assembles as
  `add edi, dword ptr [...]`, an absolute address that the loader will not relocate. Compute
  displacements in Python and write them as numbers (`add edi, {DATA - NEXT:#x}`), with `NEXT`
  taken from the length of the code before it.
- Disassemble the result with capstone or `rizin` and check that every absolute address in it is
  one you meant.

## Testing the new code with unicorn

Run the trampoline before the real program does. Map the page with the cave and the data page,
replace every external call with a hook that returns a value you choose, and call the trampoline
with known registers:

```python
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import *
import struct

mu = Uc(UC_ARCH_X86, UC_MODE_32)
mu.mem_map(CAVE & ~0xfff, 0x1000)
mu.mem_write(CAVE & ~0xfff, pe.read(CAVE & ~0xfff, 0x1000))
mu.mem_map(DATA & ~0xfff, 0x1000)
mu.mem_map(STACK - 0x1000, 0x2000)
mu.mem_map(RET & ~0xfff, 0x1000)

def fake(uc, addr, size, _):
    uc.reg_write(UC_X86_REG_EAX, results[addr].pop(0))   # value the real callee would return
    uc.reg_write(UC_X86_REG_ECX, 0xBAD0BAD0)             # a real callee may change these two
    uc.reg_write(UC_X86_REG_EDX, 0xBAD1BAD1)
    esp = uc.reg_read(UC_X86_REG_ESP)                    # return to the caller
    uc.reg_write(UC_X86_REG_EIP, struct.unpack('<I', uc.mem_read(esp, 4))[0])
    uc.reg_write(UC_X86_REG_ESP, esp + 4)

for page in {t & ~0xfff for t in results}:
    mu.mem_map(page, 0x1000)
for target in results:
    mu.hook_add(UC_HOOK_CODE, fake, None, target, target + 1)

mu.reg_write(UC_X86_REG_EBX, 0x11111111)   # and esi, edi, ebp
mu.mem_write(STACK - 4, struct.pack('<I', RET))
mu.reg_write(UC_X86_REG_ESP, STACK - 4)
mu.emu_start(CAVE, RET, count=500)
assert mu.reg_read(UC_X86_REG_ESP) == STACK
assert mu.reg_read(UC_X86_REG_EBX) == 0x11111111
```

- Loops need a high `count` in `emu_start`. A 400 iteration copy loop stops short with the default
  of a few thousand instructions, and the test then fails on the stack check for the wrong reason.
- When the cave replays a prologue, the stack after it differs from the entry by the size of the pushes
  and of `add esp, N`, and `ebp` has changed. Assert those exact values instead of the entry values.
- To catch leaks, give the hooked allocator and string routines a model with reference counts and
  assert at the end that only the objects the code meant to keep are alive.
- Assert that `ebx`, `esi`, `edi` and `ebp` come back unchanged on every exit, including the early exits.
- A fake callee that leaves `ecx` and `edx` alone hides a whole class of bug. A value kept in `edx` across a call
  passes the test and reaches the real callee as garbage. The same goes for a fake that stands in for a virtual
  method: map a small fake VMT with the real slot offsets, so a direct call to the wrong version fails the test.
- Code with `fs:[eax]` exception frames needs a segment. Some unicorn builds reject writes to
  `UC_X86_REG_FS_BASE` with `UC_ERR_ARG`, and a hand-built GDT can break the stack as well. It is simpler to hook
  each `fs:` instruction and emulate it against a mapped page (`push fs:[eax]`, `mov fs:[eax], esp`,
  `mov fs:[eax], edx`), then advance `eip` past it.
- To test the path where a callee raises, have its fake read the top frame from that page, unlink it, set `esp` to
  the frame and `ebp` from its saved slot, and jump to its handler. Assert that the cleanup runs exactly once and
  the frame chain is back where it started.
- Reproduce the reported failure before testing the fix. Run the unpatched code in the same harness and
  check that it faults at the instruction the crash log names, or at the same offset when the module
  loads elsewhere. A harness that reproduces the real crash is a model of the program, and one that only
  passes the patched code proves much less. Then run the same sequence on the patched bytes, in the
  order the program uses, such as several messages in a row against the same object. A bug that depends
  on state left by the previous call does not show up in a single call.

Cover every case the code branches on, such as the empty state, each side of every comparison, the
exact boundary values and counter wraparound. Hooks only need to map the page of the target, since
execution never reaches the original code. A hand-written x86 emulator for the same test is a waste
of time and misses flags and encodings that unicorn gets right.

## Byte patterns

When a tool applies the patch to other copies of the file, describe each point as an "original"
pattern and a "patched" pattern of the same length, with wildcards for bytes that differ between
copies, and require that each matches exactly once. That gives three states for free (original,
patched, or unknown, which means another build or a half applied patch).

- Include enough context around the change for the pattern to be unique. A `call rel32` alone
  matches in many places.
- A cave is all zeros, which match everywhere. Extend its pattern up to the first non-zero bytes
  after it (often the start of the next section) and check that this anchor is unique.
- Windows of a few bytes are unique in the file you have and may not be in another build, where the
  patch would write a jump to a wrong address. Ask for at least 24 to 28 literal bytes.
- Wildcard every relocated dword in the window. The relocation table lists them (`pefile`,
  directory 5, type 3).
- When several independent patches share a file, no window may contain bytes that another patch
  writes, or the "patched" pattern of one stops matching once the other is applied. Compute the write
  ranges of all the other patches and make those bytes wildcards in every window.
- Independent patches that all need a cave can share the large zero run at the end of the code
  section if each takes its own part of it. One patch anchors at the start of the run, another at the
  end, and a third can sit in the middle. Its pattern is the last bytes of the code before the run, then
  as many wildcards as it takes to reach its part, then zeros. The anchor makes it unique and the
  wildcards make it blind to what the other patches did. State what each patch uses and assert in a
  test that the ranges don't overlap.
- A pattern that starts with thousands of zeros makes a naive search compare almost the whole
  pattern at every zero of a run of megabytes, which is quadratic. Search for the literal window with
  the most non-zero bytes (16 bytes is enough), then compare the full pattern only where it matches.
  On a 14 MB file that took a real test from 572 seconds to 31.
- The same rule holds for points of a single patch. Two windows close together, such as two neighbouring
  strings, can each hold bytes the other one writes, so the second stops matching after the first is written. Make
  those bytes wildcards as well.
- A patch captured by comparing the original and the patched file ends each region at the last byte that differs.
  A string at the end of the new code loses its terminating zero, because the zero was already there. The patch
  still works where the following bytes are zero and breaks when another patch writes right after it. Add the
  zero back to the captured bytes.
- Test that patches sharing a file apply in both orders, on synthetic data and on the real file. Checking that each
  original pattern matches once isn't enough. Apply everything, then check that every patched pattern matches once
  and no original pattern still does. Synthetic data, with each window laid out apart, can't show overlaps.

## Moving a patch to another build

A new build of the same program moves functions, data and the zero run, and often changes classes. A pattern that
still matches in the new file proves only that the bytes around the patch points are the same. It doesn't prove
the patch works there.

- **Every `rel32` the patch writes depends on the distance between the point and its target.** A pattern without
  addresses can match in the new build while the `jmp` it writes lands in the middle of another function. In one
  case that crashed the program at startup with an access violation inside `TObject.Free`. Give each build its
  own variant of the patched bytes, with enough literal context (a nearby `call rel32` to an import thunk is
  usually different) for the variants not to match each other's files. Add a test that runs on the real files of
  every build and checks each point that replaces an instruction with a `jmp rel32` followed only by `nop`s. Its
  target must fall inside the bytes the same patch writes. Leave out points whose original byte was already a `jmp` or
  `call`, which only change a target, and patches without new code, whose jumps skip original code on purpose.
- **Run the program after applying.** Start it with `WINEDEBUG=err+all,+seh` under Wine (or a debugger on
  Windows) and check that no access violation shows up in the patched module, before anyone uses it.
- **Translating addresses.** Map each address the patch uses to the new build, then read the result with names.
  - Exported functions and VMTs by name.
  - Other code by context. Take the instructions around the address in the old build, mask every dword that
    the relocation table lists or that falls inside the image, and search the new code section for a single
    match. Widen the window until it is unique, and when the address is the start of a function, take context
    from before it.
  - `call`/`pop` displacements in the cave encode the distance to the target, so recompute them, including the
    ones in `add reg, imm32` and `sub reg, imm32` forms.
  - Imports by name. `pefile` leaves some import slots without a name, so find the slot by its neighbours in the
    same import table, which keep their order between builds.
  - The slack after a writable section moves when the section grows. Recompute its address from the new
    `VirtualSize` and check that it stays inside the same page.
  - Code that the normal flow never reaches still needs translating. An exception handler is entered through an
    address the code pushes, so a scan that follows calls and jumps from the entry points skips it and leaves its
    `jmp` to the runtime pointing at the old address.
  - Compare the translated targets by name on both sides (export and offset), and read every difference.
    A different offset inside a large exported region is often the region growing, not a wrong target.
- **Classes and frames change.** Before reusing a field offset, find how the new build accesses it. Align the
  instruction lists of a function that uses the field in both builds and check that every use of the old offset
  maps to the same new offset. When a new field shifts the rest by 8, the mapping is consistent across all uses.
  Do the same for the locals (`[ebp - n]`) of a host function whose frame the cave reads.
- **The host code may have changed around the point.** A function rewritten in the new build can lose the
  instruction the patch hooked, or gain a second path to it, such as a branch for encrypted content next to the
  plain one. Read the new function before reusing the point, and hook a place that every path you care about
  passes through, or only the path where the patch makes sense.

## When the program dies after patching

A cave that passes the emulator can still take the program down, and a program that exits without a
message gives nothing to read. Capture what happened before guessing.

- On Linux, `strace -f -qq -o trace.txt -e trace=exit_group,kill,tgkill -e signal=SIGSEGV,SIGKILL,SIGABRT
  program` records how every process ended. `exit_group(0)` with no signal is a normal exit. A line
  `+++ killed by SIGSEGV (core dumped) +++` is a native crash, and the `SIGSEGV` lines before it carry
  `si_addr`. Under Wine, `WINEDEBUG=err+all,+seh` logs every exception the program raises and
  handles, and `+process` logs the life cycle. Both write to stderr, so redirect it to a file.
- Bisect by changing one thing at a time while the code path stays the same. A variant that does the
  same calls but uses a constant instead of the real data tells you whether the logic or the data is
  at fault.
- Text that the cave builds and hands to the host's interface can crash the host's text rendering when
  it holds control characters, such as a line break in a place that expects one line, or a very long
  string. Replace control characters before handing the text over and cap its length.
- Keep the exact file that crashed and its hash, and put back the last file that worked before
  anyone uses the program again.

## Applying

- Read the original bytes at every point and stop if any differ from what you expect. Write to a
  new file, never over the only copy.
- Keep a backup next to the original and note both SHA-256 hashes.
- A running process keeps the image it loaded. On Windows the file is usually locked. Under Wine or
  Linux the copy on disk can be replaced, and the change takes effect on the next start. Check which
  processes have the file mapped before replacing it.
- Look for an updater or launcher that copies files from a server at startup. It will undo the patch
  silently.
- A signed executable loses its signature when any byte changes. A nonzero size in
  `DATA_DIRECTORY[4]` of the optional header means the file carries an Authenticode block. Policies that
  check signatures, such as application allow lists, can refuse the patched file, and so can an updater
  or service manager that verifies hashes. Keep the signed original and its hash next to the patched
  copy.
