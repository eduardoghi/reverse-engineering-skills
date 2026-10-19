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
- **Several patches in one cave.** Give each patch its own fixed part of the cave, for example one
  growing from the start and another placed just before the end of the section, so they can be
  applied in any order and each can be removed alone.

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
- Test that patches sharing a file apply in both orders, on synthetic data and on the real file.

## Applying

- Read the original bytes at every point and stop if any differ from what you expect. Write to a
  new file, never over the only copy.
- Keep a backup next to the original and note both SHA-256 hashes.
- A running process keeps the image it loaded. On Windows the file is usually locked. Under Wine or
  Linux the copy on disk can be replaced, and the change takes effect on the next start. Check which
  processes have the file mapped before replacing it.
- Look for an updater or launcher that copies files from a server at startup. It will undo the patch
  silently.
