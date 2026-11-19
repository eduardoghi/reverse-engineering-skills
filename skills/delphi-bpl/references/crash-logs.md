# From a crash log line to a function

Read this when a log or a dialog gives a module and an address and you need the function behind it.


A log often prints a module and an address, such as
`Access violation at address 4A2F10C8 in module 'lib.bpl'. Read of address 00000000`. To land on the code:

1. Get the module's preferred base with `rz-bin -I lib.bpl | grep baddr`. When the process loaded it at
   that base, the logged address is the file's virtual address. A module that loaded elsewhere needs the
   rebase delta, which `/proc/PID/maps` or a debugger gives.
2. Sort the exports (`rz-bin -E lib.bpl`) and take the last one at or before the logged address. The
   offset into the function is the difference. Nested procedures have no export and sit before their
   parent, so the owner can be the next export.
3. Disassemble a window around the address with
   `objdump -d -M intel --start-address=... --stop-address=... lib.bpl`. In an EXE without exports,
   walk back from the address to the nearest `push ebp; mov ebp, esp` for the start of the function and
   run `bpl-xref calls` on it to find the callers.

What the instruction tells you:

- `mov reg, [ebp-4]` followed by `mov edx, [reg]`, with a read of address 0, is a method called on a
  nil `Self`. The object was never created, or it was freed and its pointer cleared.
- The same address repeated hundreds of times points to a deterministic nil, not to memory corruption.
  A field freed with `FreeAndNil` and used again behaves like this, because the pointer is zero and the
  read always faults at the same instruction. A real use after free usually shows varying addresses,
  garbage values or crashes that come and go.
- When the faulting function belongs to a library routine such as `TStrings.IndexOfName`, the bug is in
  the caller that passed nil. Read the caller, not the library.

Counting outcomes by message type in the same log shows how wide the failure is. Group the lines that
report a result by type and by outcome. A type with no successes fails every time, and a type that mixes
both depends on the data.
