# Byte patterns and other builds

Read this when the patch works and has to be applied by a tool to many copies of the file, or carried to
a new build of the program.

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
