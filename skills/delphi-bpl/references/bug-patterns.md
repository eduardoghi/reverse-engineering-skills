# Bug patterns in Delphi code

Read this when the code runs but the result is wrong, such as a leak, a value that never changes, or data
that is lost or loaded only once. Each entry says what the defect looks like in the disassembly.

- **Library objects that the package doesn't import methods for.** The fields of VCL classes sit at fixed
  offsets for a given compiler, so code you inject can read them directly. In the Delphi 7 era layout a
  `TTreeNode` has the text at +8 and `Data` at +0xC, and a `TStrings` descendant answers `IndexOf`, `Add`
  and `Delete` through virtual slots. Confirm each offset in code that already touches it (a handler that
  reads `[node+0xC]` before using `Data`) rather than trusting a table.
- **Creating a VCL control from injected code.** Load the class pointer from the import slot of its VMT, call
  the constructor (`mov dl, 1`, owner in `ecx`), then `SetParent`, `SetBounds`, `SetAnchors` and `SetText`, and keep
  the object in a state cell that the form's `OnDestroy` hook clears. Both `SetParent` and `SetBounds` are virtual,
  so call them through the object as described in the `binary-patch` skill. With a nil owner nothing frees the
  control when the form goes away, so pass the form as owner when the control should die with it.
- **Editing a string literal in place.** A shorter text fits if you write the new length and leave the total
  size alone, padding with zeros after the new terminator. A longer one doesn't fit. To drop an argument from a
  format string without touching the code, use an index: `'%1:s'` prints the second argument of
  `'Item %d: %s'` and ignores the first. Run `bpl-xref str` first, because every reference to the literal gets the
  new text, including screens you didn't mean to change. When a text doesn't change on screen, it may come from a
  translation table and not from the literal.
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
- **`TStringList.Objects`.** Up to Delphi 2007 a `TStringList` never owns the objects stored with `AddObject`, and
  freeing the list leaves them alive. Code that hangs a freshly loaded collection on a list owned by a short-lived
  object leaks one collection per object. The same fact makes it safe to keep a pointer to such an object after
  the list is gone. Check the `Destroy` of the owner, and of the classes in the collection, before relying on it.
- **When something is loaded again.** Code that loads data once (a list read from a database, a cached object)
  usually guards it with a field of the object. It tests the field (`cmp byte [eax+0x1c], 0`), loads, and then
  sets it (`mov byte [eax+0x1c], 1`). To learn when the data is loaded again, find every write to that offset in the methods
  of the class. Take the address range of the class's exports and search the disassembly:

  ```sh
  objdump -d -M intel --no-show-raw-insn --start-address=0x... --stop-address=0x... app.bpl |
      grep -E 'mov +BYTE PTR \[e[a-z]+\+0x1c\]'
  ```

  Each write of zero is a place that invalidates the data. Run `bpl-xref calls` on the methods that hold them to
  see who triggers it. In one case only the destructor and an import routine of other subclasses cleared the flag,
  so the data stayed in memory until the program closed. The same offset is a different field in an unrelated
  class, so stay within the class and its descendants, which share the field layout.
- **A stored change that has no effect.** When the program keeps ignoring a value that was changed where it is
  stored, look for a cache of the processed result, often a file in the temporary directory or next to the data.
  Search for format strings that build file names (`bpl-xref str app.bpl '%s.'`) and for calls to the temporary
  directory helper, then read the check that decides whether the cache is still valid. It often compares a
  version, a size and a hash of only part of the input. In one case the processed form of some data was cached
  under a hash of its text alone, so changing an option stored elsewhere did nothing until the cache file was
  deleted.
- **Only one row of a list is saved.** When a routine deletes the stored rows and writes back what an in-memory
  dataset or cursor holds, check whether a range or filter is still active when the write loop runs (`SetRange`,
  `Filtered`, or a method that calls them). The loop walks only the rows inside the range, so the rows outside it
  are deleted and never written back, and the last filtered row is often the only one left. Look for the call that
  sets the range in the code that runs per row, and for a `CancelRange` that comes only after the write loop.
