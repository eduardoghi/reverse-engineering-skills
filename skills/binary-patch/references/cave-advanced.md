# Advanced code in a cave

Read this when the new code is too long for assembly and should live in a DLL, or when it calls host code
that may raise an exception.

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
- **Calling the host from the DLL.** A Delphi package exports every routine by its mangled name, so the DLL
  can find them with `GetModuleHandleA` on the package and `GetProcAddress` with the exact export name, and
  fall back to the original behaviour when one is missing. Call them with a few lines of inline assembly
  that load `eax`, `edx` and `ecx` and mark the C caller-saved registers as clobbered. The register
  convention keeps `ebx`, `esi`, `edi` and `ebp`, like the C one.
  - A constructor takes the class (the VMT export, `@Unit@TClass@`) in `eax`, 1 in `dl` to allocate, and its
    first parameter in `ecx`.
  - A result record larger than 4 bytes, such as `TMethod`, comes back through a hidden pointer passed after
    the declared parameters.
  - For a fixed `const AnsiString` argument, a static literal laid out like the compiler's own also works:
    reference count -1, length, the characters and a zero, passing the address of the first character.
    Delphi treats a count of -1 as a constant and copies the text when the callee keeps it. Text built at
    run time still goes through `@LStrFromPChar`.
- **Handling an event of the host.** A `TNotifyEvent` handler is a `TMethod`, code and data. The code gets
  the data in `eax` and the sender in `edx`, so point it at a naked stub that pushes both and calls a C
  function. Set it with `TypInfo.SetMethodProp(Instance, 'OnClick', Method)`, which finds the field by the
  published property name, so no field offset is needed. To switch an event off while the patch works, read
  it with `GetMethodProp`, set an empty `TMethod` and put the old one back at the end.
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
