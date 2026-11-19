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
