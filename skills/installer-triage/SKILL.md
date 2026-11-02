---
name: installer-triage
description: Decide whether a Windows installer or the programs inside it look malicious, without running anything. Read what the installer does, disassemble its script, compare its engine with the official build, unpack everything and check each binary for signs of tampering. Use when someone asks if a downloaded setup.exe is safe, when an antivirus result is not enough, or when you need to know what an installer will change on a machine.
---

# Installer triage

An antivirus result says little about an installer. Its payload is compressed and often encrypted, so
the scanner sees a loader and random-looking data. A clean scan of the outer EXE doesn't cover the files
inside it, and the same goes for a clean signature, which only says who signed it.

The goal is an honest answer with its limits stated. "No sign of malware in what was checked, and this
part couldn't be checked" is a result. "Clean" almost never is, because static analysis can't prove
that a program does nothing bad.

Nothing here runs the target. That rules out the installer, what it unpacks and any tool it ships, and
it also rules out reading the target with an interpreter started from inside its folder, where a planted
`json.py` would load. Keep the target in its own directory, keep scripts elsewhere and pass paths.

## Setup

- `bin/inno-unpack`, `bin/nsis-script` and `bin/hsp-unpack`, Python 3 standard library only
- `pefile` for the checks on binaries
- `xxhash` to verify files from a modified build, `pycryptodome` for decrypting anything large
- `capstone` when a finding needs reading machine code, and `delphi-bpl` or `binary-diff` to go deeper

## Method

1. **Record the starting point.** Hash the files, check their signatures and run the local scanner in
   report-only mode. On Windows that is `Get-AuthenticodeSignature` and
   `MpCmdRun.exe -Scan -ScanType 3 -File DIR -DisableRemediation`. Keep the hashes, since looking one up
   on VirusTotal publishes nothing while uploading the file does. An unsigned installer is common and
   proves nothing either way, so note it and move on.

2. **Identify the format.** `inno-unpack info setup.exe` answers for Inno Setup and says when the build
   is modified. For anything else look at the sections and the overlay. A `.rsrc` that ends well before
   the end of the file means the payload is an overlay, and its first bytes usually name the format.
   7-Zip lists NSIS and plain SFX archives. An overlay that starts with `DPMX` is an HSP program, not a
   hidden payload, see below.

   ```sh
   inno-unpack info setup.exe
   7z l setup.exe
   ```

3. **Read what the installer declares.** This is where most droppers show themselves, as a `[Run]` entry
   for something in `{tmp}`, a `Run` key in the registry, a file that lands in `{sys}` or a download. For
   NSIS, 7-Zip extracts the files but not the script, so use `nsis-script`, which prints each action.

   ```sh
   inno-unpack actions setup.exe
   inno-unpack list setup.exe | cut -f1,3 | sort -rn | head -30
   nsis-script setup.exe
   ```

   A signature covers the EXE and nothing beside it. An installer from the vendor can be driven by a
   config file in the same folder, so read those too.

4. **Disassemble the script.** The `[External]` section of `disasm` is the list of everything the script
   can call, and what isn't listed can't run, which makes it stronger evidence than any string search.
   Look for `dll:` imports, `Exec`, `ShellExec`, `DownloadTemporaryFile` and `CreateOleObject`, then read
   the procedures that use them to see when they fire. `code` is the quick version, a scan of names and
   strings that says what the script can reach but not when. A password that nobody is asked for is often
   built by the script itself from single characters, so read `InitializeSetup` and `CurPageChanged`.

   ```sh
   inno-unpack disasm setup.exe > script.txt
   sed -n '/^\[External\]/,/^$/p' script.txt
   inno-unpack disasm setup.exe --proc CurPageChanged
   ```

5. **Compare the engine with the official build.** The script isn't the only code that runs. The engine
   is, and a modified build can add anything to it. Extract the engine, take `Setup.e32` from the signed
   Inno Setup release of the same version and compare imports and strings. Use `engine`, which undoes the
   call filter and checks the result against the table in the loader, or every CALL points at the wrong
   place. A larger engine isn't suspicious by itself, because a different Delphi version pulls in other
   units. What matters is what the additions are and who calls them.

   ```sh
   inno-unpack engine setup.exe engine.bin
   inno-unpack extract innosetup-6.4.2.exe official --only '*.e32'
   ```

   A function with no direct caller that is only referenced from a registration table is script API. It
   runs only if the script imports it, and step 4 settles that.

6. **Unpack everything and classify by content.** Extensions lie, so sort by the first bytes. Anything
   that isn't the file type its name claims gets read. Every file that passes its hash also proves the
   key, layout and decompression were right, which means no data was silently skipped.

   ```sh
   inno-unpack extract setup.exe out --password SECRET
   ```

7. **Scan the unpacked files, one piece at a time.** The scanner can finally see them. A detection on an
   archive doesn't say which file set it off, so run report-only over each executable and read the name of
   the detection. `HackTool:Win32/Keygen` names a category and can be accurate about a file that does
   nothing else. A heuristic name ending in `!cl` says less than a named family.

   ```powershell
   MpCmdRun.exe -Scan -ScanType 3 -File FILE -DisableRemediation
   Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending
   Get-MpThreat | Select-Object ThreatName, IsActive, DidThreatExecute
   ```

   `DidThreatExecute` tells a file that sat on disk from one that ran. Event 5007 in the Defender log
   records changes to exclusions, which matters twice. An exclusion narrows what every other scan means,
   and an installer that adds one is a finding by itself.

   ```powershell
   Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=5007}
   ```

8. **Check each binary.** A signature that names the vendor and reports `HashMismatch` means the file
   changed after signing. That is expected in a patched program, and it also means the vendor's signature
   no longer vouches for anything in it. Then look at the structure. These all come from the linker, so
   any of them being off is worth reading:

   - extra sections, or an entry point outside `.text`
   - TLS callbacks, which run before the entry point
   - imports that differ between builds of the same code
   - imports of a DLL that isn't part of Windows and isn't in the package
   - a PE embedded in the file, and hosts and IP addresses in its strings

   A missing DLL is the one to chase. A patched plugin can swap `wininet.dll` and `ws2_32.dll` for
   replacements that ship in a separate download. Until they exist the program can fail with a message
   saying its own file wasn't found, even though the file is there, and reinstalling doesn't help. List
   what doesn't resolve:

   ```python
   import os, sys, pefile
   pe = pefile.PE(sys.argv[1], fast_load=True)
   pe.parse_data_directories()
   for entry in pe.DIRECTORY_ENTRY_IMPORT:
       if not os.path.exists(os.path.join(r"C:\Windows\System32", entry.dll.decode())):
           print(entry.dll.decode(), [i.name or f"#{i.ordinal}" for i in entry.imports])
   ```

   Those imports are often by ordinal, and for a `ws2_32` replacement the numbers keep their meaning, such
   as 1 `accept`, 3 `closesocket`, 4 `connect`, 16 `recv`, 19 `send` and 23 `socket`.

   A DLL described as doing nothing can be tested, because such a file is small enough to read in full.
   Disassemble every export, stop at the first `ret` and group the bodies. Real stubs collapse into a few
   shapes such as `xor eax, eax; ret`, and their imports are almost empty. Anything longer gets read.
   Stubs have a cost worth stating too. One that replaces `WinVerifyTrust` answers yes for every file, for
   whatever imports it.

   On x64, code built by MSVC is listed in `.pdata`, so bytes in `.text` outside it deserve a look. Most
   of them are harmless, see the table below. Compare the same check across builds of the same code, as
   injected code tends to stand out as the one gap that isn't shared.

   ```python
   import struct, sys, pefile
   data = open(sys.argv[1], "rb").read()
   pe = pefile.PE(data=data, fast_load=True)
   sections = {s.Name.rstrip(b"\0").decode("latin1"): s for s in pe.sections}
   text, pdata = sections[".text"], sections[".pdata"]
   code, raw = text.get_data(), pdata.get_data()[:pdata.Misc_VirtualSize]
   entries = struct.iter_unpack("<III", raw[:len(raw) - len(raw) % 12])
   position = text.VirtualAddress
   gaps = []
   for begin, end in sorted((b, e) for b, e, _ in entries if b) + [(text.VirtualAddress + text.Misc_VirtualSize,) * 2]:
       if begin > position:
           body = code[position - text.VirtualAddress:begin - text.VirtualAddress].strip(b"\xcc\x00\x90")
           if len(body) >= 6:
               gaps.append((len(body), hex(position), body[:16].hex()))
       position = max(position, end)
   for gap in sorted(gaps, reverse=True)[:20]:
       print(*gap)
   ```

   A signature made with `/ph` holds a hash for each 4 KiB page, which pinpoints what a patch touched
   without the original. Not every signature has them, so check.

   ```python
   table = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
   blob = data[table.VirtualAddress:table.VirtualAddress + table.Size]
   print(any(bytes.fromhex(oid) in blob for oid in ("2b060104018237020301", "2b060104018237020302")))
   ```

9. **State what was and wasn't covered.** Name what passed, then what couldn't be done. The usual gaps
   are below.

## What this can't show

A patch inside `.text` that replaces a few instructions changes no section, import or string. Without the
original binary or page hashes it can't be located, let alone proven harmless, so a modified program
keeps that risk however clean everything else looks. The signature mismatch tells you the risk exists.

Static checks also miss what only happens at run time, such as a payload decrypted from data, a download
hidden behind a condition or code that waits for a date. Say so. Going further takes a sandbox and the
owner's decision to run the file, and that isn't a step to take on your own.

Reputation searches are weak evidence in both directions. No reports about a small release group mostly
means nobody wrote about it.

## Signs that look worse than they are

| Sign | Usual source |
|---|---|
| `keylog`, `SSLKEYLOGFILE` | TLS key logging in OpenSSL and libcurl |
| `keygen`, `rsa_keygen_bits`, `EVP_PKEY_keygen` | OpenSSL key generation |
| `cscript` | a case-insensitive match inside `...FuncScriptFuncs` in Inno Setup |
| 150 KB of random bytes in `.text` | `ecp_nistz256_precomputed`, an OpenSSL table. Its first 8 bytes are `3c 14 a9 18 d4 30 e7 79` |
| thousands of `.pdata` gaps | leaf functions and C++ static initializers, such as `mov edx, 0xfff0f8ff` for the JUCE colours |
| `GetAsyncKeyState`, `SetWindowsHookExW` | ordinary in GUI frameworks such as JUCE |
| `5.0.4.1` reported as an IP address | version-like strings. Require an octet of 16 or more before reading further |
| `WinHttpOpen` in an Inno engine | the official engine has `winhttp` too, for downloads |
| `iphlpapi`, `RegSaveKeyW`, printer APIs in a Delphi engine | units pulled in as a whole, or script helpers no script imports |
| high entropy in `.rsrc` | PNG resources. List the resource types first |
| `CreateRemoteThreadEx` as a string, not an import | a table of names in the Microsoft Concurrency Runtime, next to `CreateUmsCompletionList` |
| `PowerShell.exe` with `DownloadFile` | can be a vendor's update check. Look for the update URL and product strings around it |
| `cmd.exe /c start` | can open a local HTML file. Read the rest of the format string |
| large overlay after a small runtime | a `DPMX` archive means HSP. Read `start.ax` before calling it a payload |
| `HackTool:Win32/Keygen` | says what the file is, a key generator. It neither clears nor convicts it |
| packed DLL from 2004 with one huge section | can be `BASSMOD.dll`, a tracker music player seen in keygens. Compare it across releases |

None of these clears a file. They mean the string alone is not a finding.

## Keygens

The two R2R keygens these tools were built on are an NSIS wrapper around a few files in `%TEMP%`, with a
runtime, a crypto DLL, a music player and a tracker module. `nsis-script` shows whether a wrapper only
extracts, runs and deletes. Both are also written in HSP, which makes `keygen.exe` a stock runtime with the
logic in an archive after it. `hsp-unpack` decodes that script and prints the DLLs and functions it declares,
by library, and its strings.

```sh
nsis-script KeyGen.exe
7z x KeyGen.exe -okg
hsp-unpack script 'kg/$TEMP/keygen.exe'
```

A clean list here is a list of DLLs and text. It doesn't show HSP's built-in commands such as `exec`, and
the instructions aren't disassembled, so run a keygen only in a disposable environment, with no network
and no shared folders beyond an empty one for its output. A sandbox contains the program and proves nothing
about it. One that notices the sandbox and stays quiet looks clean, so a quiet run isn't a reason to run it
on the real machine. What matters is that only checked output leaves, such as a license file read as text.

## Modified Inno Setup builds

Some release groups build Inno Setup from a fork. These show up as CRC errors and layouts that don't fit,
and generic extractors give up, which also hides the contents from scanners. That is a reason to look
closer rather than a verdict.

`inno-unpack` tells the cases apart. A table whose checksum is XXH32 is read as the known fork of 6.4.2,
which also has a 64-byte KDF salt, XXH128 file digests, keyed BLAKE2b in place of PBKDF2 and a reordered
compression enum. A table that points at setup data with any other checksum is reported as a modified
build it can't read. To add one, start from the facts the file gives away:

- Try the checksum candidates on the 40 bytes of the offset table. Constants of xxHash, BLAKE2 or SHA-3
  in the engine narrow them down.
- Skip the checks and decompress setup-0 anyway. The LZMA stream is usually intact, and the record
  sizes come from dividing the block sizes by the entry counts.
- Find the password test in the engine through its nonce copy, `mov ecx, 6` followed by `rep movsd`, then
  read the distance between the fields it uses. `GenerateEncryptionKey` is the call right before it.

## Traps

- **The call filter.** `setup.e32` is stored with E8 and E9 operands made absolute, and the filter runs
  over the whole file, data included. Read it that way and every import looks unreferenced, which reads
  as dead code, and part of `.idata` is damaged, so imports go missing and a diff shows false removals.
  If targets land outside `.text`, the filter is still on. Always work from the output of `engine`.
- **Bytes that look like calls.** Scanning for `E8` over `.text` also matches data and padding. A
  reference that changes between builds of the same code is a coincidence.
- **Regexes with an open prefix.** `[\x20-\x7e]*keygen` on a 44 MB binary backtracks for minutes. Find
  the needle first, then widen around it.
- **Substring filters.** Check what an indicator matched before reporting it, as the table above shows.
- **Detections arrive late.** Defender logs a detection some seconds after the file was touched, so a copy
  that looks fine at once can be gone a moment later. Wait, then read the log, before saying it passed.
- **A scan that ends in seconds.** Tens of gigabytes scanned in two seconds weren't read in full, whatever
  the result says. `Measure-Command` also swallows the output, so print the scanner's own line.
- **Protection left off.** Disabling the scanner to read a file is the owner's call. Check its state at the
  end and say so if it is still off.
- **`python -I` ignores `PYTHONIOENCODING`.** Printing from a target then dies on the first character the
  console can't encode. Use `python -X utf8 -I`.
- **`set -e` isn't a gate.** It didn't stop a script that went on to commit after a failed step. Check the
  result of each step before the next one that can't be undone.
