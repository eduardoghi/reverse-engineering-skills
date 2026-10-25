---
name: dotnet-decompile
description: Decompile .NET assemblies (EXE and DLL) to C# and XAML with ilspycmd, find the native functions they call through P/Invoke and read the configuration and Entity Framework model of the program. Use when you need to know how a .NET desktop program works, what a vendor SDK wrapper calls, where a program keeps its data, or what to reproduce in a program that replaces it.
---

# .NET decompilation

A .NET assembly keeps its code as IL with full metadata, so ILSpy recovers C# close to the original,
with type and member names, string literals and, for WPF, the XAML of every window from its compiled
BAML. It is still a reconstruction. Local names, loop shapes and compiler-generated classes differ
from the source, so confirm in the IL anything a conclusion depends on.

Native code is out of its reach. A program can ship native DLLs next to its assemblies and call them
through P/Invoke, and only the declarations of those calls are in the metadata. The native side needs
Ghidra or rizin, as in the `delphi-bpl` and `binary-diff` skills.

## Setup

`ilspycmd` is a .NET tool. Version 11.1 runs on the .NET 10 SDK.

```sh
dotnet tool install -g ilspycmd        # into ~/.dotnet/tools, which has to be on PATH
mkdir -p ~/.cache/netfx-ref && cd ~/.cache/netfx-ref
curl -sSLo net48.nupkg https://www.nuget.org/api/v2/package/Microsoft.NETFramework.ReferenceAssemblies.net48/1.0.3
unzip -q net48.nupkg
REF=~/.cache/netfx-ref/build/.NETFramework/v4.8
```

On Linux nothing provides the .NET Framework assemblies (`mscorlib`, `System.Windows.Forms`,
`PresentationFramework`), so pass the reference assemblies from that NuGet package with `-r` when the
target is .NET Framework. Without them ilspycmd still exits with 0 and prints nothing on stderr, but
the output degrades. On one WPF executable it left 2,808 `missing references` comments in the C#,
enum values as casts (`(MessageBoxButtons)4` instead of `MessageBoxButtons.YesNo`) and 7,324
placeholder `<Ctor>` elements in the XAML. With `-r "$REF"` there were none. The assemblies next to
the input are found without `-r`.

Pass `--disable-updatecheck` on every call, otherwise each run checks NuGet for a newer version.

## Method

1. **Sort the install folder.** A program ships its own assemblies, third-party libraries and native
   DLLs together. This lists each PE file as native, managed or mixed (C++/CLI, IL and machine code
   in one file) with its architecture and target framework. It needs `pefile`.

   ```sh
   python3 - "$APP_DIR" <<'EOF'
   import os, re, struct, sys, pefile
   for root, _, files in os.walk(sys.argv[1]):
       for name in sorted(files):
           if not name.lower().endswith((".exe", ".dll")):
               continue
           path = os.path.join(root, name)
           try:
               pe = pefile.PE(path, fast_load=True)
           except pefile.PEFormatError:
               continue
           bits = "x64" if pe.OPTIONAL_HEADER.Magic == 0x20B else "x86"
           clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
           if not clr.VirtualAddress:
               kind = "native " + bits
           else:
               flags = struct.unpack_from("<I", pe.__data__, pe.get_offset_from_rva(clr.VirtualAddress) + 16)[0]
               if not flags & 1:
                   kind = "mixed " + bits      # C++/CLI, IL and machine code
               elif bits == "x86" and not flags & 2:
                   kind = "managed AnyCPU"
               else:
                   kind = "managed " + bits
               target = re.search(rb"\.NET[A-Za-z]*,Version=v[0-9.]+", pe.__data__)
               kind += " " + (target.group().decode() if target else "?")
           print(f"{kind}\t{os.path.relpath(path, sys.argv[1])}")
           pe.close()
   EOF
   ```

   `?` means the assembly has no `TargetFrameworkAttribute`, which .NET Framework 4.0 introduced, so
   it targets 2.0 to 3.5. The vendor's assemblies usually share a name prefix and a target. Libraries
   such as Entity Framework, NLog or Autofac have public source, so skip them unless the question is
   about them.

2. **Decompile the vendor's assemblies as projects.** `-p` writes a `.csproj`, one folder per
   namespace, the `.resx` resources and, for WPF, the XAML of each window.

   ```sh
   ilspycmd --disable-updatecheck -p -r "$REF" -o out/App.Core App.Core.dll
   ```

   Ten assemblies that came out as about 2,000 source files took under 30 seconds together. Use one
   output folder per assembly.

3. **Go from what the user sees to the code.** A visible text may not be in any assembly. Search the
   install folder first, since programs keep translations in `.resx` files, satellite assemblies under
   culture folders (`pt-BR/App.resources.dll`) or files of their own (CSV, XML, JSON). The text leads to
   a key, and the key appears in the XAML (`{lex:Loc SomeKey}`, `{x:Static p:Resources.SomeKey}`) or in
   the C#. In the XAML, `Command="{Binding ...}"` and `Click="..."` name the view model command or the
   code-behind handler that runs.

4. **Read one type or member.** `-l c` lists the classes, `-t` decompiles one type and `-m` one member
   by its metadata token (`0x06...` for methods).

   ```sh
   ilspycmd --disable-updatecheck -r "$REF" -l c App.Core.dll
   ilspycmd --disable-updatecheck -r "$REF" -t Vendor.App.Devices.DeviceManager App.Core.dll
   ilspycmd --disable-updatecheck -r "$REF" -m 0x06000123 App.Core.dll
   ```

   `-il` ignores `-t` and `-m` and prints the IL of the whole assembly, so write it to a file and cut
   the method out. IL puts a space before the parameter list and ends each method with a comment:

   ```sh
   ilspycmd --disable-updatecheck -il App.Core.dll > App.Core.il
   awk '/ SaveChanges \(/,/end of method DeviceStore::SaveChanges$/' App.Core.il
   ```

## Native calls

P/Invoke declarations are rows of the `ImplMap` metadata table, and the DLL names are in `ModuleRef`.
Joining the two lists every native function an assembly calls without decompiling it:

```sh
ilspycmd --disable-updatecheck --dump-table ModuleRef --json App.Sdk.dll > modules.json
ilspycmd --disable-updatecheck --dump-table ImplMap --json App.Sdk.dll |
    jq -r --slurpfile m modules.json '($m[0].rows | map({(.Token): .Name}) | add) as $dll
        | .rows[] | "\($dll[.ImportScope])\t\(.ImportName)\t\(.MemberForwarded)"' | sort
```

The last column is the token of the C# declaration, for `-m`. In the decompiled project, the
`[DllImport]` methods and the `[StructLayout]` structs and callbacks they take are the native
interface as the vendor's wrapper sees it, with argument types, buffer sizes, string encodings and
calling conventions. When the vendor publishes the SDK, its headers and manual cover the same functions with
the original names and comments, and they beat decompiled marshaling code.

To see how the program uses a native call, search the project for the C# method name. Wrappers often
add retries, unit conversions or locking that the native function doesn't do.

## Configuration and data

- `App.exe.config` holds connection strings, settings and assembly binding redirects. Each DLL can
  have its own `.dll.config`.
- An NLog configuration (`NLog.config` or `App.exe.nlog`) says where the logs go and at what level.
  Raising the level in a copy of the program shows what it does at run time without a debugger.
- With Entity Framework 6, each migration is a `DbMigration` subclass whose `Up` method creates the
  tables with every column, so the schema is in the decompiled code even when the database can't be
  opened. The `.resx` of each migration also holds the whole model at that point, as base64 gzip EDMX
  in its `Target` value:

  ```sh
  python3 - Vendor.App.Migrations.SomeMigration.resx <<'EOF'
  import base64, gzip, sys, xml.etree.ElementTree as ET
  for d in ET.parse(sys.argv[1]).getroot().iter("data"):
      if d.get("name") == "Target":
          print(gzip.decompress(base64.b64decode(d.find("value").text)).decode("utf-8-sig"))
  EOF
  ```

- SQLite files open with `sqlite3`. SQL Server Compact files (`.sdf`) have no reader on Linux that
  was tried with this skill, so take the schema from the migrations.

Work on copies of databases and configuration files.

## Obfuscation

Obfuscators rename what other assemblies don't reference. In one protected program, public types and
their public members kept their names. Private members got random names of 10 or 11 characters
(`pX7m2QaLc9`), and internal and compiler-generated classes and some namespaces 20-character ones
(`Kq3VhT8wZpLx0RmNc5Ya`). Constructors started with a call to an empty static method the protector
added, and the protector brought its own classes with crypto routines. String
literals and method bodies were intact, so the code read fine once the names were taken as labels.
Rename them in your notes as you work out what they do.

Other protectors encrypt strings or method bodies, which shows up as calls with a number where
literals should be, or as bodies that only call into the protector. This skill hasn't been tried on
such a file, nor on single-file bundles (`-d` and `--bundle-entry` in ilspycmd) or NativeAOT
executables, which have no IL and need Ghidra.

## Under Wine

A .NET Framework program can run under Wine on Linux, where the `wine-debugging` skill applies. Its
files are in the prefix (`drive_c/ProgramData` and `drive_c/users/<user>/AppData` for data and
settings), and its network traffic goes through the host's sockets, so `tcpdump` on the host captures
it (`sudo tcpdump -i any -w app.pcap host 192.0.2.10`).

## Writing a replacement

Keep decompiled code and the vendor's binaries out of any repository. To write a program that
replaces another, describe what it does (calls, messages, formats, timings) in your own words and
write the new code from that description. When the program talks to devices or services through a
vendor SDK, check whether they also speak a documented protocol before reproducing the SDK.
