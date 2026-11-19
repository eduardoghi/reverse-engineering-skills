# Inspecting a running process

Read this when the code reads the same in every build but the program behaves differently, and you need
to look at its objects in memory, at how it grows or at where its time goes.

## Contents

- [Reading the memory of a process](#reading-the-memory-of-a-process)
- [Permissions and objects in memory](#permissions-and-objects-in-memory)
- [Growth and time](#growth-and-time)
- [Debuggers under Wine](#debuggers-under-wine)

## Reading the memory of a process

When the code reads the same in every build and the behaviour still differs, look at the objects in
memory. On Linux, including programs running under Wine, `/proc/PID/mem` can be read from Python
without attaching a debugger, and the process keeps running.

```python
mem = open(f'/proc/{pid}/mem', 'rb', 0)
for line in open(f'/proc/{pid}/maps'):
    lo, hi = (int(x, 16) for x in line.split()[0].split('-'))
    if 'r' not in line.split()[1] or lo >= 0x80000000:
        continue
    try:
        mem.seek(lo); data = mem.read(hi - lo)
    except OSError:
        continue      # guard pages and unreadable mappings
    ...
```

On Windows the same reads go through the Win32 API from 64-bit Python with `ctypes`, and the process
keeps running too. `LIST_MODULES_ALL` is what makes the 32-bit modules of a Delphi program visible from
64-bit Python, and each module handle is the image's load address:

```python
import ctypes
from ctypes import wintypes as w
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.OpenProcess.restype = w.HANDLE
k32.VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.K32EnumProcessModulesEx.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), w.DWORD]
k32.K32GetModuleFileNameExW.argtypes = [w.HANDLE, ctypes.c_void_p, w.LPWSTR, w.DWORD]

class MBI(ctypes.Structure):  # MEMORY_BASIC_INFORMATION
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', w.DWORD), ('PartitionId', w.WORD), ('RegionSize', ctypes.c_size_t),
                ('State', w.DWORD), ('Protect', w.DWORD), ('Type', w.DWORD)]

h = k32.OpenProcess(0x0400 | 0x0010, False, pid)  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
mods, needed = (ctypes.c_void_p * 1024)(), w.DWORD()
k32.K32EnumProcessModulesEx(h, mods, ctypes.sizeof(mods), ctypes.byref(needed), 3)  # LIST_MODULES_ALL
name = ctypes.create_unicode_buffer(260)
for base in mods[:needed.value // ctypes.sizeof(ctypes.c_void_p)]:
    k32.K32GetModuleFileNameExW(h, base, name, 260)
    print(hex(base), name.value)

READABLE = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80  # PAGE_READONLY to PAGE_EXECUTE_WRITECOPY
mbi, addr = MBI(), 0
while addr < 1 << 32 and k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
    lo, size = mbi.BaseAddress or 0, mbi.RegionSize
    addr = lo + size
    if mbi.State != 0x1000 or mbi.Protect & 0x100 or not mbi.Protect & READABLE:
        continue      # not committed, guard page or no access
    buf, got = ctypes.create_string_buffer(size), ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(lo), buf, size, ctypes.byref(got)):
        continue
    data = buf.raw[:got.value]
    ...
```

The module list also shows the WOW64 modules above 4 GB, which the scan skips. Reading a program that
runs as administrator needs Python started as administrator too.

## Permissions and objects in memory

- Reading another process needs ptrace permission. With `kernel.yama.ptrace_scope = 1` (the usual
  default) only a parent can read its child, and the read fails with `Permission denied`. Set it to
  0 with `sudo sysctl kernel.yama.ptrace_scope=0` for the session and back to 1 when done.
  Without sudo, a program you start yourself can allow it for its own process, which is useful with
  `strace -p` once it has settled, since starting it under `strace` slows down its startup. The
  exception ends with the process, but while it runs any program of the same user can trace it.

  ```sh
  python3 -I -c 'import ctypes, os, sys
  ctypes.CDLL(None).prctl(0x59616d61, ctypes.c_ulong(-1).value, 0, 0, 0)  # PR_SET_PTRACER, any
  os.execv(sys.argv[1], sys.argv[1:])' ./program &
  sleep 15
  strace -f -e trace=ioctl -p $!
  ```

  `strace -k` adds a stack to each call and can slow a busy program so much that the trace no longer
  shows its normal behavior. In one test, 15 seconds of tracing `ioctl` went from over 30,000 calls to about 300.
- The first dword of every Delphi object is its class pointer, which is the address of the exported
  VMT symbol `@Unit@TClass@` (adjusted by the rebase delta if the package didn't load at its
  preferred base, which `/proc/PID/maps` or the module list on Windows shows). Scanning readable memory for aligned dwords equal
  to that address lists the instances. Expect false hits inside the VMT itself, in RTTI and in freed
  objects, so check a few fields before trusting one.
- To find which field holds a sub-object when you don't know the offset, scan the object for
  pointers whose target starts with the VMT of the class you expect. Then read the container. Get the
  layout from the getters (`TList.GetCount`, `TCollection.GetCount`) in the build you are looking
  at, since field offsets change between compiler versions.
- An AnsiString field points at the first character, with the length in the dword before it and the
  reference count before that.
- Comparing instances answers questions that the code alone doesn't. For example, when the same data
  exists in a runtime object and in an edit copy, counting the items each one holds shows which copy
  lost them.

## Growth and time

- **Growth per unit of work.** To compare variants of a patched binary, sample the resident size and a
  counter that a hook increments once per unit, then divide the growth by the units over the same
  range for every variant. The cost of a unit depends on its content, so the cumulative average of runs
  of different lengths misleads. One variant looked like 0.77 MB per item that way and was 1.14 over the
  range the other runs shared. Disabling one callee at a time narrows a leak down quickly, but a variant
  that skips only the allocation's consumer may not change anything, because the leaked object is created
  before it.
- **Where the time goes.** Sampling `/proc/PID/task/TID/stat` (the state letter) and
  `/proc/PID/task/TID/syscall` shows whether the main thread is running or blocked, and in which system
  call. `perf record -e cpu-clock:u -g -p PID` counts CPU only, so a program that spends most of its time
  waiting looks almost idle, and the wall clock is the number that matters to the user. Under Wine the
  packages have no names in `/proc/PID/maps`. Build the module table by reading the first bytes of each
  candidate image at its preferred base from `/proc/PID/mem` and comparing the `TimeDateStamp` with the
  file's header, then name each sampled address with the nearest export from `rz-bin -E`. The
  `wine-debugging` skill has the rest.

## Debuggers under Wine

Debuggers under Wine are fragile. `winedbg --gdb` on a 32-bit program in Wine's new WoW64 mode
reports the target as i386, but its break-in thread runs at a 64-bit address. gdb truncates that
address, reports a SIGSEGV, and detaching then can leave the program dead or frozen. The gdb proxy
also accepts a single connection, so a failed session can't be resumed. Prefer reading memory as
above, or a GUI debugger such as x32dbg running inside the same Wine prefix, and warn whoever is
using the program that it may close.
