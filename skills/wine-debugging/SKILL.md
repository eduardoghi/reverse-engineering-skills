---
name: wine-debugging
description: Find out why a Windows program is slow, behaves differently or dies when it runs under Wine on Linux. Use to split wall time between CPU, file access and waiting, to measure what a network share costs, to reproduce Windows text widths, and to capture a silent crash.
---

# Debugging a Windows program under Wine

The usual question is whether the slowness or the failure belongs to the program or to the environment
Wine builds around it. Measure first. The same binary can take 7 seconds on one machine and 80 on
another because of how files are listed, how fonts are measured or how a share is mounted.

All the commands below work on the process of the program, so find its Linux PID first. Wine names the
process by the Windows command line, which `/proc/PID/cmdline` shows:

```sh
for p in /proc/[0-9]*; do tr '\0' ' ' < $p/cmdline 2>/dev/null | grep -q '^C:.Dir.app.exe' && basename $p; done
```

## Where the time goes

`perf` and the wall clock answer different questions.

- `perf record -e cpu-clock:u -F 499 -g -p PID -- sleep 120` counts CPU time only, and it works on the
  process of your own user without extra permission. A program that waits for files or the network
  shows a few seconds of CPU while the user waits a minute.
- `strace -f -c -w -p PID -o resumo.txt` totals the wall time spent in each system call, for all threads.
  Idle threads (a timer thread in `pselect6`, a waiting thread in `ioctl` or `futex`) dominate the
  totals, so look at what the busy thread does. Stop it with Ctrl+C or `kill -INT` so it prints.
- To see the main thread over time without attaching anything, read `/proc/PID/task/PID/stat`
  (field 3 is the state, `R` running, `S` sleeping, `D` waiting on I/O) and `/proc/PID/task/PID/syscall`
  every 20 ms. A thread blocked in `read`, `getxattr` or `newfstatat` in state `D` is waiting for files.
  Group the samples by 10 seconds to see when the slow part starts and ends. Reading these files needs
  ptrace permission (see `kernel.yama.ptrace_scope` in the `delphi-bpl` skill).
- Many sockets show up as `sendmsg` and `recvmsg` to the wine server. Count the ones on the database
  socket and the gap between a send and the next read to get the round trip time. In one case 1281
  round trips cost 0.7 seconds in total, which cleared the database of any blame.

## Files on a network share

Wine asks for two extended attributes of every file it lists, `user.DOSATTRIB` and `user.WINEREPARSE`,
with `getxattr`. On a CIFS mount each call goes to the server, even when the file has no such attribute
and the answer is `ENODATA`. For a folder of 6000 files that was 8700 calls of about 2 ms, over 20
seconds of waiting in a single directory listing.

```sh
python3 - <<'PY'
import os, time
files = sorted(os.listdir('.'))[:300]
t = time.time()
for f in files:
    try: os.getxattr(f, 'user.DOSATTRIB')
    except OSError: pass
print('%.3f s' % (time.time() - t))
PY
sudo mount -o remount,nouser_xattr /path/to/mount     # try it, and user_xattr undoes it
```

With `nouser_xattr` the kernel answers `EOPNOTSUPP` at once and the 300 calls took under a millisecond.
Add the option to the mount options (`pam_mount.conf.xml`, `/etc/fstab`) to keep it after the next
login. The price is that Wine can no longer store DOS attributes (hidden, read only, system) on that
share. The contents of the files are not affected.

Reading the start of each file is slow on a cold cache as well. Time 300 files with a plain `open` and
`read` of a few hundred bytes. On the share used here it was 18 ms per file the first time and 3 ms the
second. A fix has to avoid the per file work, because mount options don't help.

## Text widths that differ from Windows

A program that measures text and compares the width with a stored value, for example to check that
the fonts of a document are the ones it was made with, fails by one or two pixels under Wine. FreeType's
TrueType interpreter version 40 hints only vertically. Windows GDI uses the full hinting of version 35,
so the advance widths differ.

```sh
FREETYPE_PROPERTIES=truetype:interpreter-version=35 wine app.exe
```

Measure before and after with a small program, built with `i686-w64-mingw32-gcc medir.c -o medir.exe
-lgdi32 -luser32`, that calls `GetTextExtentPoint32A` for a few strings and heights:

```c
HDC dc = GetDC(NULL);
HFONT f = CreateFontA(-12, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, DEFAULT_QUALITY, 0, "Arial");
SelectObject(dc, f);
SIZE s; GetTextExtentPoint32A(dc, text, lstrlenA(text), &s);   // s.cx is the width in pixels
```

For Arial, a 54 character line at 12 px measured 314 px by default and 312 px with version 35, and at 16
px 409 against 396. That removed a 2 pixel mismatch that failed a document check. The glyphs look
different with version 35, which is the price of the same widths. Set the variable only for the runs that
need it, in a second launcher. The metric compatible fonts of the original (for example the
`corefonts` package) have to be installed in the prefix too.

Run the program from `wine` in the same prefix as the application while it is open. It shares the wine
server and doesn't disturb it.

## A program that closes or crashes

Wine writes nothing by default when a program disappears. Start it from a shell with the logging you
need, and redirect stderr to a file.

- `WINEDEBUG=err+all` prints the unhandled exceptions Wine reports, usually nothing for a clean exit.
- `WINEDEBUG=err+all,+seh` logs every exception the program raises, including the ones it handles on
  purpose. A Delphi program raises many, so the file grows to tens of megabytes. The last lines show
  which handler was running when it died. An access violation with `ecx=cafebabe` is a Java thread
  that the JVM handles by itself and is not your crash.
- `WINEDEBUG=err+all,+process` is small and logs process creation and exit.
- `strace -f -qq -o trace.txt -e trace=exit_group,kill,tgkill -e signal=SIGSEGV,SIGKILL,SIGABRT wine app.exe`
  shows how each process ended. `exit_group(0)` is a normal exit. `+++ killed by SIGSEGV (core dumped)
  +++` is a native crash, and the `SIGSEGV` lines before it give `si_addr`. A first fault at a null
  address followed by one at a protected address is a crash while Wine was already handling the first,
  so look at what the program was drawing or writing at that moment.
- When a patched program dies, bisect with a variant that follows the same path but uses a constant
  where the real data goes. See the `binary-patch` skill.
