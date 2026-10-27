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

## Directory listing order

A program that lists a directory with `FindFirstFile`/`FindNextFile` (Delphi `FindFirst`) got the
entries in alphabetical order under Wine, even when the folder was on btrfs and its subfolders had been
created in a different order. `ls -U` on the same folder showed the creation order. Wine appears to sort
the entries the way NTFS returns them, so the order in which you create files or folders can't be used
to steer a program that processes them in listing order. Rename them instead.

## Driving the user interface

To reproduce a bug or run a test through the screens of a program, `xdotool` sends clicks and keys and
ImageMagick's `import` captures a window. Wine windows are X11 windows, so this also works in a Wayland
session through XWayland. Both act on the real mouse and keyboard, so ask the person at the machine to
leave them alone while a script runs.

```sh
wmctrl -lG                                       # window ids, titles and geometry
import -window 0x01a00159 shot.png               # capture one window, without decorations
xdotool windowactivate --sync 0x01a00159
xdotool mousemove --window 0x01a00159 205 39 click 1
xdotool type --delay 40 '1234'; xdotool key Tab
magick shot.png -crop 900x60+0+500 part.png      # zoom into a region before reading it
```

- Use coordinates relative to the window (`mousemove --window`) and read them from a capture of that
  window, where pixel (x, y) of the image is the same point. With display scaling, `wmctrl -lG` and
  `xdotool getwindowgeometry` report the same window at different absolute positions (4688 against
  2344 at 200%), so absolute coordinates are easy to get wrong.
- After every action that can open a message box, list the windows again with `wmctrl -l` and look for a
  new one before typing anything. A modal dialog takes the keys, and `xdotool getactivewindow` doesn't
  always return it, so a script that captures "the active window" can miss the dialog and keep typing
  into the wrong place. Capture the dialog by its id, answer it, and only then go on.
- Don't rely on a fixed `sleep` after an action that loads data. A record that took 10 seconds to load
  swallowed the keys typed after 3 seconds, and they ended up in another field. Capture again until the
  screen shows the loaded data.
- A grid can keep showing an edited value after it was saved or reverted. Check the result in the data
  the program writes (a database, a file) rather than on the screen, and reload the record before
  editing it again. Some screens only write when a save button is pressed, not when the field loses
  focus, and a child dialog's "OK" may only take effect after the save button of the parent screen.
- Clicking a VCL edit box doesn't select its text, and `ctrl+a` doesn't select all in it, so typing
  appends to the old value. A record number field kept its digits and the new ones went after them,
  and the program asked whether to create a record out of sequence. Clear the field with `End` and
  enough `BackSpace`, or reach it with `Tab`, which selects the whole text of the field it lands on.
- A click can land on the neighbouring field and take the typing with it, for example a code that
  ended up inside a date field and came back as an invalid date. After clicking a field, capture it and
  check the focus before typing.
- A form with a horizontal scroll bar scrolls when a field near its edge gets the focus, so every
  coordinate read from the previous capture moves. Capture again after each click on such a form.
- In a data grid (`TDBGrid`), `Down` on the last row usually posts it and appends a new row (once it
  appended nothing, and the row came only with `Insert`), and `Escape` discards an appended row that is
  still empty. `Insert`, or a click on a cell of the empty row, makes the grid validate that row at once
  and pops up a "required field" message. To reach a column, press `Tab` a counted number of times from
  a column you know instead of clicking, because the grid scrolls sideways as the focus moves.
- Message boxes often share one title ("Confirmation", "Warning") and a progress window can stay open
  under them. Tell them apart by size with `xdotool getwindowgeometry` and wait in a loop for the next
  window that isn't the progress one:

  ```sh
  for i in $(seq 1 30); do sleep 2
    for d in $(wmctrl -l | awk 'NR>2{print $1}'); do        # skip the main windows
      g=$(xdotool getwindowgeometry $d | grep Geometry)
      case "$g" in *260x92*) ;;                             # size of the progress window
        *) import -window $d next.png; echo "$d $g"; break 2;; esac
    done
  done
  ```

  Click the buttons by coordinates inside the dialog (`mousemove --window $d`), read from its capture.

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
