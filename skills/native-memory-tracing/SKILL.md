---
name: native-memory-tracing
description: Find what keeps growing in a native program on Linux when you don't have its source or its symbols, including GPU memory that doesn't show up in RSS. Use when a program or media pipeline slows down the machine or gets killed by the OOM killer, to measure memory per DRM client, to record who allocates with an LD_PRELOAD shim, to resolve stacks through debuginfod and to isolate the culprit layer by layer.
---

# Tracing memory growth in a native program

A process can take down a machine while its RSS looks fine. In one case a video pipeline showed about
900 MB of RSS and swap, but closing it released far more than that, because the growth was in GPU
buffers. Watch the system and the GPU counters from the start.

## GPU memory per client

`/proc/PID/fdinfo` lists DRM usage for each open device, in `drm-total-*`, `drm-resident-*` and
`drm-shared-*` keys. Group by `drm-client-id`, since several descriptors can point to one client, and sum
the regions of a client, since i915 reports several and the last one may be 0.

```python
import glob, re, sys
units = {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024, "": 1 / 1048576}
clients = {}
for path in glob.glob(f"/proc/{sys.argv[1]}/fdinfo/*"):
    try:
        text = open(path).read()
    except OSError:
        continue
    client = re.search(r"drm-client-id:\s*(\d+)", text)
    if client:
        clients[client.group(1)] = sum(int(v) * units[u] for v, u in
            re.findall(r"drm-total-[\w-]+:\s*(\d+)\s*(KiB|MiB|GiB)?", text))
for cid, total in sorted(clients.items(), key=lambda c: -c[1]):
    print(f"{cid:>8} {total:9.1f} MB")
```

Take two samples 30 seconds apart. A count of clients that matches the number of decoders plus one
already separates them. In the case above, 26 clients stayed at 17 MB each and one grew 816 MB. A low
`drm-shared` value on the growing client can mean it allocates its own buffers instead of importing them,
which held in that one case. A steady descriptor count rules out leaked file descriptors.

## Who allocates

`strace -f -e trace=ioctl` counts creations against releases per thread, which names the thread. On i915,
`GEM_CREATE` without `GEM_CLOSE` means buffers are only being added. See the `delphi-bpl` skill for attaching
under `ptrace_scope = 1`.

For the stacks, `strace -k` is too slow on a busy program. `bin/gem-log.c` is a small library that wraps
`ioctl` and isn't, and it also records the size of each buffer.

```sh
gcc -shared -fPIC -O1 -o gem-log.so "$REPO/bin/gem-log.c" -ldl
GEMLOG=gem.txt LD_PRELOAD=./gem-log.so ./program
```

Skip the first seconds, group the rest by stack and sum the sizes. Sizes can hint at what is being allocated.
Allocations of 512 KB and 256 KB in similar numbers looked like the Y and UV planes of a 704x480 NV12 frame,
but confirm that in the stacks. `bin/gem-log.c` only knows the i915 ioctl, so other drivers need their own
request from their DRM header.

## Resolving the stacks

Arch keeps debug files on its debuginfod server, and they can be fetched without installing anything. Use
the offsets from the stack (`libfoo.so(+0x1f789)`).

```sh
id=$(readelf -n /usr/lib/libgstgl-1.0.so.0 | awk '/Build ID/{print $3}')
curl -sSfL -o gstgl.dbg "https://debuginfod.archlinux.org/buildid/$id/debuginfo"
addr2line -f -i -C -e gstgl.dbg 0x1f789 0x1b1ef
```

`-i` also shows inlined frames. Those names lead to the source of the exact version, which is the next
thing to read. Other distributions run their own servers, so only the URL should change. The build ID
matches only the installed version, and a vendor's binary usually has no debug file to fetch.

## CPU, split by thread

A leak can come with a CPU cost that hides the cause. `/proc/PID/task/*/stat` has `utime` and `stime` for each
thread, in fields 14 and 15 counted from the start of the line. The thread name can contain spaces, so parse after
the last `)`, and remember that the numbering shifts if you cut the line there. Grouping by name shows which
threads cost the most, and kernel time in threads that should only be drawing is worth a profile.

```sh
perf record -e task-clock -c 2000000 -g -p "$PID" -o perf.data -- sleep 10
perf report -i perf.data --no-children --sort comm,dso,symbol --stdio -g none | head -40
```

Seeing kernel symbols needs `kernel.perf_event_paranoid=1`. In one case, threads in `ppoll` under
`g_main_loop_run` turned out to be watching the Wayland connection rather than delivering frames, and
`GST_GL_WINDOW=surfaceless` cut the app's CPU by about 45%.

## Isolating by layers

Cut the pipeline at different points and see where the growth starts. With GStreamer, `fakesink` takes the
frames and discards them.

```
src ! depay                           ! fakesink   network
src ! depay ! decoder                 ! fakesink   + decoding
src ! depay ! decoder ! glupload ! video/x-raw(memory:GLMemory) ! fakesink   + upload
```

**A clean result may only mean the layer didn't run.** Without the caps filter, `glupload` saw that
`fakesink` accepts anything and passed the buffers through without touching OpenGL, so it measured 0 MB/s
for doing nothing. The hint was GPU memory identical to the previous layer. Before trusting a cut, confirm
with an independent signal that the piece worked, such as the negotiated caps or memory that moved. The
same goes for any layer that can turn itself off when nothing consumes its output.

Also keep track of what each number measured. A pipeline may fall back to a copy path without an error, so
read which path it took in the log of the running program, not in a test that ends differently. In one
case `input not dmabuf` in the debug log contradicted a claim of zero copy that had come from such a test.
