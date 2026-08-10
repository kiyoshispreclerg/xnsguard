# xisback protocol

One daemon per session, listening on a Unix socket:

```
$XDG_RUNTIME_DIR/xisback.sock   (fallback: /tmp/xisback.sock)
```

Single-instance coordination via flock on `$XDG_RUNTIME_DIR/xisback.lock`.
No need to probe whether the daemon is already running: just try to connect
to the socket. If the connection fails, start `xisback` (with no arguments
it comes up as an empty daemon waiting for commands) and retry with a short
backoff (the binary itself already does this when invoked from the command
line).

## Format

Each command is **one connection**: connect, write a line terminated with
`\n`, `shutdown(SHUT_WR)` (or just close after writing), read the response
until EOF, close. Fields are separated by `\t` (tab).

### Commands

```
SET\t<output>\t<desktop>\t<mode>\t<interval>\t<shuffle>\t<path>\n
CLEAR\t<output>\t<desktop>\n
CLEARALL\n
LIST\n
PING\n
QUIT\n
```

- `<output>`: `*` (spans the whole virtual screen) or the name of an xrandr
  output (e.g. `HDMI-1`, `DP-1`). Invalid names fall back to full screen
  (with a warning on the daemon's stderr).
- `<desktop>`: `*` (sticky, shown on every virtual desktop) or a 0-based
  integer (KWin/NETWM desktop index).
- `<mode>`: `fill` (fills the window, cropping the excess, keeps aspect
  ratio) or `stretch` (stretches without keeping aspect ratio).
- `<interval>`: seconds between slideshow switches. Only matters when
  `<path>` is a folder with more than one image; ignored for a single file.
- `<shuffle>`: `0` (alphabetical order, default) or `1` (random order,
  reshuffled every time it completes a full pass through the folder). Only
  matters for slideshows.
- `<path>`: path to an image file, or to a folder (in which case every file
  with an image extension inside it becomes a slide, in alphabetical or
  random order per `<shuffle>`, no crossfade).

`(output, desktop)` is the key: a repeated `SET` with the same
`(output, desktop)` pair **replaces** the existing layer (swaps
image/folder, repositions if needed) instead of creating a new one.

### Responses

- `OK\n` — success, no extra body.
- `ERR <message>\n` — failure, human-readable message in English.
- `PONG\n` — response to `PING`.
- For `LIST`: zero or more lines, one per active layer, same field format
  as `SET` (without the leading `SET\t`):
  `output\tdesktop\tmode\tinterval\tshuffle\tpath\n`.
  Connection closes (EOF) at the end of the list.

## Persistence

On every successful `SET`, `CLEAR`, or `CLEARALL`, the daemon rewrites
`$XDG_CONFIG_HOME/xisback.conf` (fallback `~/.config/xisback.conf`) with one
line per active layer, in the same field format as `LIST` (no command
prefix). On startup, before processing command-line arguments, the daemon
reads that file and replays each line as a `SET`, restoring the previous
session's state — so a plain `xisback` invoked with no arguments (e.g. from
a login autostart entry) comes back up with the last configured
wallpaper/slideshow instead of a blank desktop until someone reconfigures
it.

## Python example

```python
import socket, os

def send(cmd: str) -> str:
    path = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "xisback.sock")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(path)
        s.sendall(cmd.encode() + b"\n")
        s.shutdown(socket.SHUT_WR)
        return b"".join(iter(lambda: s.recv(4096), b"")).decode()

# single wallpaper for everything
send("SET\t*\t*\tfill\t300\t0\t/home/kiyoshi/Pictures/wall.jpg")

# one per output
send("SET\tDP-1\t*\tfill\t300\t0\t/home/kiyoshi/Pictures/dp1.jpg")
send("SET\tHDMI-1\t*\tfill\t300\t0\t/home/kiyoshi/Pictures/hdmi1.jpg")

# slideshow only on desktop 2, output DP-1, switching every 10 minutes,
# in random order
send("SET\tDP-1\t2\tfill\t600\t1\t/home/kiyoshi/Pictures/slideshow/")

# remove a specific layer
send("CLEAR\tHDMI-1\t*")

# go back to "one wallpaper for everything": clear before recreating the global layer
send("CLEARALL")
send("SET\t*\t*\tfill\t300\t0\t/home/kiyoshi/Pictures/wall.jpg")

print(send("LIST"))
```

## Important rule: don't overlap layers

The program **does not validate overlap**. `(output=*, desktop=*)` covering
the whole screen at the same time as `(output=DP-1, desktop=*)` covering
part of it is an inconsistent configuration (the two windows will compete
for the same region, stacking order between them is not guaranteed). When
switching from "one global wallpaper" to "one per output" (or per desktop),
the UI should send `CLEARALL` before recreating the layers under the new
scheme, to make sure every point of the screen, on every desktop, is
covered by at most one layer.

## Multi-monitor and KWin's render loop

Each layer with a specific `output` becomes a window sized exactly to that
CRTC's geometry (via `XRRGetCrtcInfo`), so when there's different content
per monitor the natural split is already "one window per output" — they
never overlap spatially, so stacking order between them doesn't matter.
This doesn't interfere with KWin's per-output render loop: the compositor
decides what to composite for each screen based on each window's geometry,
not the number of windows — one big window covering two monitors or two
small windows each covering its own monitor cost, in practice, the same
total VRAM texture area (the sum of the areas is the same); the only
difference is that without a specific `output` you can't show different
images per screen.
