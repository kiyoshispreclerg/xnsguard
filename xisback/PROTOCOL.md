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
SET\t<output>\t<desktop>\t<mode>\t<interval>\t<shuffle>\t<fade_ms>\t<path>\n
CLEAR\t<output>\t<desktop>\n
CLEARALL\n
LIST\n
NEXT\t<output>\t<desktop>\n
ACTIONS\n
SETACTIONS\t<left>\t<right>\t<middle>\t<double>\n
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
- `<fade_ms>`: crossfade duration on image switch, in milliseconds, from `0`
  (instant swap) to `5000` (5s). Out-of-range values are clamped by the
  daemon. See "Crossfade" below for how it's implemented.
- `<path>`: path to an image file, or to a folder (in which case every file
  with an image extension inside it becomes a slide, in alphabetical or
  random order per `<shuffle>`).

`(output, desktop)` is the key: a repeated `SET` with the same
`(output, desktop)` pair **replaces** the existing layer (swaps
image/folder, repositions if needed) instead of creating a new one.

`NEXT` advances that exact layer's slideshow immediately (same effect as
its interval timer firing right now, including a crossfade if configured)
and resets the timer; it's a no-op (still `OK`) if the layer is a single
image or `interval` is `0` — there's nothing to advance to. `ACTIONS` and
`SETACTIONS` read/write the four click-action commands described in "Click
actions" below; they're global, not per-layer, so they take no
`output`/`desktop` arguments.

### Responses

- `OK\n` — success, no extra body.
- `ERR <message>\n` — failure, human-readable message in English.
- `PONG\n` — response to `PING`.
- For `LIST`: zero or more lines, one per active layer, same field format
  as `SET` (without the leading `SET\t`):
  `output\tdesktop\tmode\tinterval\tshuffle\tfade_ms\tpath\n`.
  Connection closes (EOF) at the end of the list.
- For `ACTIONS`: one line, `left\tright\tmiddle\tdouble\n` — the four
  command strings currently bound (empty string for an unbound slot).

## Crossfade

When `<fade_ms>` is greater than 0 and the layer already had a window
showing something, the switch to the new image is animated instead of
instant: the daemon draws the new image into a second window stacked above
the current one and animates its `_NET_WM_WINDOW_OPACITY` property from 0 to
full opacity over `<fade_ms>` milliseconds (~30 steps/second), then destroys
the old window. The actual alpha blending is done by the compositor (KWin)
on the GPU — the daemon never touches pixel data for the animation, it just
decodes the new image once (same cost as an instant switch) and nudges a
window property periodically. A geometry change forced by a monitor
reconfiguration (RandR) snaps any in-flight crossfade to its final state
immediately rather than animating, since there's no "old" content to fade
from in that case. `<fade_ms>` is clamped to `[0, 5000]` by the daemon
regardless of what a client sends.

## Click actions

Each layer's window accepts left/right/middle clicks and double-clicks
(any button). What happens on click is **global** to the daemon, not
per-layer: four shell command strings (`left`, `right`, `middle`,
`double`), run via `sh -c "<cmd>"` when the corresponding click lands on
*any* layer's window. An empty string means no action for that slot
(the common case, and the default).

The command runs detached (the daemon doesn't wait for it) with two
environment variables set to identify which layer was actually clicked:
`XISBACK_OUTPUT` and `XISBACK_DESKTOP` (same values as that layer's
`<output>`/`<desktop>`). This is what makes a *generic* "next wallpaper"
binding work without the daemon needing a special built-in for it — bind
`xisback --next` as the command, and since `--next` falls back to
`$XISBACK_OUTPUT`/`$XISBACK_DESKTOP` when `--output`/`--desktop` aren't
passed explicitly, it advances whichever layer was clicked.

Double-click detection needs to briefly hold back the single-click action
to see if a second click of the same button arrives within 400ms — but
only when a `double` command is actually configured; with no double-click
binding, single clicks fire the instant the button goes down, no delay.

Command strings must not contain literal tab or newline characters (they're
flattened to spaces if you try) since they travel as tab-separated protocol
fields and newline-terminated config lines; point a command at a script if
you need something more elaborate than a one-liner.

## Persistence

On every successful `SET`, `CLEAR`, `CLEARALL`, or `SETACTIONS`, the daemon
rewrites `$XDG_CONFIG_HOME/xisback.conf` (fallback `~/.config/xisback.conf`)
with one `LAYER\t...` line per active layer (same fields as `SET`, plus the
leading tag) and one `ACTIONS\t...` line for the click bindings. On
startup, before processing command-line arguments, the daemon reads that
file and replays each line (`SET` for `LAYER` lines, `SETACTIONS` for the
`ACTIONS` line), restoring the previous session's state — so a plain
`xisback` invoked with no arguments (e.g. from a login autostart entry)
comes back up with the last configured wallpaper/slideshow and click
bindings instead of a blank desktop until someone reconfigures it.
Pre-0.4 config files (unprefixed layer lines, no click actions) are still
read on first load for a smooth upgrade; they get rewritten in the new
tagged format on the next change.

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

# single wallpaper for everything, default 1s crossfade
send("SET\t*\t*\tfill\t300\t0\t1000\t/home/kiyoshi/Pictures/wall.jpg")

# one per output, instant switch (no crossfade)
send("SET\tDP-1\t*\tfill\t300\t0\t0\t/home/kiyoshi/Pictures/dp1.jpg")
send("SET\tHDMI-1\t*\tfill\t300\t0\t0\t/home/kiyoshi/Pictures/hdmi1.jpg")

# slideshow only on desktop 2, output DP-1, switching every 10 minutes,
# in random order, with a slow 3s crossfade
send("SET\tDP-1\t2\tfill\t600\t1\t3000\t/home/kiyoshi/Pictures/slideshow/")

# remove a specific layer
send("CLEAR\tHDMI-1\t*")

# go back to "one wallpaper for everything": clear before recreating the global layer
send("CLEARALL")
send("SET\t*\t*\tfill\t300\t0\t1000\t/home/kiyoshi/Pictures/wall.jpg")

print(send("LIST"))

# left-click advances whatever layer was clicked; double-click shows a
# notification with which output/desktop it was; right/middle left unbound
send("SETACTIONS\txisback --next\t\t\tnotify-send \"clicked $XISBACK_OUTPUT / $XISBACK_DESKTOP\"")

print(send("ACTIONS"))
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
