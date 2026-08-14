# XisPanel

**XisPanel** is a lightweight desktop panel/taskbar daemon for X11, built
to replace heavyweight panels (plasmashell, liquidshell) with something
that stays fast even under a compositing window manager.

No toolkit: plain Xlib for windowing/RandR, Cairo (cairo-xlib, no
Pango/GLib) for vector rendering and text via FreeType/Fontconfig, and
Imlib2 for image decoding -- the same dependency spirit as
[XisBack](../xisback) and [XisGuard](../xisguard).

### Status

**Early / core only.** What works right now:

- One or more panels, each anchored to an edge (top/bottom/left/right) of
  a chosen XRandR output (or the whole virtual screen), sized by a
  percentage of that edge plus a configurable thickness.
- Three behavior modes: `dock` (reserves screen space via
  `_NET_WM_STRUT_PARTIAL`), `overlay` (floats above everything, no
  reserved space), `autohide` (overlay that slides in on hover and back
  out shortly after).
- A small widget system (compile-time registry, no plugins/dlopen) with
  two widget types so far: `spacer` (fixed or greedy/fill) and `clock`.
- Basic theming: background/foreground color with alpha (real per-pixel
  transparency when a compositor provides an ARGB visual), spacing.
- A control socket (see [PROTOCOL.md](PROTOCOL.md)) for `PING`,
  `GET_STATUS`, `RELOAD`, `QUIT`.

Everything else this tool is meant to eventually do -- system tray,
global menu, task list with window thumbnails and media controls,
application launcher, system monitor -- is **not implemented yet**. See
the phased plan this was built from for what's next.

### Dependencies

- libX11, libXrandr
- Cairo with the `cairo-xlib` backend
- Imlib2
- FreeType2, Fontconfig

On Debian/Ubuntu: `libx11-dev libxrandr-dev libcairo2-dev libimlib2-dev
libfreetype6-dev libfontconfig1-dev`.

### How to Compile and Install

`make`

`sudo make install`

### How to Use

`xispanel` with no arguments runs as the daemon, loading
`$XDG_CONFIG_HOME/xispanel.conf` (fallback `~/.config/xispanel.conf`). If
that file doesn't exist yet, it comes up with no panels -- create the
file (see [PROTOCOL.md](PROTOCOL.md) for the format) and send `--reload`,
or just restart it.

```
xispanel --reload    # tell the running daemon to reload its config
xispanel --quit      # stop the running daemon
xispanel --version
```

Example config:

```
PANEL	top	*	edge=top	pct=100	thickness=32	mode=dock
WIDGET	top	0	spacer
WIDGET	top	1	clock	format=%H:%M
THEME	top	bg=#202020cc	fg=#eeeeee	spacing=6
```
