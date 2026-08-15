# XisPanel

**XisPanel** is a lightweight desktop panel/taskbar daemon for X11, built
to replace heavyweight panels (plasmashell, liquidshell) with something
that stays fast even under a compositing window manager.

No toolkit: plain Xlib for windowing/RandR, Cairo (cairo-xlib, no
Pango/GLib) for vector rendering and text via FreeType/Fontconfig, and
Imlib2 for image decoding -- the same dependency spirit as
[XisBack](../xisback) and [XisGuard](../xisguard).

### Status

**Early.** What works right now:

- One or more panels, each anchored to an edge (top/bottom/left/right) of
  a chosen XRandR output (or the whole virtual screen), sized by a
  percentage of that edge plus a configurable thickness.
- Three behavior modes: `dock` (reserves screen space via
  `_NET_WM_STRUT_PARTIAL`), `overlay` (floats above everything, no
  reserved space), `autohide` (overlay that slides in on hover and back
  out shortly after).
- `rotate=0|90|180|270`: turns every widget's content sideways (or
  upside down) as a rigid whole, on any edge -- e.g. a left/right panel's
  text reading along the panel instead of cramped into its thickness.
- A small widget system (compile-time registry, no plugins/dlopen), each
  type in its own file under [widgets/](widgets/): `spacer` (fixed or
  greedy/fill), `clock`, `tasklist` (EWMH-based, wide/compact modes,
  per-window context menu with minimize/maximize/move/close/pin, shrinks
  to a scrollable strip with an up/down arrow pair when it doesn't fit),
  and `winctl` (active window's icon/title + configurable
  minimize/maximize/close buttons, similar to KDE's Active Window Control
  -- see [PROTOCOL.md](PROTOCOL.md)).
- Widgets that don't fit the panel's available space shrink toward a
  per-type minimum instead of overflowing it (see PROTOCOL.md's "Widget
  sizing").
- A generic context-menu popup any widget can use for itself or a
  sub-item, not just the panel as a whole -- glued to the panel edge and
  aligned to the triggering item, plasmashell-style.
- A generic hover-tooltip popup, same positioning convention, opt-in per
  widget (`clock`: full date/weekday; `winctl`/`tasklist`: full window
  title). `tasklist`'s is also clickable: click it to activate the
  window, or its corner close icon to close it. Window thumbnails are a
  planned follow-up.
- Basic theming: background/foreground color with alpha (real per-pixel
  transparency when a compositor provides an ARGB visual), spacing. A
  panel's background can also be a 9-slice PNG instead of a solid color
  (`bg_image=`/`bg_slice=` -- see [themes/](themes/) for a starting
  template and [PROTOCOL.md](PROTOCOL.md)'s "PNG bitmap themes"), falling
  back to the plain color scheme if the image is missing or fails to
  load.
- A control socket (see [PROTOCOL.md](PROTOCOL.md)) for `PING`,
  `GET_STATUS`, `RELOAD`, `QUIT`.

Everything else this tool is meant to eventually do -- system tray,
global menu, window thumbnails, media controls, application launcher,
system monitor -- is **not implemented yet**. See the phased plan this
was built from, and [PROTOCOL.md](PROTOCOL.md)'s "Source layout" section
for how a new widget type gets added.

### Dependencies

- libX11, libXrandr
- Cairo with the `cairo-xlib` backend
- Imlib2
- FreeType2, Fontconfig
- dbus-1 (build-time headers only -- see below)

On Debian/Ubuntu: `libx11-dev libxrandr-dev libcairo2-dev libimlib2-dev
libfreetype6-dev libfontconfig1-dev libdbus-1-dev`.

MPRIS media controls (previous/play-pause/next buttons in `tasklist`'s
tooltip for whatever window owns an active media player) are the one
optional *runtime* dependency: `libdbus-1-dev` is needed to **build**
xispanel (for `<dbus/dbus.h>`'s types), but `libdbus-1.so.3` is never
linked -- it's `dlopen()`'d at runtime, so a system without it installed
still runs xispanel fine, just without those buttons. See
[PROTOCOL.md](PROTOCOL.md)'s "MPRIS media controls" section.

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
WIDGET	top	0	tasklist	mode=wide
WIDGET	top	1	spacer
WIDGET	top	2	winctl	buttons=min,max,close	show=maximized
WIDGET	top	3	clock	format=%H:%M
THEME	top	bg=#202020cc	fg=#eeeeee	spacing=6
```
