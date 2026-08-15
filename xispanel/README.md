# XisPanel

**XisPanel** is a lightweight desktop panel/taskbar daemon for X11, built
to replace heavyweight panels (plasmashell, liquidshell) with something
that stays fast even under a compositing window manager.

No toolkit: plain Xlib for windowing/RandR, Cairo (cairo-xlib, no
Pango/GLib) for vector rendering and text via FreeType/Fontconfig, and
Imlib2 for image decoding -- the same dependency spirit as
[XisBack](../xisback) and [XisGuard](../xisguard).

Text uses whatever font family the desktop itself is configured with --
`~/.config/kdeglobals`'s `[General] font=` on Plasma, falling back to
`~/.config/gtk-3.0/settings.ini`'s `gtk-font-name=` on GTK-based desktops,
and finally Fontconfig's own `sans-serif` default if neither file exists
-- read directly (no Qt/GTK linked) once at startup. See
[PROTOCOL.md](PROTOCOL.md)'s "Design notes" section.

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
  `winctl` (active window's icon/title + configurable
  minimize/maximize/close buttons, similar to KDE's Active Window Control
  -- see [PROTOCOL.md](PROTOCOL.md)), `tray` (StatusNotifierItem system
  tray -- xispanel becomes the watcher if none exists yet, or coexists as
  a second host if one already does), `launcher` (a single user-defined
  clickable icon: `icon=`/`name=`/`cmd=` plus per-button/scroll
  variants, no `.desktop` parsing), and `volume` (default sink level/mute,
  scroll to adjust, shells out to `pactl` -- no libpulse linked).
- Widgets that don't fit the panel's available space shrink toward a
  per-type minimum instead of overflowing it (see PROTOCOL.md's "Widget
  sizing").
- A generic context-menu popup any widget can use for itself or a
  sub-item, not just the panel as a whole -- glued to the panel edge and
  aligned to the triggering item, plasmashell-style.
- A generic hover-tooltip popup, same positioning convention, opt-in per
  widget (`clock`: full date/weekday; `winctl`/`tasklist`: full window
  title). `tasklist`'s is also clickable: click it to activate the
  window, or its corner close icon to close it. `tasklist`'s
  `show_thumbs=yes` adds a live window thumbnail (XComposite -- no
  dependency at all if `libxcomposite-dev` isn't installed, no
  thumbnail if no compositor is running).
- Basic theming: background/foreground color with alpha (real per-pixel
  transparency when a compositor provides an ARGB visual), spacing. A
  panel's background can also be a 9-slice PNG instead of a solid color
  (`bg_image=`/`bg_slice=` -- see [themes/](themes/) for a starting
  template and [PROTOCOL.md](PROTOCOL.md)'s "PNG bitmap themes"), falling
  back to the plain color scheme if the image is missing or fails to
  load.
- A control socket (see [PROTOCOL.md](PROTOCOL.md)) for `PING`,
  `GET_STATUS`, `RELOAD`, `QUIT`.

Everything else this tool is meant to eventually do -- global menu,
window thumbnails, application launcher, system monitor -- is **not
implemented yet**. See the phased plan this was built from, and
[PROTOCOL.md](PROTOCOL.md)'s "Source layout" section for how a new widget
type gets added.

### Dependencies

- libX11, libXrandr
- Cairo with the `cairo-xlib` backend
- Imlib2
- FreeType2, Fontconfig
- dbus-1 (optional, build-time headers only -- see below)

On Debian/Ubuntu: `libx11-dev libxrandr-dev libcairo2-dev libimlib2-dev
libfreetype6-dev libfontconfig1-dev`, plus `libdbus-1-dev` if you want
MPRIS/tray support.

MPRIS media controls (previous/play-pause/next buttons in `tasklist`'s
tooltip for whatever window owns an active media player) and the `tray`
widget (StatusNotifierItem system tray) are both **fully optional**, at
both build time and runtime -- `xispanel` compiles and runs fine on a
system with none of `libdbus-1-dev`/`libdbus-1.so.3` installed at all,
it just silently doesn't offer those two features:

- **Build time**: the Makefile checks `pkg-config --exists dbus-1` and,
  if it's missing, links `mpris_stub.c`/`sni_stub.c` (harmless no-ops
  with identical signatures) instead of `mpris.c`/`sni.c` -- no
  `<dbus/dbus.h>` ever gets `#include`'d, so `libdbus-1-dev` isn't
  needed to build at all in that case.
- **Runtime**: even when `mpris.c`/`sni.c` *are* built (dbus-1-dev was
  present), neither links `libdbus-1.so.3` directly -- both `dlopen()`
  it, so a system with the dev headers at build time but no
  `libdbus-1.so.3` installed at runtime still runs fine too. See
[PROTOCOL.md](PROTOCOL.md)'s "MPRIS media controls" and "System tray
(StatusNotifierItem)" sections.

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
