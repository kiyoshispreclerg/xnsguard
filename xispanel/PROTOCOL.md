# xispanel protocol

One daemon per session, listening on a Unix socket:

```
$XDG_RUNTIME_DIR/xispanel-ctl.sock   (fallback: /tmp/xispanel-ctl.sock)
```

Single-instance coordination via flock on `$XDG_RUNTIME_DIR/xispanel.lock`.
No need to probe whether the daemon is already running: just try to connect
to the socket. If the connection fails, start `xispanel` (with no arguments
it comes up as the daemon, loading whatever panels/widgets/theme are in the
config file) and retry with a short backoff.

The socket is created mode `0600` (session-local only).

## Format

Each command is **one connection**: connect, write a single line of flat
JSON terminated with `\n`, read the response line, close. Unlike xisback's
tab-separated fixed-arity lines, xispanel's config objects are inherently
nested/variable-arity (a panel has an ordered list of widgets, each with
its own arbitrary key=value option set) -- line-JSON handles that shape
better, following the precedent set by xisguard's `xisguard-ctl` control
socket rather than xisback's `SET`-style protocol.

### Commands (current)

```
{"cmd":"PING"}
{"cmd":"GET_STATUS"}
{"cmd":"RELOAD"}
{"cmd":"QUIT"}
```

- `PING` -> `{"ok":true,"pong":true}`
- `GET_STATUS` -> `{"ok":true,"version":"0.1.0","panels":N}`
- `RELOAD` -> tears down every panel/widget and reloads
  `$XDG_CONFIG_HOME/xispanel.conf` from scratch, then reactivates every
  panel found in it. `{"ok":true}` on success.
- `QUIT` -> stops the daemon. `{"ok":true}`

Unknown commands get `{"ok":false,"error":"unknown command"}`.

### Commands (planned, not yet implemented)

Panel/widget/theme mutation over the socket (`ADD_PANEL`, `REMOVE_PANEL`,
`LIST_PANELS`, `LIST_WIDGETS`, `SET_WIDGET`, `REMOVE_WIDGET`, `SET_THEME`)
is a later phase, once there is something that actually persists a live
mutation back to the config file. Until then, panels/widgets/theme are
configured by editing the config file directly and sending `RELOAD`.

## Config file

`$XDG_CONFIG_HOME/xispanel.conf` (fallback `~/.config/xispanel.conf`),
read at startup and on `RELOAD`. Not currently written by the daemon
itself -- hand-edit it (or generate it from a future `xisconf` tab).

Three record types, one per line, fields separated by tabs. Blank lines
and lines starting with `#` are ignored.

```
PANEL	<name>	<output>	<key>=<value> ...
WIDGET	<panel>	<order>	<type>	<key>=<value> ...
THEME	<panel>	<key>=<value> ...
```

### `PANEL`

```
PANEL	top	*	edge=top	pct=100	thickness=32	mode=dock
```

- `<name>`: arbitrary identifier, referenced by `WIDGET`/`THEME` lines for
  this panel. Must be unique.
- `<output>`: `*` (falls back to the whole virtual screen bounding box) or
  an XRandR output name (e.g. `HDMI-1`, `DP-1`), same convention as
  xisback's `--output`.
- `edge`: `top` | `bottom` | `left` | `right` (default `top`).
- `pct`: 1-100, percentage of that edge's length the panel occupies,
  centered (default `100`).
- `thickness`: panel thickness in pixels along the cross axis (default
  `32`).
- `mode`: `dock` (reserves screen space via `_NET_WM_STRUT_PARTIAL`) |
  `overlay` (floats on top, no reserved space) | `autohide` (overlay,
  slides in on hover over a thin edge sensor and back out shortly after
  the pointer leaves). Default `dock`.
- `rotate`: `0` | `90` | `180` | `270` (default `0`). Rotates every
  widget's content as a rigid whole around the center of its on-panel
  slot -- works on *any* edge, not just left/right: `180` on a top panel
  just flips its content upside down; `90`/`270` on a top panel turns its
  (normally wide/short) content sideways to fit the same footprint. Most
  useful case: by default a `left`/`right` panel's widgets render upright
  and stacked (readable head-on, but text gets cramped into the panel's
  thickness -- fine for icon-only/compact widgets, poor for `clock`'s or
  `tasklist`'s wide-mode text); `rotate=90` or `rotate=270` turns that
  content sideways to read along the panel instead, same content a
  horizontal panel would draw, just rotated a quarter turn. Popups
  (context menu, tooltip) are never rotated -- they render normally just
  outside the panel either way.
- `tooltip_delay`: milliseconds of hover over a widget before its tooltip
  appears (default `500`). `0` makes it instant. Only matters for widgets
  that implement a tooltip at all -- see "Hover tooltips" below.

### `WIDGET`

```
WIDGET	top	0	spacer
WIDGET	top	1	clock	format=%H:%M	tz=America/Sao_Paulo
```

- `<panel>`: the `PANEL` name this widget belongs to.
- `<order>`: currently informational only -- widgets are laid out in the
  order their `WIDGET` lines appear in the file, left-to-right (or
  top-to-bottom for a vertical panel).
- `<type>`: one of the registered widget types (see below).
- remaining fields: widget-specific `key=value` options.

Widget types implemented so far:

- `spacer`: `size=<px>` for a fixed-width spacer, or omit `size` for a
  greedy spacer that fills whatever space is left, split evenly among
  every greedy spacer on the panel. A greedy spacer before a fixed-size
  widget right-aligns everything after it.
- `clock`: `format=<strftime format>` (default `%H:%M`). Updates once a
  second. No timezone popup yet.
- `tasklist`: `mode=wide|compact` (default `wide`). One button per
  top-level window from `_NET_CLIENT_LIST`, refreshed by polling every
  ~800ms. `wide` draws icon+title (Windows XP style, titles truncated
  with an ellipsis and capped at 180px); `compact` draws icon only
  (Windows 7 style). A small desktop-number badge is drawn on a task's
  icon when the session has more than one virtual desktop. Left-click
  activates a window (or minimizes it if it's already the active one,
  clicking again restores it); right-click opens a context menu
  (Minimizar/Maximizar/Mover/Fechar, plus Fixar/Desafixar). "Fixar" is
  currently a visual-only toggle for the running session -- a pinned
  entry does not yet survive its window closing and relaunch on click,
  since that needs `.desktop`-file lookup by `WM_CLASS`, which is
  launcher-phase territory. Windows of type `_NET_WM_WINDOW_TYPE_DESKTOP`/
  `_NET_WM_WINDOW_TYPE_DOCK` or carrying `_NET_WM_STATE_SKIP_TASKBAR` are
  never listed (desktop containment layers, other panels, xispanel's own
  panel windows). If the widget doesn't have room for every open window's
  button, it shrinks to as little as one button wide and shows a small
  up/down arrow pair (one task at a time) instead of overflowing the
  panel -- see "Widget sizing" below. `same_desktop=yes|no` (default
  `no`) restricts the list to windows on the current `_NET_CURRENT_DESKTOP`
  (ignored if the WM never sets that property). `minimized_only=yes|no`
  (default `no`) restricts it to only minimized windows. Both filters
  apply independently and can be combined; either just narrows the same
  `_NET_CLIENT_LIST` polling tasklist already does, not a different data
  source.
- `winctl`: active-window icon + title, plus configurable window-control
  buttons -- similar to KDE's "Active Window Control" plasmoid. Options:
  `buttons=<comma-list>` (any of `min`, `max`, `close`, in the order given
  -- default `min,max,close`), `show=maximized|always` (only show the
  buttons while the active window is maximized, or always -- default
  `maximized`), `side=start|end` (buttons before or after the icon/title,
  *within this widget* -- default `end`). The maximize button draws as a
  single square when the active window isn't maximized and as two
  overlapping squares (restore) when it is. Polls `_NET_ACTIVE_WINDOW`
  every ~300ms, same tradeoff as `tasklist`'s polling.

More widget types (tray, global menu, launcher, system monitor) are later
phases -- see the plan this tool was built from; they are not implemented
yet.

### Widget sizing

Every widget reports both a desired length and a minimum length from
`measure()`. `panel_layout()` gives each widget its desired length as long
as everything fits; once it doesn't, it shrinks widgets proportionally to
how much slack (desired minus minimum) each one has, never below any
widget's minimum. Widgets that can't meaningfully shrink (`clock`) report
`min == desired`; `spacer`'s minimum is always `0`, so it's the first
thing squeezed away. `tasklist`'s minimum is one button plus room for the
scroll-arrow pair described above -- if it's given less than its natural
width, it shows as many buttons as fit starting from its current scroll
position rather than clipping or overflowing.

### `THEME`

```
THEME	top	bg=#202020cc	fg=#eeeeee	spacing=6
```

- `bg`, `fg`: `#RRGGBB` or `#RRGGBBAA` (alpha only has a visible effect if
  the X server has a 32-bit ARGB visual available, i.e. a compositor is
  running -- otherwise the background renders fully opaque). Also used
  for the context menu and hover tooltip popups (see below) -- there's
  one color scheme per panel, not a separate one for its popups.
- `spacing`: pixels of gap between adjacent widgets (default `4`).
- `bg_image`: path to a PNG to use as the panel's background instead of
  the solid `bg` color, sliced 9-slice-style (see "PNG bitmap themes"
  below). If the file doesn't exist or fails to decode, xispanel logs a
  warning and falls back to the plain `bg`/`fg` color scheme -- a missing
  or broken theme file is never a startup-blocking error.
- `bg_slice`: path to that image's (optional) measurements sidecar file.
  Ignored if `bg_image` isn't set or didn't load. Missing/unreadable just
  means every inset defaults to 0 (a plain full-image stretch), not an
  error.

## PNG bitmap themes

`bg_image` replaces a panel's solid background color with a PNG,
9-slice-sliced to fit any panel thickness/length without looking
stretched-blurry at the corners: the image's four corners (sized by
`bg_slice`'s `left`/`top`/`right`/`bottom`, in source-image pixels) are
copied unscaled, the four edge strips between them stretch along one axis
each, and the middle stretches on both -- standard border-image
technique, also used by tint2, GTK, and CSS `border-image`. Real
per-pixel alpha in the PNG works exactly like `bg`'s `#RRGGBBAA` does:
visible transparency wherever a compositor is running, fully opaque
otherwise.

`bg_slice` is a tiny standalone text file (not part of `xispanel.conf`,
so a PNG + its measurements travel together as a shareable pair):

```
left=12
top=12
right=12
bottom=12
```

Any key can be omitted (defaults to `0`, meaning that side has no fixed
corner/edge -- a 0-everywhere file is equivalent to a plain stretch, no
9-slicing at all). Unknown lines are ignored.

[`themes/template.png`](themes/template.png) +
[`themes/template.slice`](themes/template.slice) are a starting point: a
48x48 image with clearly color-coded, semi-transparent corner/edge/center
regions and thin red guide lines exactly on the slice boundaries, so the
9 regions are visible at a glance. Paint over it (or start fresh at
whatever resolution you like) and delete the guide lines once you have a
real theme -- `bg_slice`'s numbers, not the image's actual size, are what
xispanel goes by, so the source image can be any resolution/aspect ratio.

Only the panel background is themeable this way for now -- widget/popup
chrome (buttons, tasklist rows, menu items) still draws with Cairo using
the panel's `fg`/`bg` colors, not bitmap art. Extending 9-slice theming
to those is a possible follow-up, not implemented yet.

## Context menus

Any widget can pop up a context menu for itself or one of its own
sub-items (e.g. `tasklist`'s per-window menu) via a generic popup system
shared by every widget type -- the menu code itself doesn't know or care
what the items mean, only how to draw/position/dismiss the popup. It's an
`override-redirect` window with an exclusive pointer+keyboard grab while
open: a click outside the menu's bounds, or Escape, dismisses it (a click
outside is *not* re-delivered to whatever was actually underneath it --
a known, accepted simplification; click again to interact with that).

The menu is positioned glued to the panel's outer edge (below a top
panel, above a bottom one, beside a left/right one) with its leading edge
aligned to whichever sub-item triggered it -- e.g. right-clicking a task
button opens the menu directly under *that button*, not at the raw click
coordinates -- same convention plasmashell's taskbar context menus use.

## Hover tooltips

Any widget can opt into a hover tooltip by implementing
`PanelWidgetOps.get_tooltip()` (optional -- widgets that don't are
unaffected, `spacer` doesn't implement it). After the pointer sits over a
widget (or one of its sub-items, e.g. one `tasklist` button) for the
panel's `tooltip_delay` (default 500ms, `0` = instant -- see `PANEL`
above), a small popup appears with whatever text the widget reports --
glued to the panel's outer edge and aligned with that specific item, the
same plasmashell-style positioning context menus use, so it never
overlaps the panel itself, and painted with the panel's own `bg`/`fg`
theme colors (same as the context menu -- one color scheme per panel, not
a separate one for its popups). Content refreshes about once a second
while shown, so e.g. `clock`'s tooltip keeps ticking even if the pointer
doesn't move.

Unlike the context menu, the tooltip takes no pointer/keyboard grab --
it's meant to coexist with normal desktop interaction, not take it over.
Every tooltip (whether interactive or not) shares one hover-intent
dismissal rule: leaving the source widget starts a ~200ms grace period
before it actually closes, cancelled if the pointer enters the popup
itself (there's no gap between panel and popup, so that's one continuous
motion) -- this lets an interactive tooltip's contents actually be
reachable with the mouse instead of vanishing the instant the pointer
leaves the panel.

A widget can additionally make its tooltip clickable by reporting
`*out_closable = 1` (+ an opaque `*out_ctx`) from `get_tooltip()` and
implementing `tooltip_activate()`/`tooltip_close_item()`: clicking the
popup's body then calls `tooltip_activate()` (e.g. focus the window it
describes), and a small close icon drawn in its corner calls
`tooltip_close_item()` (e.g. close that window) -- both close the popup
right after, mirroring `menu.c`'s select-and-close pattern. Widgets that
never touch `*out_closable` just get a plain read-only tooltip with no
close icon.

Currently implemented:

- `clock`: full weekday + date + seconds (`strftime("%A, %d de %B de
  %Y")` + `"%H:%M:%S"`), locale-aware (`setlocale(LC_TIME, "")` at
  startup) -- unlike the panel's short, locale-independent `format=`. Not
  clickable.
- `winctl`: the active window's full, untruncated title. Not clickable
  (the panel itself already has minimize/maximize/close buttons).
- `tasklist`: the hovered task's full, untruncated title, anchored to
  that specific button (not the whole widget, and never over the
  scroll-arrow pair). Clickable: clicking the tooltip body activates that
  window (`ewmh_activate`), the close icon closes it (`ewmh_close`) --
  same actions the button's own click/context-menu already expose, just
  reachable from the tooltip too, like plasmashell's taskbar tooltips.
  If the hovered task's window also owns an active MPRIS2 player (see
  below), its tooltip additionally shows previous/play-pause/next
  buttons.

### MPRIS media controls

`tasklist`'s tooltip shows previous/play-pause/next buttons when the
hovered window's PID (`_NET_WM_PID`) matches an active
`org.mpris.MediaPlayer2.*` player on the session bus (matched via
`org.freedesktop.DBus.GetConnectionUnixProcessID`) -- same idea as
plasmashell's taskbar tooltips showing media controls for whichever app
happens to be playing something.

This is the one place in xispanel that talks to DBus, and it's an
**optional runtime dependency**: `mpris.c` `dlopen()`s `libdbus-1.so.3`
and resolves every symbol it needs via `dlsym()` -- it is never linked at
build time (`ldd xispanel` shows no `libdbus`). A system with the
`dbus-1` dev headers available at build time (needed for `mpris.c` to
compile against `<dbus/dbus.h>`'s types) but no `libdbus-1.so.3`
installed at runtime just runs fine with MPRIS support silently
unavailable -- no crash, no startup failure, `tasklist`'s tooltip simply
never shows the extra buttons. Volume/mute control (PulseAudio/PipeWire)
is a separate, heavier dependency decision, deliberately not part of
this -- see the project notes.

Player discovery polls the bus every ~1.5s (`mpris_poll()`, called from
the main loop) rather than subscribing to DBus signals or folding
libdbus-1's file descriptor into the `select()` loop -- simpler, and a
media-control button doesn't need sub-second freshness. Every DBus call
uses a short (200ms) blocking timeout; this is a deliberate tradeoff
(documented in `mpris.c`) to avoid the far larger complexity of a real
async DBus main-loop integration for a best-effort feature.

Window thumbnails are a planned follow-up, gated on an active compositor
-- not implemented yet.

## Source layout

Following the plan's "widgets can be added/removed/reordered, each is its
own file" structure:

- `xispanel.c`: main, config parsing, IPC, the select() event loop, panel
  geometry/window/rendering/autohide/lifecycle, and the compile-time
  widget registry (an array of externs pointing at each widget's
  `PanelWidgetOps`).
- `xispanel.h`: shared `Panel`/`PanelWidget`/`PanelWidgetOps` types and
  the core API a widget file is built against (`now_ms`, `kv_get`,
  `widget_get_rect`, the `ewmh_*` helpers, `panel_menu_open`, ...).
- `ewmh.c`: EWMH/ICCCM client-list reading and window-control actions
  (activate/close/minimize/maximize/move), plus `_NET_WM_ICON` decoding
  and the icon/text drawing helpers built on top of it.
- `menu.c`: the generic context-menu popup described above.
- `tooltip.c`: the generic hover-tooltip popup described above.
- `mpris.c`: the optional (dlopen'd libdbus-1) MPRIS2 client described
  above.
- `widgets/spacer.c`, `widgets/clock.c`, `widgets/tasklist.c`,
  `widgets/winctl.c`: one file per widget type. Adding a new type is
  "write `widgets/foo.c` defining a `PanelWidgetOps foo_ops`, declare it
  `extern` in `xispanel.h`, add it to
  the registry array in `xispanel.c`" -- no other file needs to change.

## Design notes

- `overlay`/`autohide` panel windows are `override-redirect`: xispanel
  manages their own position/stacking rather than asking a window manager
  to, which is what makes the autohide slide animation reliable. `dock`
  mode panels are *not* override-redirect, on purpose: at least one
  real-world WM (this repo's KWin fork) only walks its list of managed
  clients when recomputing `_NET_WORKAREA`, so an override-redirect
  window's `_NET_WM_STRUT_PARTIAL` is set but silently never honored --
  reserving screen space requires being a real, WM-managed client. A dock
  panel sets `_NET_WM_WINDOW_TYPE_DOCK` (which every WM that matters here
  auto-disables decoration for), `WM_HINTS.input = False` (never wants
  keyboard focus, so click-to-focus can't steal it), and initial
  `_NET_WM_STATE_SKIP_TASKBAR`/`_NET_WM_STATE_SKIP_PAGER` +
  `_NET_WM_DESKTOP = -1` (all desktops) before the first map, same as any
  other well-behaved managed dock/panel application (plasmashell, tint2,
  polybar's `dock` mode) does.
- `autohide` panels start hidden (unmapped) and stay that way until the
  pointer enters a permanently-mapped, always-raised 1px sensor strip
  running the length of the configured edge. The full panel window then
  slides in over ~150ms, stays shown, and slides back out ~400ms after
  the pointer leaves it.
- Monitor hotplug (`RRScreenChangeNotify`) tears down and recreates every
  panel from the current config, same as a manual `RELOAD` -- simple and
  robust, at the cost of losing any in-flight autohide animation state
  across a hotplug (hotplug is rare enough that this doesn't matter in
  practice).
- Every panel's `cairo_t` is created once and reused across every
  repaint, not recreated per frame. Cairo hard-fails (and stays failed --
  `cairo_save`/`cairo_restore` become no-ops too) on invalid UTF-8 passed
  to text functions, and window-supplied text (titles, `WM_CLASS`, ...)
  is not guaranteed to be well-formed even where the spec says it should
  be. `ewmh_get_title()` sanitizes to valid UTF-8, `trim_to_width()` never
  truncates mid-codepoint, and `panel_repaint()` recreates the `cairo_t`
  outright if it ever ends up in an error state anyway -- defense in
  depth, since a single bad frame blanking a panel forever would be a
  much worse failure mode than one widget occasionally not repainting.
- `widget_get_rect()` always returns a *local*, `(0,0)`-anchored
  rectangle -- a widget never knows its own on-panel position, the
  panel's edge, or its `rotate` angle. `panel_repaint()` computes each
  widget's real physical on-panel rectangle, then does
  `cairo_translate` (to its center) + `cairo_rotate(rotate degrees)` +
  `cairo_translate` (back by half the *possibly-transposed* content
  size) around its `paint()` call -- rotating about the rect's own
  center is what makes one formula handle every edge/angle combination
  without special-casing any of the four angles. This is also why
  `rotate` needs zero per-widget code: at 90/270 `widget_get_rect()`
  reports that physical rectangle transposed (width/height swapped), so
  every widget (text, icons, `tasklist`'s scroll arrows, `winctl`'s
  buttons) paints exactly as it always does into what it thinks is an
  ordinary axis-aligned strip -- the rotation is a rigid transform of
  that same drawing, applied once, outside any widget's knowledge.
  Hit-testing (`dispatch_button`'s `local_x`, `tasklist`'s per-button
  indices) is computed from the panel's real, physical, *unrotated*
  main-axis extent and is therefore completely unaffected by this --
  rotation is a rendering-only transform.
- Every panel repaints into an offscreen `cairo_image_surface_t` first
  (`Panel::buf_surface`/`buf_cr`), then blits the finished frame onto the
  real, on-screen `cairo_xlib_surface_t` with a single `cairo_paint()`.
  Painting widgets directly onto the on-screen surface sent each widget's
  fills/strokes as its own X request, which a compositor could pick up
  mid-repaint -- visible as flicker, worst on `tasklist` since it repaints
  on every ~800ms poll tick even when nothing actually changed.
