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
read at startup and on `RELOAD`. Not otherwise written by the daemon
itself -- hand-edit it (or generate it from a future `xisconf` tab) --
except once, on first run: if the file doesn't exist yet at all, the
daemon writes a minimal default (rather than silently starting with zero
panels, which looks exactly like it isn't working) -- one panel at the
bottom edge of the RandR primary output (or `*`, the whole virtual
screen, if no primary is set -- equivalent on a single-monitor session
anyway), with `launcher`+`tasklist` on the left and `tray`+`clock` pushed
to the right by a `spacer` in between. Deliberately no `THEME` line and
no font in that generated file: colors/font aren't copied in at
generation time (which would just go stale the next time the system
theme changes) -- see "Colors and font default to the live system theme"
below.

Three record types, one per line, fields separated by any run of spaces
and/or tabs (mix freely, including within the same line -- there's no
semantic difference, so hand-editing with a normal spacebar works just as
well as tabs). Blank lines and lines starting with `#` are ignored.

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
- `tooltip_close_delay`: milliseconds of grace after the pointer leaves the
  widget or the tooltip popup before it actually closes (default `300`,
  a bit less than the open delay). `0` closes instantly. Lets the pointer
  cross from the widget into the popup itself (e.g. to click something in
  it) without the popup vanishing out from under it.
- `tooltip_reuse`: `0` (default) or `1`. When `1`, moving the pointer from
  one tooltip-bearing widget straight to another reuses the same X window
  (`XMoveResizeWindow` + `cairo_xlib_surface_set_size`, then a full
  repaint) instead of destroying and recreating it. The window is still
  destroyed for real once the tooltip actually closes (pointer leaves the
  panel/popup for `tooltip_close_delay`), so this doesn't change memory
  behavior over time -- it only avoids a create/destroy pair on every
  widget-to-widget hover. The point is compositor-visual: a same-window
  move/resize lets effects like KWin's "Geometry Change" animate the
  transition smoothly, instead of the flicker a window create+destroy
  causes. Off by default since not every compositor has that effect, and
  a briefly-reused window keeping the previous item's content on screen
  during the new item's `tooltip_delay` is a visible (if intentional)
  behavior change from the default create/destroy-per-item flow.

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
- remaining fields: widget-specific `key=value` options. A value may be
  wrapped in double quotes to embed spaces, e.g. `launcher`'s
  `cmd="xterm -e htop"` -- there's no escaping inside the quotes (a value
  can't contain a literal `"`), which nothing needs so far.

Widget types implemented so far:

- `spacer`: `size=<px>` for a fixed-width spacer, or omit `size` for a
  greedy spacer that fills whatever space is left, split evenly among
  every greedy spacer on the panel. A greedy spacer before a fixed-size
  widget right-aligns everything after it.
- `clock`: `format=<strftime format>` (default `%H:%M`). Updates once a
  second. `tz=<IANA zone, e.g. America/Sao_Paulo>` (default: empty, meaning
  the system's own configured zone) overrides just this widget's displayed
  time -- e.g. a second panel/output showing a different zone. There's no
  portable `localtime_r()`-in-an-arbitrary-zone call, so this uses the
  standard workaround of pointing `TZ` at the target zone, calling
  `tzset()`, reading the time, then restoring `TZ` exactly as it was.
  `tooltip_tz=<zone1,zone2,...>` lists additional zones to show in the
  tooltip, each as its own date+time block separated by a blank line;
  without it the tooltip just shows one weekday/date/time block for the
  widget's own zone (`tz=` or system default).
- `tasklist`: `mode=wide|compact` (default `wide`). One button per
  top-level window from `_NET_CLIENT_LIST`, refreshed by polling every
  ~800ms. `wide` draws icon+title (Windows XP style, titles truncated
  with an ellipsis and capped at 180px); `compact` draws icon only
  (Windows 7 style). `show_desktop_badge=yes|no` (default `no`) draws a
  small desktop-number badge on a task's icon when the session has more
  than one virtual desktop; off by default to keep icons uncluttered.
  Every visible
  task's on-screen button rectangle is also written to its window's
  `_NET_WM_ICON_GEOMETRY` on every repaint -- the same property KWin/
  Compiz/etc. read to decide where a minimize/unminimize animation should
  end/start, instead of defaulting to the pointer position (exact for
  `rotate=0/180`; an approximation at `90/270` since content is
  transposed there, acceptable for what's only an animation-endpoint
  hint). Left-click
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
  (ignored if the WM never sets that property). `same_output=yes|no`
  (default `no`) restricts the list to windows whose center falls on this
  panel's own resolved output rectangle (`Panel::out_x/y/w/h`) -- useful
  in multi-monitor setups so a per-output panel only lists that monitor's
  windows; a no-op for `output=*` panels, since every window's center is
  necessarily inside the full virtual screen. `minimized_only=yes|no`
  (default `no`) restricts it to only minimized windows. All three filters
  apply independently and can be combined; each just narrows the same
  `_NET_CLIENT_LIST` polling tasklist already does, not a different data
  source. `icon_padding=<px>` (default `0`) shrinks each task's icon by
  that many pixels on every side instead of it always filling the whole
  button height. `show_thumbs=yes|no` (default `no`) adds a live
  thumbnail of the hovered task's window to its tooltip (see "Window
  thumbnails" below); clicking the thumbnail activates the window, same
  as clicking anywhere else in a closable tooltip. `group=yes|no` (default
  `no`) collapses windows sharing the same `WM_CLASS` (the general
  "which application" half of it, `res_class` -- not the per-instance
  name) into a single button, with a small count badge (bottom-left of
  the icon, the one corner the pin dot and desktop badge never use).
  Grouping is applied *after* `same_desktop`/`same_output`/
  `minimized_only` already narrowed the list down, so it only ever
  collapses buttons that would otherwise already sit side by side on this
  panel -- never reaches across a filter to pull in a window this panel
  wouldn't otherwise show. This is the same signal simple non-Plasma
  taskbars (xfce4-panel, tint2) group by; KWin itself doesn't group
  windows -- that's Plasma's Task Manager applet, which prefers a
  window's `.desktop`-file match (`StartupWMClass`) over raw `WM_CLASS`
  when one's known. xispanel has no `.desktop`-matching yet (launcher-
  phase territory), so `WM_CLASS` is the whole story for now. The button
  shown for a group displays whichever member is currently active (or the
  first member found, if none is); left/right-click always act on that
  representative window, same as an ungrouped button -- picking a
  *different* member is done via the tooltip (see below), not a separate
  click target. Hovering a grouped button shows every member: a row of
  live thumbnails with title + close icon under each if a compositor is
  running, or a stacked list of title + close icon per row otherwise
  (wraps into more columns rather than growing past the output's height);
  either way every entry activates its window on click and closes it via
  its own close icon, independent of the others. If there isn't room for
  every member even after wrapping, the grid caps out with a trailing
  "+N mais" cell rather than silently dropping members with no
  indication more exist.
- `winctl`: active-window icon + title, plus configurable window-control
  buttons -- similar to KDE's "Active Window Control" plasmoid. Options:
  `buttons=<comma-list>` (any of `min`, `max`, `close`, in the order given
  -- default `min,max,close`), `show=maximized|always` (only show the
  buttons while the active window is maximized, or always -- default
  `maximized`), `side=start|end` (buttons before or after the icon/title,
  *within this widget* -- default `end`). The maximize button draws as a
  single square when the active window isn't maximized and as two
  overlapping squares (restore) when it is. `same_desktop=yes|no` and
  `same_output=yes|no` (both default `no`, same semantics as `tasklist`'s
  filters above) make the whole widget render as empty (or `fallback=`
  content, see below) whenever the active window doesn't match -- e.g.
  `same_output=yes` on a per-output panel hides icon/title/buttons while
  focus is on another monitor, instead of showing controls for a window
  this panel doesn't "own". `_NET_ACTIVE_WINDOW` pointing at a desktop/
  dock/skip-taskbar window (same categories `tasklist` already excludes
  from its own list -- e.g. clicking the desktop itself) never applies
  either. `width=<px>` or `width=<pct>%` (default unset -- auto width,
  the widget grows with the title's length up to 220px, then grows again
  when the buttons become visible) pins the widget to always exactly
  that wide instead, in raw pixels or as a percentage of the panel's own
  main-axis length (re-resolved against the panel's *current* size on
  every `measure()`, so it tracks RandR/output geometry changes rather
  than freezing at whatever it resolved to at startup): the title is
  ellipsized into whatever room icon+buttons leave, and shows nothing at
  all if there's no room left, rather than ever resizing the widget
  itself -- keeps whatever's drawn after `winctl` in the panel from
  shifting position every time the active window or its maximized state
  changes. When `width=`/`width=NN%` is set *and* there's no applicable
  active window, the widget keeps reserving that same space (instead of
  collapsing to zero, which is what it still does without a fixed width)
  and renders `fallback=<mode>` into it: `clock` (current time, format
  from `fallback_format=<strftime format>`, default `%H:%M`), `username`
  (`$USER`, falling back to the passwd entry), `os` (`/etc/os-release`'s
  `NAME=`, e.g. "Ubuntu"), `os_version` (`PRETTY_NAME=` instead, e.g.
  "Ubuntu 22.04.3 LTS" -- already includes the version, no separate
  concatenation needed), or `text` (literal `fallback_text=<string>`,
  quote it if it needs spaces). Default `fallback` is unset, meaning
  nothing is drawn in the reserved space. Polls `_NET_ACTIVE_WINDOW`
  every ~300ms, same tradeoff as `tasklist`'s polling.
- `tray`: one square icon button per active StatusNotifierItem (the
  `org.kde.StatusNotifierItem`/`org.freedesktop.StatusNotifierItem`
  DBus protocol used by every modern tray -- KDE, GNOME's legacy
  extension, XFCE, etc.). `icon_padding=<px>` (default `0`, same
  semantics as `tasklist`'s) shrinks each icon by that many pixels;
  applied as a single shared margin around the *whole row* rather than
  per-icon, so the gap between two adjacent icons ends up the same width
  as the gap from an icon to the widget's own edge, not double that (a
  naive per-icon-slot padding would count both icons' padding at every
  internal boundary). Left-click sends `Activate(x,y)`, middle-click
  `SecondaryActivate(x,y)`, right-click `ContextMenu(x,y)` (the item's
  own process pops up its own menu near that point -- xispanel doesn't
  render it). Hovering shows the item's `Title` (or `IconName` if
  `Title` is empty) as a plain tooltip. See "System tray
  (StatusNotifierItem)" below for how registration/hosting works. No
  dependency on `libdbus-1` at build *link* time -- see MPRIS's note on
  optional runtime deps, same mechanism (`sni.c`).
- `launcher`: a single generic clickable icon -- `icon=<path>` (any
  format Imlib2 can decode; falls back to a single-letter placeholder
  derived from `name` if missing or it fails to load), `name=<text>`
  (hover tooltip, and the fallback placeholder's letter), `cmd=<command>`
  (run via `sh -c` on left-click, detached -- quote it if it needs
  spaces, e.g. `cmd="xterm -e htop"`). `cmd_middle=`/`cmd_right=`/
  `cmd_scroll_up=`/`cmd_scroll_down=` are the same shape of option for
  middle-click, right-click, and the scroll wheel (X11 delivers wheel
  motion as a button 4/5 press, so it's the same dispatch path as a
  click) -- any left unset is simply a no-op for that button/direction.
  This makes one `launcher` usable as a small multi-action control (e.g.
  scroll to adjust something, click to open a full app for it) without a
  dedicated widget type. Deliberately not a full `.desktop`-aware
  application launcher (no parsing, no icon-theme lookup, no search) --
  multiple `launcher` widgets is how the user pins individual shortcuts
  today; that's future launcher-phase territory.
- `volume`: a speaker icon reflecting the default PulseAudio/PipeWire
  sink's level/mute state, backed by shelling out to `pactl` (see
  "Volume control" below) -- no libpulse linked, and no dependency at
  all (build or runtime) if `pactl` isn't installed. Scroll up/down on
  the icon adjusts the default sink's volume by `step=<pct>` (default
  `5`) per notch; left-click toggles mute; right-click runs
  `cmd_edit=<command>` (default `pavucontrol`) for a full mixer. Hovering
  shows a read-only tooltip with the default output's and input's
  level/mute state (`Saída: NN%` / `Entrada: NN%`) -- individually
  adjustable per-device scrollbars in the tooltip are a known gap against
  the original ask, not yet implemented; `cmd_edit`'s external mixer
  covers that need for now.

- `globalmenu`: renders the active window's exported application menu
  (File/Edit/View/...), when it has one -- see "Global menu (appmenu)"
  below for the underlying mechanism. `mode=open|closed` (default
  `closed`): `open` draws the top-level menu names inline in the widget,
  like a normal window's own menu bar (or macOS's global menu bar);
  `closed` draws a single hamburger icon instead. In `open` mode,
  hovering (or clicking) a top-level name (e.g. "File") opens *that
  item's own* subtree as a real cascading submenu (see "Context menus"
  above) anchored under the label; once one top-level menu is open,
  moving the pointer to a *different* top-level label switches to that
  one too, no click needed -- same behavior as a normal application's
  menu bar. In `closed` mode, clicking the hamburger opens the *entire*
  menu tree as a cascade instead, rooted at the top rather than one
  top-level item. Collapses to zero width whenever the active window has
  no exported menu (same "just don't render" fallback `tray` uses when
  empty). Polls `_NET_ACTIVE_WINDOW` every ~300ms, same tradeoff as
  `tasklist`/`winctl`'s polling; only re-fetches the top-level item list
  when the tracked window (or its menu's busname/objpath) actually
  changes, not on every poll tick -- each submenu's own contents are
  fetched fresh (one `GetLayout` call) whenever it's actually opened.
- `folder`: a single folder icon (`path=<dir>`, required) that, on click,
  shows that folder's contents as a real cascading menu (see "Context
  menus" above) -- every directory level gets "Abrir esta pasta"/"Abrir
  terminal aqui" (shelling out to `xdg-open`/a terminal, see below) ahead
  of its entries; a subfolder entry opens its own contents as a nested
  submenu, and so on. `icon=<path>` overrides the icon (any format Imlib2
  decodes); without it, resolves the theme's own "folder" icon (breeze/
  Adwaita/hicolor, same lookup `tray` uses for a themed `IconName`),
  falling back to the single-letter placeholder if that fails too.
  `name=<text>` overrides the hover-tooltip text and fallback-placeholder
  letter (default: the path's basename). Rebuilt fresh on every click of
  the icon (not cached), reading *one directory level at a time* -- unlike
  a DBusMenu tree (bounded by however deep an app's own menu structure
  goes, fetched whole in one `GetLayout(-1)` call), a filesystem tree has
  no natural bound, so a subfolder's contents are only ever read when its
  submenu is actually opened (`menu.c`'s lazy-expand mechanism, see
  "Context menus" above), not recursively up front. Each directory lists
  at most 100 entries (with a "... mais itens" note if truncated), the
  overall item count across every level opened so far shares `menu.c`'s
  own cap, symlinks are never followed (rules out a symlink loop), and
  hidden entries (leading `.`) are skipped. Clicking a file runs
  `xdg-open` on it directly; a directory always opens its own submenu
  instead (never fires `xdg-open` directly -- use that submenu's own
  "Abrir esta pasta" if that's what you want).

System monitor is a later phase -- see the plan this tool was built
from; it is not implemented yet.

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

### Colors and font default to the live system theme

A panel with no `THEME` line at all, or one that doesn't set `bg=`/`fg=`,
doesn't fall straight to a hardcoded gray -- `alloc_panel()` first tries
reading the *current* KDE/Plasma color scheme
(`~/.config/kdeglobals`'s `[Colors:Window]` `BackgroundNormal=R,G,B` /
`ForegroundNormal=R,G,B`, each channel 0-255) and only falls back to the
hardcoded default for whichever of bg/fg it didn't find there. Font
detection (`~/.config/kdeglobals`'s `[General]` `font=`, falling back to
`~/.config/gtk-3.0/settings.ini`'s `gtk-font-name=`) already worked this
way from an earlier session. Both are read fresh every time a panel's
defaults are computed (config load or `RELOAD`), not cached/copied into
`xispanel.conf` -- so a later system theme change just takes effect on
the next `RELOAD` rather than requiring `xispanel.conf` to be
regenerated or hand-edited to match. An explicit `bg=`/`fg=` in a
`THEME` line always overrides this regardless of what the system theme
says. GTK has no equivalent simple flat-file color key the way it does
for fonts (GTK themes are CSS, not `key=value`), so this only actually
finds anything on a KDE/Plasma-configured system today -- a known gap,
not worth a CSS parser for.

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
what the items mean, only how to draw/position/dismiss the popup(s). It's
`override-redirect` window(s) with an exclusive pointer+keyboard grab
(held by only the first/root window) while open: a click outside every
open frame's bounds, or Escape, dismisses the whole thing (a click
outside is *not* re-delivered to whatever was actually underneath it --
a known, accepted simplification; click again to interact with that).

The root frame is positioned glued to the panel's outer edge (below a top
panel, above a bottom one, beside a left/right one) with its leading edge
aligned to whichever sub-item triggered it -- e.g. right-clicking a task
button opens the menu directly under *that button*, not at the raw click
coordinates -- same convention plasmashell's taskbar context menus use.

Menus with nested items (currently: the tray's/`globalmenu`'s DBusMenu
popups, and `folder`'s directory listings) render as real **cascading
submenus** -- a separate popup window per open nesting level, positioned
beside its parent frame at the row that spawned it, classic Windows/GTK/Qt
style -- rather than one long flattened+indented list. Hovering an item
with children opens its own submenu frame after `tooltip_delay` (the same
open-delay hover tooltips use); clicking such an item opens it
immediately. Moving the pointer to a different item in an already-open
parent frame closes whatever deeper frames no longer apply; moving it off
of every open frame for `tooltip_close_delay` closes the whole menu (same
grace-period idea hover tooltips use, see below) -- clicking a leaf item,
or Escape, close it immediately as always. A small right-pointing arrow
at an item's trailing edge indicates it has a submenu.

A submenu's children can either be supplied up front (DBusMenu's
`GetLayout(-1)` already returns a whole bounded subtree in one call) or
fetched **lazily**, the first time that item's submenu is actually opened
-- `folder` uses this so opening the icon only ever reads *that*
directory's own entries, not the whole tree underneath it; a subfolder's
contents aren't read from disk until you actually open *its* submenu in
turn, however deep you go.

Any frame with more items than fit the output vertically **pages**
instead of overflowing off-screen (or silently truncating): its height is
capped to the output's own height, with a small up/down arrow row
reserved at the top and bottom (dim when there's no previous/next page,
same look `tasklist`'s own task-overflow arrows use) -- clicking a bright
arrow jumps a whole page at once, not a continuous scroll. A frame's width
still spans every item across every page, so paging never resizes it
mid-browse.

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
dismissal rule: leaving the source widget starts a grace period (the
panel's `tooltip_close_delay`, default 300ms, `0` = instant -- see `PANEL`
above) before it actually closes, cancelled if the pointer enters the popup
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
happens to be playing something. Clicking previous/play-pause/next only
performs that action and repaints the popup (to reflect a play<->pause
icon flip right away) -- unlike clicking the thumbnail (activates the
window) or its close icon (closes it), a media-control click does *not*
dismiss the tooltip, so the buttons stay reachable for repeated clicks.

This is fully **optional at both build time and runtime**. At build
time, the Makefile checks `pkg-config --exists dbus-1`; if it's missing,
`mpris_stub.c` (identical function signatures, every one a no-op) is
compiled and linked instead of `mpris.c`, so `libdbus-1-dev` isn't even
needed to build xispanel in that case -- `<dbus/dbus.h>` is never
`#include`'d. When `mpris.c` *is* built (dbus-1-dev was present), it's
still an optional *runtime* dependency: it `dlopen()`s `libdbus-1.so.3`
and resolves every symbol it needs via `dlsym()`, never linked at build
time (`ldd xispanel` shows no `libdbus` either way). A system with the
dev headers at build time but no `libdbus-1.so.3` installed at runtime
just runs fine with MPRIS support silently unavailable -- no crash, no
startup failure, `tasklist`'s tooltip simply never shows the extra
buttons. Volume/mute control (PulseAudio/PipeWire) is a separate,
heavier dependency decision, deliberately not part of this -- see the
project notes.

Player discovery polls the bus every ~1.5s (`mpris_poll()`, called from
the main loop) rather than subscribing to DBus signals or folding
libdbus-1's file descriptor into the `select()` loop -- simpler, and a
media-control button doesn't need sub-second freshness. Every DBus call
uses a short (200ms) blocking timeout; this is a deliberate tradeoff
(documented in `mpris.c`) to avoid the far larger complexity of a real
async DBus main-loop integration for a best-effort feature.

Window thumbnails are a planned follow-up, gated on an active compositor
-- not implemented yet.

### System tray (StatusNotifierItem)

The `tray` widget implements the `org.freedesktop.StatusNotifierItem`
protocol (aka "SNI", aka KDE's tray spec -- what every modern tray icon
speaks today, including apps that only know the older `org.kde.*` names,
which are interface-compatible aliases of the same protocol). Same
optional-at-build-and-runtime mechanism as MPRIS above: no `dbus-1`
pkg-config at build time links `sni_stub.c` instead of `sni.c` (no tray
items, ever, but the widget still builds/registers normally); when
`sni.c` is built, it `dlopen()`s `libdbus-1.so.3` and never links it
(`ldd xispanel` shows no `libdbus` either way) -- no libdbus-1 at runtime
just means an empty tray, not a crash or startup failure.

Unlike MPRIS (a pure DBus *client*), a tray also has to act as a DBus
*service*: other processes' tray icons call `RegisterStatusNotifierItem`
on whichever process owns the well-known watcher name. Two such names
exist for the exact same protocol in practice --
`org.freedesktop.StatusNotifierWatcher` (what the spec document actually
says) and `org.kde.StatusNotifierWatcher` (the original pre-freedesktop.org
name, still what KDE's `kded5`/`kded6` registers, and still what most
tray items' client libraries check first or exclusively -- confirmed
against a real Plasma session: `kded5` owns `org.kde.StatusNotifierWatcher`
and nothing owns the freedesktop.org name at all). On startup xispanel
checks both via `dbus_bus_name_has_owner()` and logs which role it ended
up in:

- **No other watcher running** (e.g. replacing plasmashell/liquidshell
  entirely on a bare X session): xispanel becomes the watcher itself
  under *both* names at once (`DBUS_NAME_FLAG_DO_NOT_QUEUE` on each --
  fail immediately rather than silently becoming a backup owner), so it
  answers to whichever name a given item's library happens to probe. It
  then has to *receive* `RegisterStatusNotifierItem` calls from other
  processes, which -- rather than pulling `libdbus-1`'s watch/timeout
  objects into xispanel's `select()` loop (flagged as the fiddliest part
  of DBus integration in the original phased plan) -- is handled by
  polling too: every `sni_poll()` tick (~1.5s, same cadence as MPRIS)
  drains any pending incoming messages with a zero-timeout
  `dbus_connection_read_write()` + `dbus_connection_pop_message()` loop
  and answers whatever's there by hand (no
  `dbus_connection_register_object_path()`/vtable machinery needed for
  the handful of methods anything actually calls on us: mainly
  `RegisterStatusNotifierItem`, plus best-effort stubs for
  `Properties.Get(All)`/`Introspect` so a strict client doesn't hang
  waiting on a reply that never comes).
- **Another watcher already running** (the common case on an existing
  Plasma/KDE session, or any other DE already running its own tray host):
  xispanel doesn't fight over either name -- it just becomes a second
  host, polling *that* watcher's `RegisteredStatusNotifierItems` property
  instead of tracking registrations itself.

Either way, once an item is known, xispanel re-fetches its `Title`
(targeted `org.freedesktop.DBus.Properties.Get`, not `GetAll`) every
~1.5s poll -- cheap, a small string. `IconPixmap` is *not* re-fetched on
that same schedule: an early implementation did (`GetAll` on the whole
`org.kde.StatusNotifierItem` interface, dragging along `IconPixmap` and
`ToolTip` -- both potentially tens of KB of raw pixel data -- every
1.5s regardless of whether anything changed) and it measurably cost
~4-5% sustained CPU with just 2-3 real tray items registered. Instead,
xispanel adds a bus match rule for
`type='signal',interface='org.kde.StatusNotifierItem'` at connect time
(still no per-item `dbus_connection_add_filter()`/watch-object
machinery -- these signals just show up in the same
`dbus_connection_pop_message()` drain everything else uses) and only
re-fetches `IconPixmap` (via a targeted `Properties.Get`, not `GetAll`)
for all known items when a `NewIcon`/`NewAttentionIcon`/`NewOverlayIcon`/
`NewStatus`/`NewTitle`/`NewToolTip` signal was seen from *any* item since
the last poll, plus a 60s fallback in case some item's client library
doesn't emit those signals reliably. `IconPixmap` is an `a(iiay)` array
of `(width, height, ARGB32-network-byte-order bytes)` structs; the
largest available is picked and converted to a premultiplied Cairo
surface the same way `_NET_WM_ICON` already is in `ewmh.c`. Items that
never set `IconPixmap` fall back to the same single-letter placeholder
tasklist/winctl use, keyed off `Title`/`IconName`.

Left-click always sends `Activate(root_x, root_y)` -- the item's primary
action, same convention plasmashell follows (e.g. left-click on
OpenSnitch's tray icon opens its UI, not a menu). Middle-click always
sends `SecondaryActivate(root_x, root_y)` (both fire-and-forget, per
spec -- DBusMenu below has no equivalent for either). Only right-click
first tries rendering the item's own **DBusMenu** (`Menu` property): a
real object path there means the item expects *that* to be its
right-click interaction, not `ContextMenu()` -- confirmed against
fcitx5's real SNI item, whose introspection doesn't even list a
`ContextMenu` method (only `Activate`/`Scroll`/`SecondaryActivate`),
while `Menu` points at a working `com.canonical.dbusmenu` object serving
its input-method switcher. xispanel fetches it with a single
`GetLayout(0, -1, [])` call (depth `-1` returns the *entire* tree
recursively -- fcitx5's real menu nests the actual input-method list one
level under a "Group" container, so this avoids a follow-up round-trip
per level) and opens it as a real cascading submenu popup via
`dbusmenu.c`/`menu.c`'s `panel_menu_open_tree()` (see "Context menus"
above) rather than one flattened list. Clicking a leaf entry sends
`Event(id, "clicked", <int32 0>, 0)` fire-and-forget, same convention
DBusMenu clients use. `menu.c`'s per-fetch item cap is 24 for the tray
(`DBUSMENU_MAX_ITEMS`), enough to fit menus like fcitx5's (5 input
methods + separator + Configure/Restart/Exit = 9 entries) -- larger than
that silently truncates rather than crashing (`dbusmenu_fetch()` just
stops filling its output arrays at `max_items`). Only when the `Menu`
property is empty/absent (the spec's "no menu" convention, object path
`/` or unset) does right-click fall back to plain
`ContextMenu(root_x, root_y)`. Tested end-to-end against a throwaway
Python (`dbus-python`) fake tray item: registration, icon fetch,
left/middle/right click dispatch, and tooltip all confirmed working
(before the DBusMenu client existed -- that part's been exercised
against fcitx5's real menu directly, `ldd`/`strings` still confirm no
build-time link to `libdbus`).

### Global menu (appmenu)

`globalmenu` reads whichever application menu the *active* window
exported, using the same mechanism a working reference implementation
already relies on (a KRunner plugin the tool's author uses day to day):
Qt/KF5 apps set two X11 window properties directly on their own
top-level window, no registrar service involved --

- `_KDE_NET_WM_APPMENU_SERVICE_NAME` (type `STRING`): the DBus bus name
  hosting the menu.
- `_KDE_NET_WM_APPMENU_OBJECT_PATH` (type `STRING`): the
  `com.canonical.dbusmenu` object path on that bus name.

Despite the name, no `com.canonical.AppMenu.Registrar` service is needed
just to *read* an already-exported menu -- that registrar only matters
for the (different) job of being the thing apps register a window with in
the first place, which `xispanel` doesn't need to be here. `globalmenu`
just tracks `_NET_ACTIVE_WINDOW` (polled every ~300ms, same tradeoff as
`tasklist`/`winctl`) and reads both properties straight off whatever
window that points at; a window with neither property set (most GTK apps,
apps with no menu at all) makes the widget collapse to zero width, same
as `tray` when there are no items.

Coverage is inherently partial, same caveat as the tray's `Menu`-property
handling: this only works for apps that actually export
`_KDE_NET_WM_APPMENU_*` (Qt/KF5 apps, and GTK apps running the
`appmenu-gtk-module` shim) -- a GTK app with a headerbar and no exported
menu at all just has nothing to show, and `globalmenu` reports that as
"no menu" rather than an error.

The actual `GetLayout`/`Event` protocol work is shared with the tray's
`Menu`-property handling via `dbusmenu.c` (see "System tray" above) --
`globalmenu` is only the EWMH property lookup, active-window tracking,
and open/closed-mode layout on top of it.

### Volume control

The `volume` widget shells out to the `pactl` command-line tool
(`pulse.c`) instead of linking `libpulse`/`libpipewire` directly. This is
a different shape of "optional dependency" than MPRIS/tray's dlopen'd
libdbus-1: PulseAudio's (and PipeWire's pulse-compat) client library is
built around a persistent async connection + callback mainloop, not
simple one-shot synchronous calls the way libdbus-1's blocking-call API
is -- wrapping it properly would mean folding a real chunk of that
mainloop into xispanel's own `select()` loop for not much benefit over
just running `pactl`, which is bundled with `pulseaudio-utils` and also
provided by `pipewire-pulse`'s compatibility layer, so it's present on
both actual PulseAudio and PipeWire-with-pulse-compat systems. This means
`pulse.c` has **no build-time dependency whatsoever** (no headers, no
library, nothing in the Makefile's `pkg-config` list) -- it compiles
unconditionally, and `pulse_available()` is a runtime-only check (a
cached `pactl --version` run through `popen()`) for whether the binary
exists in `$PATH`; every function reports "no audio" instead of failing
if it doesn't.

Every `pactl` invocation is prefixed with `LC_ALL=C` so its output is
locale-independent to parse -- verified against a real pt_BR session
where `pactl get-sink-mute` would otherwise print `Mute: não` instead of
`Mute: no`. The device names passed around are always the literal
`@DEFAULT_SINK@`/`@DEFAULT_SOURCE@` (PulseAudio's own aliases for
"whatever the current default is"), not resolved device names -- no
separate "get default device" call needed. Verified live: scroll
up/down changed the real system volume (confirmed against `pactl
get-sink-volume` before/after), click toggled real mute state, and the
tooltip reflected both sink and source levels correctly.

### Window thumbnails

`tasklist`'s `show_thumbs=yes` draws a live thumbnail of the hovered
task's window into its tooltip (`thumb.c`), via the XComposite
extension. Two independent gates, both fail open (no thumbnail, not a
crash) if unmet:

- **Build time**: `libxcomposite-dev` availability, checked via
  `pkg-config --exists xcomposite` in the Makefile. Unlike `dbus-1`
  there's no dlopen-equivalent trick here (XComposite is used over the
  already-open X connection, not a separate shared library you could
  choose not to link), so this is a normal optional *link-time*
  dependency: `thumb_stub.c` (always reports no thumbnail support) is
  linked instead of `thumb.c` when the headers aren't found.
- **Runtime**: an active compositor, detected the same way every
  EWMH-aware compositing check does -- looking for an owner of the
  `_NET_WM_CM_S<screen>` selection. Without a compositor, no window is
  redirected to an offscreen pixmap at all, so there's nothing to
  capture.

Once both gate checks pass, `thumb_paint()` calls
`XCompositeNameWindowPixmap()` on the window and wraps the result as a
`cairo_xlib_surface`, scaled to fit a fixed-size box (200x130) preserving
aspect ratio, never upscaled past the window's real size. Re-fetched
fresh on every tooltip repaint (~1/s, the same cadence clock's tooltip
already refreshes at) rather than cached, avoiding the classic
stale-composite-pixmap pitfall where the pixmap ID silently stops
updating across an unmap/map or resize.

**Real-world gotcha, worth remembering if this is touched again:** on a
reparenting WM, the window `_NET_CLIENT_LIST` reports is not necessarily
the one that's actually composite-redirected -- confirmed on this repo's
own KWin fork, where `XCompositeNameWindowPixmap()` on the raw client
window fails with `BadMatch`, and the *client's parent's parent* (two
`XQueryTree()` hops up) is what's actually redirected. `thumb_paint()`
walks up the parent chain (capped at 4 hops) trying each ancestor until
one succeeds or it hits the root, rather than assuming a fixed number of
wrapper levels.

Also discovered while building this: xispanel had **no global
`XErrorHandler`** anywhere -- since it continuously queries arbitrary
other processes' window properties (`tasklist`/`winctl` polling every
open window's title/icon/state), any window closing between being listed
and being queried raises a protocol error that Xlib's default handler
turns into `exit()`, taking down the whole daemon over a routine,
expected race. This surfaced as a real crash during thumbnail testing
(`X_GetProperty`/`BadWindow` from ordinary `ewmh.c` polling, unrelated to
`thumb.c` itself) and is now fixed process-wide: `xispanel.c` installs a
permissive `x_error_handler()` right after `XOpenDisplay()` that logs and
continues instead of exiting. `thumb.c` additionally swaps in its own
temporary handler around composite-specific calls (to detect *its own*
failures without the generic log line firing for the very common
"window isn't the redirected one" case), always restoring the process
handler afterward.

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
  (activate/close/minimize/maximize/move), plus `_NET_WM_ICON` decoding,
  the icon/text drawing helpers built on top of it, and
  `resolve_icon_theme_name()` (freedesktop icon-theme lookup by name,
  e.g. `folder` or a tray item's `IconName` -- lives here rather than in
  `sni.c` since it has no DBus dependency of its own and `folder` needs
  it too).
- `menu.c`: the generic context-menu popup described above.
- `tooltip.c`: the generic hover-tooltip popup described above.
- `mpris.c`: the optional (dlopen'd libdbus-1) MPRIS2 client described
  above; `mpris_stub.c` is its build-time fallback (identical API,
  every function a no-op) when `dbus-1` isn't found via pkg-config --
  the Makefile links exactly one of the two.
- `sni.c`: the optional (dlopen'd libdbus-1) StatusNotifierItem tray
  client+host described above; `sni_stub.c` is its equivalent build-time
  fallback.
- `dbusmenu.c`: the generic (dlopen'd libdbus-1, own independent session-bus
  connection) `com.canonical.dbusmenu` client -- `GetLayout`/`Event`,
  shared by `sni.c` (a tray item's `Menu` property) and the `globalmenu`
  widget (a window's `_KDE_NET_WM_APPMENU_*` properties). `dbusmenu_stub.c`
  is its build-time fallback (identical API, every function a no-op) when
  `dbus-1` isn't found via pkg-config.
- `widgets/globalmenu.c`: renders the active window's exported application
  menu, described in its own section above.
- `pulse.c`: the `pactl`-shelling volume control backend described
  above. Unconditionally compiled -- no stub pair needed, since it has no
  build-time dependency to begin with.
- `thumb.c`: the XComposite-based window-thumbnail capture described
  above; `thumb_stub.c` is its build-time fallback when `xcomposite`
  isn't found via pkg-config.
- `widgets/spacer.c`, `widgets/clock.c`, `widgets/tasklist.c`,
  `widgets/winctl.c`, `widgets/tray.c`, `widgets/launcher.c`,
  `widgets/volume.c`, `widgets/folder.c`: one file per widget type. Adding
  a new type is
  "write `widgets/foo.c` defining a `PanelWidgetOps foo_ops`, declare it
  `extern` in `xispanel.h`, add it to
  the registry array in `xispanel.c`" -- no other file needs to change.

## Design notes

- Text uses whatever font family the desktop is actually configured
  with, not Fontconfig's `sans-serif` generic alias (a distro-wide
  default, often not what the user picked in System Settings).
  `detect_system_font_family()` in `xispanel.c` reads, in order:
  `~/.config/kdeglobals`'s `[General] font=Family,size,...` (Plasma),
  then `~/.config/gtk-3.0/settings.ini`'s `gtk-font-name=Family size`
  (GTK-based desktops), falling back to Fontconfig's own default if
  neither file exists or has the key. Plain text-file parsing, no Qt/GTK
  linked -- same "read the config file directly" approach as everything
  else in this tool. Only the family is taken from either source; the
  point size in `kdeglobals`/`gtk-font-name` is ignored on purpose --
  panel text is sized off panel thickness (`p->thickness * 0.45`, see
  `panel_repaint()`), not a fixed point size, so it always fits whatever
  `thickness=` the panel is configured with. Read once at startup, not
  re-read on `RELOAD` -- font changes are rare enough that restarting
  xispanel is an acceptable way to pick up a new one for now.
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
