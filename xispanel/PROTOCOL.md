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
  second.

More widget types (tasklist, tray, window controls, global menu,
launcher, system monitor) are later phases -- see the plan this tool was
built from; they are not implemented yet.

### `THEME`

```
THEME	top	bg=#202020cc	fg=#eeeeee	spacing=6
```

- `bg`, `fg`: `#RRGGBB` or `#RRGGBBAA` (alpha only has a visible effect if
  the X server has a 32-bit ARGB visual available, i.e. a compositor is
  running -- otherwise the background renders fully opaque).
- `spacing`: pixels of gap between adjacent widgets (default `4`).

## Design notes

- Panel windows are `override-redirect`: xispanel manages its own
  position/stacking rather than asking a window manager to. `dock` mode
  still reserves space via `_NET_WM_STRUT_PARTIAL`/`_NET_WM_STRUT` --
  every WM that matters here reads that property from any top-level
  window, managed or not.
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
