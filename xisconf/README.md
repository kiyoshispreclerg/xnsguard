# xisconf

Visual configurator (PyQt5/PyQt6) for XiS, an XLibre fork. Runs on top of
`subprocess`, calling the same tools you'd run by hand in a terminal — no
direct C/lib bindings.

## Tabs

- **Screens** — monitor layout via `xrandr`. Graphics canvas (QGraphicsScene)
  with draggable, edge-snapping monitors, plus a properties panel:
  enabled/primary, resolution, refresh rate, rotation, mirror, position, DPI
  and Scale. Also exposes *any* extra property the driver advertises via
  `xrandr --verbose` (TearFree, underscan, scaling mode, PRIME
  Synchronization, HDCP, etc.) — discovered generically, no hardcoded list:
  if the prop has `supported:` it becomes a combo box, if it has
  `range: (0,1)` it becomes a checkbox, if it has some other `range:` it
  becomes a spinbox, otherwise it's just shown read-only (label:value).
  - DPI < 96 isn't applied as the DPI property (outside the intended
    domain); on Apply it's automatically converted to DPI 96 + an
    equivalent `--scale` (the factor's inverse).
- **Pointer/Keyboard** — acceleration/natural scroll/left-handed/tapping via
  `xinput` (libinput properties), keyboard repeat/bell via `xset`, and the
  fork's 2 extra flags: `ToggleModifiersOnPress` and `KickHotkeysOnRelease`
  (XInput properties on the master keyboard).
- **Wallpaper** — wallpaper layers per (output, desktop), talking to the
  `xisback` session daemon (renamed from `xdesktopbg`) over a Unix socket
  (`$XDG_RUNTIME_DIR/xisback.sock`, line-oriented text protocol, see
  `xisback/PROTOCOL.md`). The "Active layers" box is a static canvas (the
  same `QGraphicsScene`/`QGraphicsView` as the Screens tab, just without
  drag): one box per output showing that layer's info; when there's a
  global layer (`output=*`), it becomes a single box covering the union of
  every output. Clicking a box loads that layer into the "Set / replace a
  layer" form below. Unlike the other tabs, there's no "detected vs edited"
  state to diff here: SET/CLEAR/NEXT act immediately on the daemon
  (auto-started on demand if it isn't running). `<path>` can be a single
  file or a folder (slideshow, alphabetical or shuffled, with a
  configurable crossfade).
- **Panels** — edits `xispanel.conf` (the `xispanel` panel/taskbar's config,
  see `xispanel/PROTOCOL.md`) directly as a file — parses and writes its 3
  line types, `PANEL`/`WIDGET`/`THEME` (`parse_xispanel_conf`/
  `write_xispanel_conf`), without talking to the daemon field-by-field
  (that control-socket command doesn't exist yet). 3 nested levels: panel
  list (Add/Remove) → the selected panel's own options in a 3-pair-of-
  columns grid (output, edge, mode, thickness, pct, rotate, bg/fg colors,
  spacing, tooltip delays) + its widget list side by side, in a resizable
  `QSplitter`, with the selected widget's own options next to it (Add with
  a combo of the pre-registered types — `launcher`, `tasklist`, `spacer`,
  `clock`, `winctl`, `globalmenu`, `volume` — and Remove; a dynamic form
  built from `WIDGET_TYPE_SCHEMAS`, the same pattern as the Screens tab's
  dynamic xrandr advanced-properties form). The **Save** button writes the
  file; there's no Reload here — that action moved to xisconf's top-level
  **Apply** button (which now always sends `RELOAD` to the
  `xispanel-ctl.sock` control socket, best-effort, on top of whatever else
  it already applied for the other tabs). **Restart panels** stays in this
  tab (`QUIT` + relaunches `xispanel` from scratch, unlike a plain reload).
  Loaded from disk once at startup (not on every Detect click), so as not
  to blow away unsaved edits.
- **Other** — DPMS and screensaver via `xset`, the fork's 3rd extra flag:
  `DisablePrimarySelection` (via `xprop -root`, disables middle-click
  paste), and the number of virtual desktops (`_NET_NUMBER_OF_DESKTOPS`,
  applied via `wmctrl -n N` — depends on the WM honoring the EWMH request;
  the spinbox is disabled if `wmctrl` isn't installed).
- **Permissions** — runtime mode and ALLOW/DENY rules for `xisguard` (the
  XNOTIFY extension's permission daemon, see `xisguard/XISGUARD.md`), via
  its control socket (`$XDG_RUNTIME_DIR/xisguard-ctl.<display>.sock`, a
  1-line-JSON-request → 1-line-JSON-response protocol). Unlike Wallpaper,
  xisconf **never starts xisguard on its own** — it's a security daemon,
  so that would be a strange thing for a configurator to do. Two parts:
  - **Runtime mode** (`GET_STATUS`/`SET_STATUS`) — `no_pause` (notify-only),
    `quiet` (no Zenity dialog), `always_kill`, `log_level` (0-4). Follows
    the same baseline/diff model as the other tabs: only enters `Apply` if
    something actually changed.
  - **Rules** (`LIST_RULES`/`ADD_RULE`/`REMOVE_RULE`/`RELOAD`) — a table of
    `perms.conf`'s rules, with a dialog to add one (any of XNOTIFY's 16
    actions + `ALL`, an exe pattern, ALLOW/DENY) and a button to remove the
    selected one. Act immediately on the daemon, like the Wallpaper tab —
    not part of the staged Apply. Removing a rule doesn't revoke access
    already granted to a client in its current session, only future
    decisions.
- **About** — info about the connected X server (name, vendor, version,
  release) and the list of active extensions, via `xdpyinfo`. Purely
  informational — X11 doesn't allow disabling extensions at runtime.

## Log / status bar

The log box at the bottom starts **hidden** by default: in its place is a
thin, clickable bar showing the last logged line (status-bar style).
Clicking it expands/collapses the full log (`QPlainTextEdit`).

## "Baseline" and diff model

Every tab keeps a snapshot ("baseline") of the last detected/applied state.
The **Apply** button only emits commands for what actually changed since
then (e.g. if only the refresh rate changed, the block is just
`--output NAME --rate X`, not the output's whole description). Tabs with
pending changes are highlighted (bold+italic) on the tab until the next
detect/apply. The exceptions are the Wallpaper tab and the Permissions
tab's "Rules" section (see above) — Permissions' "Runtime mode" section
follows the normal baseline/diff model.

Every action logs the command (`$ ...`) to the log box at the bottom, and
honors the global "Simulation mode" checkbox (dry-run): when checked, it
only logs, it doesn't execute anything.

## xrandr parsing

`detect()` runs `xrandr --verbose` and `xrandr` (plain) and does manual
regex-based parsing — extracting output headers (`_parse_header`), verbose
properties including Transform/DPI/generic ones (`_parse_verbose_props`),
and modes+rates from the plain format (`_parse_plain_modes`). There are a
few property lists: `_DEDICATED_PROPS` (already has its own UI, e.g. DPI),
`_READONLY_PROPS` (LUTs, CTM, identifiers — meaningless as a control) and
`_HIDDEN_PROPS` (never shown: EDID, `_KDE_SCREEN_INDEX`, CTM).

## Entry point

```
xisconf.py                # opens the GUI (Qt)
xisconf.py --dry-run      # opens the GUI with "Simulation mode" already checked
xisconf.py --self-test    # no GUI: runs every detect and prints to stdout
```

`--self-test` is useful for debugging the xrandr/xinput/xset parsing in a
non-interactive environment, without having to open the window.
