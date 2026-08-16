# xisserve

GTK2 application launcher (kickoff/krunner-style), companion to
`xispanel`'s `launcher` widget.

**Status: skeleton only.** `xisserve.c` currently just opens a blank GTK2
window to confirm the toolchain works -- no search, no `.desktop`
parsing, no positioning logic yet.

## Why a separate process

Same reasoning as `xisnotif` (see its README): a real search-as-you-type
popup with icon-grid/list results is GTK-shaped UI work that doesn't fit
`xispanel`'s "no toolkit, plain Cairo" philosophy. `xispanel`'s own
`launcher` widget (`../xispanel/widgets/launcher.c`) stays a simple
pin-a-shortcut icon; `xisserve` is where full application search lives.

## Planned scope

- Krunner-style popup: type to search installed applications
  (`.desktop` parsing across `$XDG_DATA_DIRS` +
  `~/.local/share/applications`).
- Eventually, something in the spirit of Ubuntu Unity's HUD -- searching
  *actions within the currently focused app*, not just launching new
  ones. The user's existing `krunner_appmenu.py` script (a working
  KRunner plugin reading a focused Qt/KF5 window's exported menu via
  `_KDE_NET_WM_APPMENU_SERVICE_NAME`/`_OBJECT_PATH` and matching DBusMenu
  entries against the query) is the reference for that half --
  `xispanel`'s own `globalmenu` widget and `dbusmenu.c` already do the
  DBus side of that lookup in C, so this should reuse it rather than
  reimplementing.
- Positioning: `xispanel`'s `launcher` widget invokes `xisserve` with its
  own on-screen anchor coordinates (argv), not embedding/reparenting --
  reparenting would make `xispanel` an XEmbed-style host for a second
  toolkit, real complexity for something that's a floating popup on top
  of everything anyway, not literally inside the panel bar.

## Open question: matching the system theme

Same as `xisnotif` -- see its README's "Open question" section. Applies
here identically (font + KDE Plasma color scheme in GTK2).

## Building

```
make
./xisserve
```

Needs `gtk+-2.0` (`pkg-config --exists gtk+-2.0`).
