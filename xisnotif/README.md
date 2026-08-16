# xisnotif

Notification-history viewer, companion to `xispanel`'s tray bell icon.

**Status: skeleton only.** `xisnotif.c` currently just opens a blank GTK2
window to confirm the toolchain works -- no notification protocol, no
history, no IPC client yet.

## Why a separate process

`xispanel` (see `../xispanel/PROTOCOL.md`) implements the
`org.freedesktop.Notifications` DBus service itself, a tray bell icon
with an unread-count badge, and transient popup banners for incoming
notifications (including clickable action buttons, reusing the same
mechanism already built for MPRIS media controls in tooltip popups) --
none of that needs a second process.

What doesn't fit `xispanel`'s "no toolkit, minimal deps, plain Cairo"
philosophy is a scrollable *history* view: balloons of past
notifications with icon/text/timestamp, read/unread state, per-item
close, grouping by app. That's real list-widget UI, and reimplementing a
scrolling/selection framework in raw Cairo isn't worth it when GTK2
already has one.

## Planned architecture

- `xispanel` keeps a bounded in-memory ring buffer of recent
  notifications and exposes it over its existing control socket
  (`$XDG_RUNTIME_DIR/xispanel-ctl.sock`, line-JSON protocol -- see
  `../xispanel/PROTOCOL.md`), the same "already have the plumbing"
  reasoning `xisconf` uses to drive `xisback`/`xisguard`.
- `xisnotif` is a thin GTK2 client: connects to that socket, queries
  history, renders it as a list. Clicking an entry runs whatever action
  the notification offered.

## Open question: matching the system theme

GTK2 has no direct equivalent of Qt's palette system, and the old
bridges (oxygen-gtk, qt5ct's GTK2 hook) are largely unmaintained today.
The more realistic path is generating a small `.gtkrc-2.0` snippet from
`kdeglobals`'s `[Colors:Window]`/`[Colors:Button]` sections (mirroring
`xispanel.c`'s own `detect_system_colors()`) and pointing
`GTK2_RC_FILES` at it before `gtk_init()` -- not investigated yet.

Font should follow the same live-system-font detection `xispanel.c`
already does (`kdeglobals`'s `[General] font=`, falling back to
`gtk-3.0/settings.ini`'s `gtk-font-name=`) rather than trusting GTK2's
own default.

## Building

```
make
./xisnotif
```

Needs `gtk+-2.0` (`pkg-config --exists gtk+-2.0`).
