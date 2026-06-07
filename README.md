# XnsGuard

**XnsGuard** is a lightweight external permission guardian for X11.

It communicates with the **Xnotify** extension (present in [my personal XLibre fork](https://github.com/kiyoshispreclerg/xserver/tree/xnotify) of the X server) to control privileged actions that X11 clients attempt to perform in real time, such as:

- Clipboard access (SELECTION)
- Screen recording or capture (RECORD, COMPOSITE, SCREEN)
- Input capture or injection (INPUT, INPUT_GRAB, INPUT_INJECT)
- Other sensitive actions (ATTACH, HOTKEY, etc.)

When a program tries to perform a protected action, Xnotify notifies XnsGuard, which can allow it automatically (via rules), ask the user (using Zenity), deny it, or kill the process.

### Status and Purpose
- This is a **personal hobby project**, not officially integrated into XLibre development (yet?).
- It serves as a **practical demonstration** of how Xnotify can be used for real-time permission communication between the X server and an external manager, such as this daemon, or a compositor, or a system tool.
- It started as an attempt to control the Xnamespace extension externally, but that first idea went to the end of my priorities after some coding with AI, hehe~
- And yes, I use AI in many parts of the code, but always reading and testing them before compiling 😊

### What is Xnotify?
Xnotify is a small X extension present in [this XLibre fork](https://github.com/kiyoshispreclerg/xserver/tree/xnotify).
It intercepts privileged client requests and notifies an external guardian via Unix domain socket, allowing real-time permission decisions.
It works with static rules or dynamically with the external guardian (XnsGuard).
[More about Xnotify here](https://github.com/kiyoshispreclerg/xserver/blob/xnotify/doc/Xnotify.md).

### Dependencies
- Linux (recommended) — uses Unix domain sockets
- Zenity (for graphical permission dialogs)
- GCC or Clang with pthread support
- libX11 (for Xnotify extension detection at startup)
- [This XLibre experimental fork with Xnotify enabled](https://github.com/kiyoshispreclerg/xserver/tree/xnotify)

### How to Compile and Install

`make`

`sudo make install`

Or manually:

`gcc -O2 -Wall -Wextra -pthread -D_FORTIFY_SOURCE=2 -fstack-protector-strong -o xnsguard xnsguard.c -lX11`

### How to Use

`xnsguard`

Useful options:

`xnsguard --no-pause`                    # notify only, do not pause processes

`xnsguard --quiet`                       # no Zenity dialogs, logs only

`xnsguard --always-kill`                 # automatically kill unauthorized processes

`xnsguard --conf=$HOME/.config/xnsguard` # custom configuration directory

### Permission Configuration

XLibre with Xnotify already loads fixed permissions from xnotify.conf*, but the user can allow (or deny) more programs
by creating the file ~/.config/xnsguard/perms.conf with more rules, or just by allowing them when xnsguard asks for permission.

Examples:

`ALLOW INPUT /usr/bin/firefox`

`ALLOW SELECTION /usr/share/codium/codium`

`ALLOW SCREEN /usr/lib/chromium/chromium`

`ALLOW COMPOSITE /usr/share/librewolf/librewolf`

`ALLOW ALL /home/kiyoshi/Downloads/syncthing`

`DENY RECORD *`

### Ignore Reports

The user can add a list of programs to the file ignore.conf (in the same path of perms.conf), and
reports coming from these programs will not be shown. It can be a good idea to add programs always required for the session, such as
window, clipboard, keyboard layout and session managers.

