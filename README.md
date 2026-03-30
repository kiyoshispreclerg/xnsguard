# XnsGuard

**XnsGuard** is a lightweight external permission guardian for X11.

It communicates with the **Xnotify** mechanism (present in [my experimental XLibre fork](https://github.com/kiyoshispreclerg/xserver/tree/experiments) of the X server) to control privileged actions that X11 clients attempt to perform in real time, such as:

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
Xnotify is **not** a classic X extension (it is not loaded via `XInitExtension`). It is an internal notification mechanism using Unix domain sockets.
It works with static rules in `/etc` or dynamically with the external guardian (XnsGuard).
[More about Xnotify here](https://github.com/kiyoshispreclerg/xserver/blob/experiments/doc/Xnotify.md).

### Dependencies
- Linux (recommended) — uses Unix domain sockets
- Zenity (for graphical permission dialogs)
- GCC or Clang with pthread support
- [This XLibre experimental fork with Xnotify enabled](https://github.com/kiyoshispreclerg/xserver/tree/experiments)

### How to Compile and Install

`make`

`sudo make install`

Or manually:

`gcc -O2 -Wall -Wextra -pthread -D_FORTIFY_SOURCE=2 -fstack-protector-strong -o xnsguard xnsguard.c`

### How to Use

`xnsguard`

Useful options:

`xnsguard --no-pause`                    # notify only, do not pause processes

`xnsguard --quiet`                       # no Zenity dialogs, logs only

`xnsguard --always-kill`                 # automatically kill unauthorized processes

`xnsguard --conf=$HOME/.config/xnsguard` # diretório de configuração personalizado

### Permission Configuration

Xlibre with Xnotify already loads fixed permissions from /etc/X11/xnotify.conf*, but the user can allow (or deny) more programs
by creating the file ~/.config/xnsguard/perms.conf with more rules, or just by allowing them when xnsguard asks for permission.

Examples:

`ALLOW INPUT /usr/bin/firefox`

`ALLOW SELECTION /usr/share/codium/codium`

`ALLOW SCREEN /usr/lib/chromium/chromium`

`ALLOW COMPOSITE /usr/share/librewolf/librewolf`

`ALLOW ALL /home/kiyoshi/Downloads/syncthing`

`DENY RECORD *`

### Ignore Reports

Because Xnotify sends notifications about every single interaction with protected places in its code, sometimes XnsGuard floods
the terminal with these. So the user can add a list of programs to the file ignore.conf in the same path of perms.conf, and
reports coming from these programs will not be shown. It can be a good idea to add programs required for the session, such as
window, clipboard, keyboard layout and session managers.

