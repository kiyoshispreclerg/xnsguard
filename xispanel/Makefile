CFLAGS ?= -Wall -Wextra -O2
PKGS := x11 xrandr cairo cairo-xlib imlib2 freetype2 fontconfig

# dbus-1 (mpris.c/sni.c's MPRIS media controls + system tray) is the one
# *build-time* optional dependency: if `pkg-config dbus-1` isn't found
# (no libdbus-1-dev installed), we link mpris_stub.c/sni_stub.c instead --
# harmless no-ops with the exact same function signatures, so xispanel.c
# and the widgets that call into them (tasklist.c, widgets/tray.c) never
# need to know or care which pair got built. This is on top of (not
# instead of) mpris.c/sni.c's own runtime dlopen() of libdbus-1.so.3: even
# on a system that *does* have the dev headers, neither ever links
# libdbus-1 directly, so a system with headers but no libdbus-1.so.3
# installed still runs fine too. See mpris.c/sni.c/mpris_stub.c/sni_stub.c.
HAVE_DBUS := $(shell pkg-config --exists dbus-1 && echo yes)
ifeq ($(HAVE_DBUS),yes)
DBUS_SRCS := mpris.c sni.c
DBUS_CPPFLAGS := $(shell pkg-config --cflags dbus-1)
else
DBUS_SRCS := mpris_stub.c sni_stub.c
DBUS_CPPFLAGS :=
$(info xispanel: dbus-1 not found via pkg-config -- building without MPRIS/tray support)
endif

CPPFLAGS := $(shell pkg-config --cflags $(PKGS)) $(DBUS_CPPFLAGS)
LDLIBS := $(shell pkg-config --libs $(PKGS)) -lm -ldl

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin

SRCS := xispanel.c ewmh.c menu.c tooltip.c $(DBUS_SRCS) widgets/spacer.c widgets/clock.c widgets/tasklist.c widgets/winctl.c widgets/tray.c widgets/launcher.c
OBJS := $(SRCS:.c=.o)

xispanel: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c xispanel.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

install: xispanel
	install -Dm755 xispanel $(DESTDIR)$(BINDIR)/xispanel

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/xispanel

clean:
	rm -f xispanel $(OBJS)

.PHONY: clean install uninstall
