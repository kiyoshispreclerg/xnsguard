CFLAGS ?= -Wall -Wextra -O2
PKGS := x11 xrandr cairo cairo-xlib imlib2 freetype2 fontconfig
# dbus-1 is cflags-only (mpris.c/sni.c need its type/constant definitions
# to build) -- deliberately *not* in $(PKGS)'s --libs: both dlopen()
# libdbus-1.so.3 at runtime instead of linking it, so a system with the
# dbus-1 dev headers available at build time but no libdbus-1.so.3
# installed at runtime still runs fine, just without MPRIS/tray support.
# See mpris.c/sni.c.
CPPFLAGS := $(shell pkg-config --cflags $(PKGS) dbus-1)
LDLIBS := $(shell pkg-config --libs $(PKGS)) -lm -ldl

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin

SRCS := xispanel.c ewmh.c menu.c tooltip.c mpris.c sni.c widgets/spacer.c widgets/clock.c widgets/tasklist.c widgets/winctl.c widgets/tray.c widgets/launcher.c
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
