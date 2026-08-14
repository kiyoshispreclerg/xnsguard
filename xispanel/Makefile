CFLAGS ?= -Wall -Wextra -O2
PKGS := x11 xrandr cairo cairo-xlib imlib2 freetype2 fontconfig
CPPFLAGS := $(shell pkg-config --cflags $(PKGS))
LDLIBS := $(shell pkg-config --libs $(PKGS)) -lm

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin

SRCS := xispanel.c ewmh.c menu.c widgets/spacer.c widgets/clock.c widgets/tasklist.c widgets/winctl.c
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
