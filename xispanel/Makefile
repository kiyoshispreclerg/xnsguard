CFLAGS ?= -Wall -Wextra -O2
LIBS := $(shell pkg-config --cflags --libs x11 xrandr cairo cairo-xlib imlib2 freetype2 fontconfig) -lm

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin

xispanel: xispanel.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

install: xispanel
	install -Dm755 xispanel $(DESTDIR)$(BINDIR)/xispanel

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/xispanel

clean:
	rm -f xispanel

.PHONY: clean install uninstall
