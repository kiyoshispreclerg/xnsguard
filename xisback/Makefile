CFLAGS ?= -Wall -Wextra -O2
LIBS := $(shell pkg-config --cflags --libs x11 xrandr imlib2) -lm

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin

xisback: xisback.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

install: xisback
	install -Dm755 xisback $(DESTDIR)$(BINDIR)/xisback

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/xisback

clean:
	rm -f xisback

.PHONY: clean install uninstall
