CFLAGS ?= -Wall -Wextra -O2
LIBS := $(shell pkg-config --cflags --libs gtk+-2.0)

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin

xisnotif: xisnotif.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

install: xisnotif
	install -Dm755 xisnotif $(DESTDIR)$(BINDIR)/xisnotif

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/xisnotif

clean:
	rm -f xisnotif

.PHONY: clean install uninstall
