CFLAGS ?= -Wall -Wextra -O2
LIBS := $(shell pkg-config --cflags --libs gtk+-2.0)

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin

xisserve: xisserve.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

install: xisserve
	install -Dm755 xisserve $(DESTDIR)$(BINDIR)/xisserve

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/xisserve

clean:
	rm -f xisserve

.PHONY: clean install uninstall
