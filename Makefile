# XnsGuard - Permission Guard for XLibre
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -pthread -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS ?= -pthread

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

all: xnsguard

xnsguard: xnsguard.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: xnsguard
	install -D -m 755 xnsguard $(DESTDIR)$(BINDIR)/xnsguard

clean:
	rm -f xnsguard

.PHONY: all install clean