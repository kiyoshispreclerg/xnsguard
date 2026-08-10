# XisGuard - Permission Guard for XiS
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -pthread -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS ?= -pthread -lX11

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

all: xisguard

xisguard: xisguard.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: xisguard
	install -D -m 755 xisguard $(DESTDIR)$(BINDIR)/xisguard

clean:
	rm -f xisguard

.PHONY: all install clean