CFLAGS ?= -Wall -Wextra -O2
LIBS := $(shell pkg-config --cflags --libs x11 xrandr imlib2) -lm

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin

# xcb/xcb-randr/x11-xcb (xisback_inputscale.c's X-INPUT-SCALE client query --
# see that file's doc comment, adapted from xispanel/inputscale.c) are the
# one place this otherwise Xlib-only program touches XCB, needed only
# because no Xlib-side client binding exists yet for this project's own
# experimental server extension -- hand-rolling one raw extension request is
# far simpler via XCB's generic xcb_send_request() than via Xlib's
# unexported extension-request internals. Without all three -dev packages,
# xisback_inputscale_stub.c (always reports "no confinement active") is
# linked instead -- wallpapers just use each CRTC's raw physical geometry,
# same as before this feature existed.
HAVE_XINPUTSCALE := $(shell pkg-config --exists xcb xcb-randr x11-xcb && echo yes)
ifeq ($(HAVE_XINPUTSCALE),yes)
INPUTSCALE_SRC := xisback_inputscale.c
INPUTSCALE_CPPFLAGS := $(shell pkg-config --cflags xcb xcb-randr x11-xcb)
INPUTSCALE_LDLIBS := $(shell pkg-config --libs xcb xcb-randr x11-xcb)
else
INPUTSCALE_SRC := xisback_inputscale_stub.c
INPUTSCALE_CPPFLAGS :=
INPUTSCALE_LDLIBS :=
$(info xisback: xcb/xcb-randr/x11-xcb not found via pkg-config -- building without X-INPUT-SCALE support)
endif

xisback: xisback.c $(INPUTSCALE_SRC)
	$(CC) $(CFLAGS) $(INPUTSCALE_CPPFLAGS) -o $@ xisback.c $(INPUTSCALE_SRC) $(LIBS) $(INPUTSCALE_LDLIBS)

install: xisback
	install -Dm755 xisback $(DESTDIR)$(BINDIR)/xisback

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/xisback

clean:
	rm -f xisback

.PHONY: clean install uninstall
