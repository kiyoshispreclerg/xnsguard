/*
 * mpris_stub.c - drop-in replacement for mpris.c when the Makefile
 * couldn't find dbus-1 via pkg-config at build time (see Makefile).
 * Every function is a harmless no-op that reports "nothing found" --
 * callers (tasklist.c) never need to know or care which of mpris.c/
 * mpris_stub.c actually got linked in. Exactly one of the two is ever
 * compiled; unlike mpris.c's runtime dlopen() of libdbus-1.so.3 (for
 * systems that have the dev headers but not the runtime library), this
 * is for systems that don't even have the dbus-1 *dev headers* to build
 * mpris.c against <dbus/dbus.h> in the first place.
 */
#include "xispanel.h"

void mpris_poll(uint64_t now)
{
    (void)now;
}

int mpris_find_for_pid(unsigned long pid, char *out_busname, size_t bufsz, int *out_playing)
{
    (void)pid;
    (void)out_busname;
    (void)bufsz;
    (void)out_playing;
    return 0;
}

void mpris_play_pause(const char *busname)
{
    (void)busname;
}

void mpris_next(const char *busname)
{
    (void)busname;
}

void mpris_previous(const char *busname)
{
    (void)busname;
}
