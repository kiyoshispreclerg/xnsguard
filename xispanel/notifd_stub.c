/*
 * notifd_stub.c - drop-in replacement for notifd.c when the Makefile
 * couldn't find dbus-1 via pkg-config at build time (see Makefile).
 * Every function is a harmless no-op reporting "no notifications" --
 * callers never need to know or care which of notifd.c/notifd_stub.c
 * actually got linked in. Exactly one of the two is ever compiled.
 */
#include "xispanel.h"

void notifd_poll(uint64_t now)
{
    (void)now;
}

int notifd_count(void)
{
    return 0;
}

const NotifEntry *notifd_get(int idx)
{
    (void)idx;
    return NULL;
}

int notifd_unread_count(void)
{
    return 0;
}

void notifd_mark_read(unsigned int id)
{
    (void)id;
}

void notifd_set_arrived_callback(NotifArrivedFn fn)
{
    (void)fn;
}

void notifd_set_default_expire_ms(int ms)
{
    (void)ms;
}
