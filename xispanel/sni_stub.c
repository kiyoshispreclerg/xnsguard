/*
 * sni_stub.c - drop-in replacement for sni.c when the Makefile couldn't
 * find dbus-1 via pkg-config at build time (see Makefile and mpris_stub.c
 * for the identical reasoning). Every function reports "no tray items,
 * ever" -- the `tray` widget still builds and registers normally, it
 * just always paints empty.
 */
#include "xispanel.h"

void sni_poll(uint64_t now)
{
    (void)now;
}

int sni_count(void)
{
    return 0;
}

const char *sni_title(int idx)
{
    (void)idx;
    return "";
}

cairo_surface_t *sni_icon(int idx)
{
    (void)idx;
    return NULL;
}

void sni_activate(int idx, int x, int y)
{
    (void)idx;
    (void)x;
    (void)y;
}

void sni_secondary_activate(int idx, int x, int y)
{
    (void)idx;
    (void)x;
    (void)y;
}

void sni_context_menu(int idx, int x, int y)
{
    (void)idx;
    (void)x;
    (void)y;
}
