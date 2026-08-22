/*
 * density_stub.c - built instead of density.c when libxfixes-dev isn't
 * available (see Makefile) -- X-DENSITY support (TESTS/X-DENSITY.md)
 * always reports absent, every entry point a harmless no-op. Same
 * pattern as mpris_stub.c/sni_stub.c/thumb_stub.c/modtap_stub.c.
 */
#include "xispanel.h"

void density_init(void)
{
}

int density_handle_xfixes_event(const XEvent *ev)
{
    (void)ev;
    return 0;
}

int density_handle_property(Panel *p, const XPropertyEvent *ev)
{
    (void)p;
    (void)ev;
    return 0;
}

void density_render(Panel *p)
{
    (void)p;
}

void density_panel_destroyed(Panel *p)
{
    (void)p;
}
