/*
 * thumb_stub.c - drop-in replacement for thumb.c when the Makefile
 * couldn't find libXcomposite via pkg-config at build time (see
 * Makefile and mpris_stub.c/sni_stub.c for the identical reasoning).
 * thumb_available() always reports false, so tooltip.c/tasklist.c never
 * attempt a thumbnail -- show_thumbs=yes on a build without Xcomposite
 * just silently behaves as if it were unset.
 */
#include "xispanel.h"

int thumb_available(void)
{
    return 0;
}

int thumb_paint(cairo_t *cr, Window win, double x, double y, double max_w, double max_h)
{
    (void)cr;
    (void)win;
    (void)x;
    (void)y;
    (void)max_w;
    (void)max_h;
    return 0;
}

void thumb_watch(Window win)
{
    (void)win;
}

void thumb_unwatch_all(void)
{
}

int thumb_handle_event(const XEvent *ev)
{
    (void)ev;
    return 0;
}

int thumb_take_dirty(void)
{
    return 0;
}
