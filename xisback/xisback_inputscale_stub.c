/*
 * xisback_inputscale_stub.c - built instead of xisback_inputscale.c when
 * xcb/xcb-randr/x11-xcb aren't available (see Makefile). X-INPUT-SCALE
 * support always reports "no confinement active", a harmless no-op:
 * wallpapers just use each CRTC's raw physical geometry, same as before
 * this feature existed.
 */
#include <X11/Xlib.h>

void xis_init(Display *dpy, Window root)
{
    (void)dpy;
    (void)root;
}

int xis_get_confine(unsigned long crtc, int *out_x, int *out_y, int *out_w, int *out_h)
{
    (void)crtc;
    (void)out_x;
    (void)out_y;
    (void)out_w;
    (void)out_h;
    return 0;
}

int xis_fd(void)
{
    return -1;
}

int xis_poll_change(void)
{
    return 0;
}
