/*
 * inputscale_stub.c - built instead of inputscale.c when xcb/xcb-randr/
 * x11-xcb aren't available (see Makefile) -- X-INPUT-SCALE support always
 * reports "no confinement active", a harmless no-op. Same pattern as
 * mpris_stub.c/sni_stub.c/thumb_stub.c/modtap_stub.c/density_stub.c.
 */
#include "xispanel.h"

void inputscale_init(void)
{
}

int inputscale_get_confine(unsigned long crtc, int *out_x, int *out_y, int *out_w, int *out_h)
{
    (void)crtc;
    (void)out_x;
    (void)out_y;
    (void)out_w;
    (void)out_h;
    return 0;
}

int inputscale_fd(void)
{
    return -1;
}

int inputscale_poll_change(void)
{
    return 0;
}
