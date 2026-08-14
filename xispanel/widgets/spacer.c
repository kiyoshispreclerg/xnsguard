/*
 * spacer widget - fixed-size gap, or (if no size is configured) a greedy
 * filler that eats whatever space is left, splitting it evenly with any
 * other greedy spacer on the same panel. A greedy spacer before a
 * fixed-size widget right-aligns everything after it.
 */
#include "../xispanel.h"

typedef struct {
    int fixed_size; /* 0 = greedy */
} SpacerPriv;

static int spacer_init(PanelWidget *w)
{
    SpacerPriv *sp = w->priv;
    sp->fixed_size = kv_get_int(w->config_kv, "size", 0);
    return 0;
}

static void spacer_measure(PanelWidget *w, int cross_axis, int *out_len)
{
    (void)cross_axis;
    SpacerPriv *sp = w->priv;
    *out_len = sp->fixed_size > 0 ? sp->fixed_size : -1;
}

static void spacer_paint(PanelWidget *w, cairo_t *cr)
{
    (void)w;
    (void)cr; /* transparent: the panel background already shows through */
}

const PanelWidgetOps spacer_ops = {
    .type_name = "spacer",
    .priv_size = sizeof(SpacerPriv),
    .init = spacer_init,
    .destroy = NULL,
    .measure = spacer_measure,
    .paint = spacer_paint,
    .on_button = NULL,
    .on_tick = NULL,
};
