/*
 * clock widget - shows the current time, reformatted once a second via
 * strftime(). No timezone popup yet (see the phased plan).
 */
#include "../xispanel.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct {
    char format[64];
    char text[64];
} ClockPriv;

static int clock_init(PanelWidget *w)
{
    ClockPriv *cp = w->priv;
    if (!kv_get(w->config_kv, "format", cp->format, sizeof(cp->format))) {
        snprintf(cp->format, sizeof(cp->format), "%%H:%%M");
    }
    cp->text[0] = 0;
    w->next_tick_ms = now_ms(); /* paint something immediately */
    return 0;
}

static void clock_on_tick(PanelWidget *w, uint64_t now)
{
    ClockPriv *cp = w->priv;
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(cp->text, sizeof(cp->text), cp->format, &tmv);
    w->next_tick_ms = now + 1000;
}

static void clock_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    (void)cross_axis;
    ClockPriv *cp = w->priv;
    Panel *p = w->panel;
    const char *sample = cp->text[0] ? cp->text : "00:00";
    cairo_text_extents_t ext;
    cairo_text_extents(p->cr, sample, &ext);
    *out_len = (int)ext.x_advance + 16;
    *out_min_len = *out_len; /* a clipped clock is worse than useless -- don't shrink it */
}

static int clock_get_tooltip(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w,
                              int *out_closable, void **out_ctx)
{
    (void)local_x;
    (void)out_closable;
    (void)out_ctx;
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    /* Full weekday + date on one line, HH:MM:SS on the next -- locale-aware
     * (see setlocale(LC_TIME) in main()), unlike the panel's short format. */
    char line1[96], line2[32];
    strftime(line1, sizeof(line1), "%A, %d de %B de %Y", &tmv);
    strftime(line2, sizeof(line2), "%H:%M:%S", &tmv);
    snprintf(buf, bufsz, "%s\n%s", line1, line2);
    *anchor_x = 0;
    *anchor_w = w->len;
    return 1;
}

static void clock_paint(PanelWidget *w, cairo_t *cr)
{
    ClockPriv *cp = w->priv;
    Panel *p = w->panel;
    int x, y, width, height;
    widget_get_rect(w, &x, &y, &width, &height);

    cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, p->fg_a);
    cairo_text_extents_t ext;
    cairo_text_extents(cr, cp->text, &ext);
    double tx = x + (width - ext.width) / 2.0 - ext.x_bearing;
    double ty = y + (height - ext.height) / 2.0 - ext.y_bearing;
    cairo_move_to(cr, tx, ty);
    cairo_show_text(cr, cp->text);
}

const PanelWidgetOps clock_ops = {
    .type_name = "clock",
    .priv_size = sizeof(ClockPriv),
    .init = clock_init,
    .destroy = NULL,
    .measure = clock_measure,
    .paint = clock_paint,
    .on_button = NULL,
    .on_tick = clock_on_tick,
    .get_tooltip = clock_get_tooltip,
};
