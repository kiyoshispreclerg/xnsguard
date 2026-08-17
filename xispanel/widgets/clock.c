/*
 * clock widget - shows the current time, reformatted once a second via
 * strftime(). Displays the system's configured timezone by default;
 * `tz=<IANA zone>` overrides just this widget's displayed time (e.g. a
 * secondary panel showing a coworker's timezone). `tooltip_tz=<zone,...>`
 * lists additional zones whose date+time are shown one per block in the
 * tooltip, instead of just the single current-zone line.
 */
#include "../xispanel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CLOCK_MAX_TOOLTIP_TZ 8

typedef struct {
    char format[64];
    char text[64];
    char tz[64]; /* empty = system default */
    char tooltip_tz[CLOCK_MAX_TOOLTIP_TZ][64];
    int n_tooltip_tz;
} ClockPriv;

/* localtime_r() has no "in this zone" variant in POSIX/glibc -- the
 * standard workaround is to temporarily point the TZ env var at the zone
 * of interest, call tzset() so libc re-reads it, then put TZ back exactly
 * as it was. Not signal-safe/reentrant, but xispanel is single-threaded
 * and this is only ever called from the main loop. tz=NULL/"" means "use
 * whatever TZ already says", i.e. the system default. */
static void localtime_in_tz(const char *tz, struct tm *out)
{
    char old[128];
    int had_old = 0;
    const char *cur = getenv("TZ");
    if (cur) {
        snprintf(old, sizeof(old), "%s", cur);
        had_old = 1;
    }
    if (tz && tz[0]) {
        setenv("TZ", tz, 1);
        tzset();
    }
    time_t t = time(NULL);
    localtime_r(&t, out);
    if (tz && tz[0]) {
        if (had_old) {
            setenv("TZ", old, 1);
        } else {
            unsetenv("TZ");
        }
        tzset();
    }
}

static int clock_init(PanelWidget *w)
{
    ClockPriv *cp = w->priv;
    if (!kv_get(w->config_kv, "format", cp->format, sizeof(cp->format))) {
        snprintf(cp->format, sizeof(cp->format), "%%H:%%M");
    }
    kv_get(w->config_kv, "tz", cp->tz, sizeof(cp->tz));

    char list[512];
    cp->n_tooltip_tz = 0;
    if (kv_get(w->config_kv, "tooltip_tz", list, sizeof(list))) {
        char *save = NULL;
        for (char *tok = strtok_r(list, ",", &save); tok && cp->n_tooltip_tz < CLOCK_MAX_TOOLTIP_TZ;
             tok = strtok_r(NULL, ",", &save)) {
            snprintf(cp->tooltip_tz[cp->n_tooltip_tz], sizeof(cp->tooltip_tz[0]), "%s", tok);
            cp->n_tooltip_tz++;
        }
    }

    cp->text[0] = 0;
    w->next_tick_ms = now_ms(); /* paint something immediately */
    return 0;
}

static void clock_on_tick(PanelWidget *w, uint64_t now)
{
    ClockPriv *cp = w->priv;
    struct tm tmv;
    localtime_in_tz(cp->tz, &tmv);
    strftime(cp->text, sizeof(cp->text), cp->format, &tmv);
    w->next_tick_ms = now + 1000;
}

static void clock_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    (void)cross_axis;
    ClockPriv *cp = w->priv;
    Panel *p = w->panel;
    const char *sample = cp->text[0] ? cp->text : "00:00";
    double tw;
    pango_text_extents_ellipsized(p->cr, sample, panel_text_size(p), 0, &tw, NULL);
    *out_len = (int)tw + 16;
    *out_min_len = *out_len; /* a clipped clock is worse than useless -- don't shrink it */
}

static int clock_get_tooltip(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w,
                              int *out_closable, void **out_ctx)
{
    (void)local_x;
    (void)out_closable;
    (void)out_ctx;
    ClockPriv *cp = w->priv;

    if (cp->n_tooltip_tz == 0) {
        /* No extra zones configured -- same single weekday/date + time
         * pair as before, just following this widget's own tz= override
         * (if any) instead of always the system zone, so the tooltip
         * agrees with what the panel itself is showing. */
        struct tm tmv;
        localtime_in_tz(cp->tz, &tmv);
        char line1[96], line2[32];
        strftime(line1, sizeof(line1), "%A, %d de %B de %Y", &tmv);
        strftime(line2, sizeof(line2), "%H:%M:%S", &tmv);
        snprintf(buf, bufsz, "%s\n%s", line1, line2);
    } else {
        /* One block per configured zone: zone name, then date+time,
         * separated by a blank line from the next block -- the "padding"
         * asked for so a wall of stacked times doesn't run together. */
        size_t used = 0;
        for (int i = 0; i < cp->n_tooltip_tz && used < bufsz; i++) {
            struct tm tmv;
            localtime_in_tz(cp->tooltip_tz[i], &tmv);
            char line[128];
            strftime(line, sizeof(line), "%d de %B de %Y, %H:%M:%S", &tmv);
            int n = snprintf(buf + used, bufsz - used, "%s%s\n%s\n", i > 0 ? "\n" : "", cp->tooltip_tz[i], line);
            if (n < 0) {
                break;
            }
            used += (size_t)n;
        }
    }
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
    double tw;
    pango_text_extents_ellipsized(cr, cp->text, panel_text_size(p), 0, &tw, NULL);
    double tx = x + (width - tw) / 2.0;
    pango_show_text_boxed(cr, tx, y, height, 0, panel_text_size(p), cp->text, NULL);
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
