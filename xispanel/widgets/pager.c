/*
 * pager widget - one square button per virtual desktop, click switches to
 * it, current desktop highlighted -- the classic taskbar pager.
 *
 * Two data sources, picked automatically at every tick (see ewmh.c's
 * ewmh_kiwm_get_outputs() doc comment for why): kiwm's own per-output
 * desktop extension (kiwm/PROTOCOL.md) when a _KIWM_OUTPUTS property is
 * present on the root window, otherwise the plain global EWMH pair
 * (_NET_NUMBER_OF_DESKTOPS/_NET_CURRENT_DESKTOP) every other WM exposes.
 * Standard EWMH has no concept of "this output is on desktop 2 while that
 * one is on desktop 0" at all -- under plain EWMH there's only ever one
 * desktop set, shared by the whole session, so same_output_only=yes is a
 * no-op there (nothing to restrict *to*).
 *
 * `same_output_only` (kiwm mode only, defaults to yes): show just the
 * output this panel's own THEME/PANEL `output=` name matches, instead of
 * every output's desktops side by side -- this mirrors plain EWMH mode,
 * where there's only ever one desktop *count* to show (the global one);
 * defaulting kiwm mode to "just this output's own desktops" gives the
 * same single-group-of-squares look by default in both modes, with the
 * multi-output view as an opt-in (`same_output_only=no`). Matched by name
 * against kiwm's _KIWM_OUTPUTS list -- a panel configured with output=*
 * (spanning every output, no single one to restrict to) falls back to
 * showing all of them regardless of this setting.
 *
 * Multiple outputs (kiwm mode, same_output_only=no) are drawn as separate
 * button groups side by side, each with its own PAGER_GROUP_GAP-wide
 * separator -- kiwm's model has a *uniform* desktop count across every
 * output (see kiwm/PROTOCOL.md), so every group is the same width, just
 * with a different active-desktop highlight.
 */
#include "../xispanel.h"

#include <X11/Xlib.h>

#include <stdio.h>
#include <string.h>

#define PAGER_MAX_OUTPUTS 16
#define PAGER_MAX_DESKTOPS 32
#define PAGER_MAX_BTNS (PAGER_MAX_OUTPUTS * PAGER_MAX_DESKTOPS)
#define PAGER_GROUP_GAP 10
#define PAGER_POLL_MS 500

typedef struct {
    int same_output_only;

    /* Refreshed every on_tick() -- see the file comment. */
    int is_kiwm;
    int n_desktops; /* per group -- uniform across every displayed group */
    int n_groups;
    int kiwm_output_idx[PAGER_MAX_OUTPUTS]; /* real _KIWM_OUTPUTS index per displayed group, kiwm mode only */
    int active_desktop[PAGER_MAX_OUTPUTS];  /* highlighted desktop within each group */

    /* Recomputed by pager_layout() every paint/on_button call from the
     * widget's real allotted w->len, same "never disagree" pattern
     * tasklist/tray/winctl/globalmenu all use for their own hit-testing. */
    int btn_w;
    int group_x[PAGER_MAX_OUTPUTS]; /* left edge of group g's first button */
} PagerPriv;

static int pager_init(PanelWidget *w)
{
    PagerPriv *pp = w->priv;
    char buf[16];
    pp->same_output_only = !(kv_get(w->config_kv, "same_output_only", buf, sizeof(buf)) && !strcmp(buf, "no"));
    w->next_tick_ms = now_ms();
    return 0;
}

/* Refreshes pp->is_kiwm/n_desktops/n_groups/kiwm_output_idx[]/
 * active_desktop[] from the live EWMH/kiwm properties -- see the file
 * comment for the two data sources. Returns 1 if anything that affects
 * what's drawn actually changed since the last call. */
static int pager_refresh(PanelWidget *w)
{
    PagerPriv *pp = w->priv;
    Panel *p = w->panel;

    int o_is_kiwm = pp->is_kiwm, o_n_desktops = pp->n_desktops, o_n_groups = pp->n_groups;
    int o_kiwm_idx[PAGER_MAX_OUTPUTS], o_active[PAGER_MAX_OUTPUTS];
    memcpy(o_kiwm_idx, pp->kiwm_output_idx, sizeof(o_kiwm_idx));
    memcpy(o_active, pp->active_desktop, sizeof(o_active));

    char names[PAGER_MAX_OUTPUTS][64];
    int n_outputs = 0;
    pp->is_kiwm = ewmh_kiwm_get_outputs(names, PAGER_MAX_OUTPUTS, &n_outputs);

    if (pp->is_kiwm) {
        int desktops[PAGER_MAX_OUTPUTS];
        int n_read = ewmh_kiwm_get_output_desktops(desktops, PAGER_MAX_OUTPUTS);
        int num_per_output = ewmh_kiwm_get_num_output_desktops();
        pp->n_desktops = num_per_output > 0 ? num_per_output : 1;

        int match = -1;
        if (pp->same_output_only) {
            for (int i = 0; i < n_outputs; i++) {
                if (strcmp(names[i], p->output) == 0) {
                    match = i;
                    break;
                }
            }
        }
        pp->n_groups = 0;
        if (match >= 0) {
            pp->kiwm_output_idx[pp->n_groups] = match;
            pp->active_desktop[pp->n_groups] = match < n_read ? desktops[match] : 0;
            pp->n_groups++;
        } else {
            for (int i = 0; i < n_outputs && pp->n_groups < PAGER_MAX_OUTPUTS; i++) {
                pp->kiwm_output_idx[pp->n_groups] = i;
                pp->active_desktop[pp->n_groups] = i < n_read ? desktops[i] : 0;
                pp->n_groups++;
            }
        }
    } else {
        int n = ewmh_get_number_of_desktops();
        pp->n_desktops = n > 0 ? n : 1;
        pp->n_groups = 1;
        int cur = ewmh_get_current_desktop();
        pp->active_desktop[0] = cur >= 0 ? cur : 0;
    }
    if (pp->n_desktops > PAGER_MAX_DESKTOPS) {
        pp->n_desktops = PAGER_MAX_DESKTOPS;
    }

    return o_is_kiwm != pp->is_kiwm || o_n_desktops != pp->n_desktops || o_n_groups != pp->n_groups ||
           memcmp(o_kiwm_idx, pp->kiwm_output_idx, sizeof(o_kiwm_idx)) != 0 ||
           memcmp(o_active, pp->active_desktop, sizeof(o_active)) != 0;
}

static int pager_on_tick(PanelWidget *w, uint64_t now)
{
    w->next_tick_ms = now + PAGER_POLL_MS;
    return pager_refresh(w);
}

static void pager_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    PagerPriv *pp = w->priv;
    int btn_w = cross_axis;
    int len = pp->n_groups > 0 ? pp->n_groups * pp->n_desktops * btn_w + (pp->n_groups - 1) * PAGER_GROUP_GAP : 0;
    *out_len = len;
    *out_min_len = len;
}

/* Shared by paint/on_button -- fills pp->btn_w/group_x[] from the
 * widget's actual allotted w->len (which may be less than what
 * pager_measure() reported if panel_layout() had to shrink it to fit). */
static void pager_layout(PanelWidget *w)
{
    PagerPriv *pp = w->priv;
    pp->btn_w = w->thickness;
    int x = 0;
    for (int g = 0; g < pp->n_groups; g++) {
        pp->group_x[g] = x;
        x += pp->n_desktops * pp->btn_w + PAGER_GROUP_GAP;
    }
}

static void pager_paint(PanelWidget *w, cairo_t *cr)
{
    PagerPriv *pp = w->priv;
    Panel *p = w->panel;
    int ox, oy, owidth, oheight;
    widget_get_rect(w, &ox, &oy, &owidth, &oheight);
    (void)owidth;
    (void)oheight;
    pager_layout(w);

    int hover_local_x;
    int has_hover = panel_widget_hover_local_x(w, &hover_local_x);

    for (int g = 0; g < pp->n_groups; g++) {
        for (int d = 0; d < pp->n_desktops; d++) {
            int bx = ox + pp->group_x[g] + d * pp->btn_w;
            int local_x = pp->group_x[g] + d * pp->btn_w;

            if (has_hover && hover_local_x >= local_x && hover_local_x < local_x + pp->btn_w) {
                widget_paint_hover_rect(w, cr, local_x, pp->btn_w);
            }
            if (d == pp->active_desktop[g]) {
                cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.18);
                cairo_rectangle(cr, bx, oy, pp->btn_w, w->thickness);
                cairo_fill(cr);
            }
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.4);
            cairo_rectangle(cr, bx + 1.5, oy + 1.5, pp->btn_w - 3, w->thickness - 3);
            cairo_set_line_width(cr, 1);
            cairo_stroke(cr);

            char label[8];
            snprintf(label, sizeof(label), "%d", d + 1);
            double tw;
            pango_text_extents_ellipsized(cr, label, panel_text_size(p), 0, &tw, NULL);
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, d == pp->active_desktop[g] ? 0.95 : 0.6);
            pango_show_text_boxed(cr, bx + (pp->btn_w - tw) / 2.0, oy, w->thickness, pp->btn_w, panel_text_size(p),
                                   label, NULL);
        }
        if (g < pp->n_groups - 1) {
            double sep_x = ox + pp->group_x[g] + pp->n_desktops * pp->btn_w + PAGER_GROUP_GAP / 2.0;
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.25);
            cairo_set_line_width(cr, 1);
            cairo_move_to(cr, sep_x, oy + 4);
            cairo_line_to(cr, sep_x, oy + w->thickness - 4);
            cairo_stroke(cr);
        }
    }
}

static int pager_on_button(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y)
{
    (void)local_y;
    (void)root_x;
    (void)root_y;
    PagerPriv *pp = w->priv;
    if (button != Button1 || pp->n_groups <= 0 || pp->btn_w <= 0) {
        return 0;
    }
    pager_layout(w);

    for (int g = 0; g < pp->n_groups; g++) {
        int group_end = pp->group_x[g] + pp->n_desktops * pp->btn_w;
        if (local_x < pp->group_x[g] || local_x >= group_end) {
            continue;
        }
        int d = (local_x - pp->group_x[g]) / pp->btn_w;
        if (d < 0 || d >= pp->n_desktops) {
            return 0;
        }
        if (pp->is_kiwm) {
            ewmh_kiwm_set_output_desktop(pp->kiwm_output_idx[g], d);
        } else {
            ewmh_set_current_desktop(d);
        }
        XFlush(g_dpy);
        return 1;
    }
    return 0;
}

const PanelWidgetOps pager_ops = {
    .type_name = "pager",
    .priv_size = sizeof(PagerPriv),
    .init = pager_init,
    .measure = pager_measure,
    .paint = pager_paint,
    .on_button = pager_on_button,
    .on_tick = pager_on_tick,
};
