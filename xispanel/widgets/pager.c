/*
 * pager widget - a grid of desktop buttons, click switches to one, current
 * desktop highlighted -- the classic taskbar pager.
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
 * output (see kiwm/PROTOCOL.md), so every group has the same grid shape,
 * just a different active-desktop highlight and (since each output can be
 * a different real resolution) a different button aspect ratio.
 *
 * Grid shape: read (never written -- kiconf will own writing this later)
 * from _NET_DESKTOP_LAYOUT, the same property any other EWMH pager would
 * publish for the WM's own directional desktop-switch keys. Since kiwm
 * has one uniform desktop *count* across every output, the same grid
 * shape applies to every group -- only which cell is "active" differs.
 * No property at all (not every WM sets it) falls back to a single row.
 *
 * Button aspect ratio: each button is sized proportional to the real
 * pixel resolution it represents, via RandR -- the specific output's own
 * resolution in kiwm mode (panel_lookup_output_size()), or the whole
 * screen's in plain EWMH mode (DisplayWidth/DisplayHeight), rather than a
 * fixed square.
 */
#include "../xispanel.h"

#include <X11/Xlib.h>

#include <stdio.h>
#include <string.h>

#define PAGER_MAX_OUTPUTS 16
#define PAGER_MAX_DESKTOPS 32
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
    double aspect[PAGER_MAX_OUTPUTS];       /* real width/height of the group's output (or whole screen) */

    /* Grid shape from _NET_DESKTOP_LAYOUT (or the single-row fallback),
     * same across every group -- see the file comment. */
    int cols, rows;
    int orientation;     /* 0 = horz (row-major), 1 = vert (column-major) */
    int starting_corner; /* 0=TOPLEFT 1=TOPRIGHT 2=BOTTOMRIGHT 3=BOTTOMLEFT */

    /* Recomputed by pager_compute_geometry() every measure/paint/on_button
     * call from the widget's real allotted thickness, same "never
     * disagree" pattern tasklist/tray/winctl/globalmenu all use for their
     * own hit-testing. */
    int row_h;
    int btn_w[PAGER_MAX_OUTPUTS];   /* per-group button width (aspect differs per real output) */
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

/* Derives the actual grid shape from _NET_DESKTOP_LAYOUT's raw values
 * (either of which may be 0, meaning "as many as needed" per the spec) and
 * the real desktop count -- or a single row if the property isn't set at
 * all. */
static void pager_derive_grid(int n_desktops, int layout_ok, int raw_cols, int raw_rows, int *out_cols,
                               int *out_rows)
{
    int cols = raw_cols, rows = raw_rows;
    if (!layout_ok || (cols <= 0 && rows <= 0)) {
        cols = n_desktops;
        rows = 1;
    } else if (cols <= 0) {
        cols = (n_desktops + rows - 1) / rows;
    } else if (rows <= 0) {
        rows = (n_desktops + cols - 1) / cols;
    }
    *out_cols = cols < 1 ? 1 : cols;
    *out_rows = rows < 1 ? 1 : rows;
}

/* Maps a grid cell to its desktop index per _NET_DESKTOP_LAYOUT's
 * orientation/starting_corner semantics -- see the EWMH spec's
 * _NET_DESKTOP_LAYOUT section. Used both to paint each cell (iterating
 * cells, looking up which desktop belongs there) and to hit-test a click
 * (same lookup, on the clicked cell). */
static int pager_rc_to_desktop(int r, int c, int cols, int rows, int orientation, int corner)
{
    if (corner == 1 || corner == 2) {
        c = cols - 1 - c;
    }
    if (corner == 2 || corner == 3) {
        r = rows - 1 - r;
    }
    return orientation == 1 ? c * rows + r : r * cols + c;
}

/* Refreshes everything pager_paint()/pager_on_button() need from the live
 * EWMH/kiwm/RandR state -- see the file comment for the two data sources.
 * Returns 1 if anything that affects what's drawn actually changed since
 * the last call. */
static int pager_refresh(PanelWidget *w)
{
    PagerPriv *pp = w->priv;
    Panel *p = w->panel;

    PagerPriv old = *pp;

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
        for (int g = 0; g < pp->n_groups; g++) {
            int ow, oh;
            pp->aspect[g] = panel_lookup_output_size(names[pp->kiwm_output_idx[g]], &ow, &oh) && oh > 0
                                ? (double)ow / oh
                                : 1.0;
        }
    } else {
        int n = ewmh_get_number_of_desktops();
        pp->n_desktops = n > 0 ? n : 1;
        pp->n_groups = 1;
        int cur = ewmh_get_current_desktop();
        pp->active_desktop[0] = cur >= 0 ? cur : 0;
        int sw = DisplayWidth(g_dpy, g_screen);
        int sh = DisplayHeight(g_dpy, g_screen);
        pp->aspect[0] = sh > 0 ? (double)sw / sh : 1.0;
    }
    if (pp->n_desktops > PAGER_MAX_DESKTOPS) {
        pp->n_desktops = PAGER_MAX_DESKTOPS;
    }

    int raw_cols = 0, raw_rows = 0, orientation = 0, corner = 0;
    int layout_ok = ewmh_get_desktop_layout(&raw_cols, &raw_rows, &orientation, &corner);
    pager_derive_grid(pp->n_desktops, layout_ok, raw_cols, raw_rows, &pp->cols, &pp->rows);
    pp->orientation = layout_ok ? orientation : 0;
    pp->starting_corner = layout_ok ? corner : 0;

    return old.is_kiwm != pp->is_kiwm || old.n_desktops != pp->n_desktops || old.n_groups != pp->n_groups ||
           old.cols != pp->cols || old.rows != pp->rows || old.orientation != pp->orientation ||
           old.starting_corner != pp->starting_corner ||
           memcmp(old.kiwm_output_idx, pp->kiwm_output_idx, sizeof(old.kiwm_output_idx)) != 0 ||
           memcmp(old.active_desktop, pp->active_desktop, sizeof(old.active_desktop)) != 0 ||
           memcmp(old.aspect, pp->aspect, sizeof(old.aspect)) != 0;
}

static int pager_on_tick(PanelWidget *w, uint64_t now)
{
    w->next_tick_ms = now + PAGER_POLL_MS;
    return pager_refresh(w);
}

/* Shared by measure/paint/on_button -- fills pp->row_h/btn_w[]/group_x[]
 * for the given thickness (the widget's cross-axis size: cross_axis at
 * measure() time, always the same value as w->thickness by the time
 * paint()/on_button() run it again). Returns the total along-panel length. */
static int pager_compute_geometry(PagerPriv *pp, int thickness)
{
    pp->row_h = pp->rows > 0 ? thickness / pp->rows : thickness;
    if (pp->row_h < 1) {
        pp->row_h = 1;
    }
    int x = 0;
    for (int g = 0; g < pp->n_groups; g++) {
        int bw = (int)(pp->row_h * pp->aspect[g] + 0.5);
        if (bw < 1) {
            bw = 1;
        }
        pp->btn_w[g] = bw;
        pp->group_x[g] = x;
        x += pp->cols * bw + PAGER_GROUP_GAP;
    }
    return pp->n_groups > 0 ? x - PAGER_GROUP_GAP : 0;
}

static void pager_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    PagerPriv *pp = w->priv;
    int len = pager_compute_geometry(pp, cross_axis);
    *out_len = len;
    *out_min_len = len;
}

static void pager_paint(PanelWidget *w, cairo_t *cr)
{
    PagerPriv *pp = w->priv;
    Panel *p = w->panel;
    int ox, oy, owidth, oheight;
    widget_get_rect(w, &ox, &oy, &owidth, &oheight);
    (void)owidth;
    (void)oheight;
    pager_compute_geometry(pp, w->thickness);

    int hover_local_x, hover_local_y;
    int has_hover = panel_widget_hover_local_x(w, &hover_local_x) && panel_widget_hover_local_y(w, &hover_local_y);

    for (int g = 0; g < pp->n_groups; g++) {
        for (int r = 0; r < pp->rows; r++) {
            for (int c = 0; c < pp->cols; c++) {
                int d = pager_rc_to_desktop(r, c, pp->cols, pp->rows, pp->orientation, pp->starting_corner);
                if (d < 0 || d >= pp->n_desktops) {
                    continue; /* grid cell with no matching desktop */
                }
                int bx = ox + pp->group_x[g] + c * pp->btn_w[g];
                int by = oy + r * pp->row_h;
                int local_x = pp->group_x[g] + c * pp->btn_w[g];
                int local_y = r * pp->row_h;

                if (has_hover && hover_local_x >= local_x && hover_local_x < local_x + pp->btn_w[g] &&
                    hover_local_y >= local_y && hover_local_y < local_y + pp->row_h) {
                    widget_paint_hover_cell(w, cr, local_x, local_y, pp->btn_w[g], pp->row_h);
                }
                if (d == pp->active_desktop[g]) {
                    cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.18);
                    cairo_rectangle(cr, bx, by, pp->btn_w[g], pp->row_h);
                    cairo_fill(cr);
                }
                cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.4);
                cairo_rectangle(cr, bx + 1.5, by + 1.5, pp->btn_w[g] - 3, pp->row_h - 3);
                cairo_set_line_width(cr, 1);
                cairo_stroke(cr);

                char label[8];
                snprintf(label, sizeof(label), "%d", d + 1);
                double tw;
                pango_text_extents_ellipsized(cr, label, panel_text_size(p), 0, &tw, NULL);
                cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, d == pp->active_desktop[g] ? 0.95 : 0.6);
                pango_show_text_boxed(cr, bx + (pp->btn_w[g] - tw) / 2.0, by, pp->row_h, pp->btn_w[g],
                                       panel_text_size(p), label, NULL);
            }
        }
        if (g < pp->n_groups - 1) {
            double sep_x = ox + pp->group_x[g] + pp->cols * pp->btn_w[g] + PAGER_GROUP_GAP / 2.0;
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
    (void)root_x;
    (void)root_y;
    PagerPriv *pp = w->priv;
    if (button != Button1 || pp->n_groups <= 0) {
        return 0;
    }
    pager_compute_geometry(pp, w->thickness);
    if (pp->row_h <= 0) {
        return 0;
    }

    for (int g = 0; g < pp->n_groups; g++) {
        int group_end = pp->group_x[g] + pp->cols * pp->btn_w[g];
        if (local_x < pp->group_x[g] || local_x >= group_end) {
            continue;
        }
        int c = (local_x - pp->group_x[g]) / pp->btn_w[g];
        int r = local_y / pp->row_h;
        if (c < 0 || c >= pp->cols || r < 0 || r >= pp->rows) {
            return 0;
        }
        int d = pager_rc_to_desktop(r, c, pp->cols, pp->rows, pp->orientation, pp->starting_corner);
        if (d < 0 || d >= pp->n_desktops) {
            return 0; /* clicked an empty grid cell */
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
