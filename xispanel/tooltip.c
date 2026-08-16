/*
 * tooltip.c - generic hover-tooltip popup.
 *
 * Any widget can opt in by implementing PanelWidgetOps.get_tooltip(); this
 * file doesn't know what the text means, only how to time/position/draw
 * it. It's positioned just outside the panel's own rectangle (below a top
 * panel, above a bottom one, beside a left/right one), the same
 * convention plasmashell's tooltips use, so it never overlaps a panel
 * widget.
 *
 * Unlike menu.c's popup, this one takes no pointer/keyboard grab: it's
 * meant to coexist with normal desktop interaction, not take it over.
 * That means dismissal can't rely on "any click outside the grab" like
 * menu.c does -- instead, closing is driven by a short hover-intent grace
 * period (see close_deadline below) so the pointer can cross from the
 * panel widget into the popup itself (to click something in it) without
 * the popup vanishing out from under it.
 *
 * A widget can optionally make its tooltip clickable (get_tooltip()
 * reporting *out_closable = 1) -- e.g. tasklist's tooltip can activate
 * the window it describes, or close it via a small icon in the corner.
 * Widgets that don't need that (clock, winctl) just leave it at 0 and
 * the popup stays purely informational.
 *
 * Only one tooltip can be pending/shown at a time, mirroring menu.c.
 */
#include "xispanel.h"

#include <X11/Xatom.h>
#include <cairo/cairo-xlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Show-delay is per-panel and configurable (PANEL's tooltip_delay=<ms>,
 * default 500, 0 = instant) -- see Panel::tooltip_delay_ms. Close-delay
 * (hover-intent grace window before an actual close) is likewise per-panel
 * and configurable (tooltip_close_delay=<ms>, default 300, 0 = instant) --
 * see Panel::tooltip_close_delay_ms and close_delay_ms() below. */
#define TOOLTIP_REFRESH_MS 1000 /* how often to re-poll get_tooltip() while shown */
#define THUMB_FALLBACK_DEFAULT_MS 33 /* used when the panel's output refresh rate is unknown -- see
                                        * thumb_fallback_interval_ms() */
#define TOOLTIP_GAP 0 /* no dead zone between panel and popup, so the pointer
                        * can cross directly from one to the other */
#define TOOLTIP_PAD_X 10
#define TOOLTIP_PAD_Y 6
#define TOOLTIP_FONT_SIZE 13.0
#define TOOLTIP_MAX_LINES 4
#define TOOLTIP_CLOSE_ICON 14
#define MPRIS_BTN_SIZE 22
#define MPRIS_BTN_GAP 4
#define MPRIS_ROW_H (MPRIS_BTN_SIZE + TOOLTIP_PAD_Y)
#define THUMB_W 200
#define THUMB_H 130
#define THUMB_MARGIN 6 /* gap between the thumbnail and whatever's drawn below it */

/* Grouped-item (tasklist group=yes) tooltip layout -- a completely separate
 * rendering mode from the single-item text/thumb/mpris one above, see the
 * g_has_group branches in show_popup()/paint_popup()/handle_popup_click().
 * Cells are arranged in a row-major grid, wrapping to a new row once the
 * output's width is exhausted and capping the row count once its height
 * is too -- see compute_group_grid(). */
/* Same size as the single-window tooltip's thumbnail (THUMB_W/H) -- the
 * tooltip is meant to grow with the group instead of shrinking thumbnails
 * to fit, capped by compute_group_grid()'s wrap/"+N mais" overflow
 * handling rather than by making each cell smaller. */
#define GROUP_THUMB_W THUMB_W
#define GROUP_THUMB_H THUMB_H
#define GROUP_CELL_GAP 8
#define GROUP_TITLE_ROW_H (TOOLTIP_CLOSE_ICON + 6) /* title + close icon share this row, under the thumbnail */
#define GROUP_TITLE_MAXW 150 /* text-mode cell content width cap before ellipsis */
#define GROUP_ROW_GAP 6
#define GROUP_SCREEN_MARGIN 24 /* stay this far from the output's edges */

typedef struct {
    Window win;
    cairo_surface_t *surface; /* window-backed -- only ever touched by the one atomic blit at the end of paint_popup() */
    cairo_t *cr;
    /* Offscreen composition buffer, same size as the window -- every
     * paint_popup()/paint_popup_group() drawing call targets this, not
     * `cr` above, so a damage-driven thumbnail repaint (which can happen
     * many times a second for a busy window) never shows the window
     * itself mid-draw (background cleared, then border, then text, then
     * thumbnail, each a separate visible frame on an unbuffered window
     * surface -- exactly the flicker plasmashell-style live thumbnails
     * don't have). The window surface only ever receives one `cairo_
     * paint()` of this fully-composed buffer per repaint. */
    cairo_surface_t *back;
    cairo_t *back_cr;
    int width, height;
    /* Close-icon hit-rect, in popup-local coordinates; only meaningful
     * when g_closable. */
    int close_x, close_y, close_w, close_h;
    /* previous/play-pause/next button hit-rects, only meaningful when
     * g_has_mpris. */
    int mpris_btn_x[3], mpris_btn_y, mpris_btn_size;
    /* y where "normal" content (text/close-icon/mpris row) starts --
     * 0 unless g_has_thumb, in which case it's THUMB_H + THUMB_MARGIN,
     * pushed down to make room for the thumbnail drawn at the top. */
    int content_y0;

    /* Only meaningful when g_has_group -- see the comment above. */
    int group_shown_n; /* items actually laid out (<= g_group_n) */
    int group_more; /* items folded into the trailing "+N mais" cell, 0 if none */
    int group_thumbs; /* 1 = thumbnail grid cells, 0 = plain text rows */
    int group_item_x[TOOLTIP_GROUP_MAX_ITEMS], group_item_y[TOOLTIP_GROUP_MAX_ITEMS];
    int group_item_w[TOOLTIP_GROUP_MAX_ITEMS], group_item_h[TOOLTIP_GROUP_MAX_ITEMS]; /* whole cell, click = activate */
    int group_close_x[TOOLTIP_GROUP_MAX_ITEMS], group_close_y[TOOLTIP_GROUP_MAX_ITEMS];
} TooltipPopup;

static TooltipPopup *g_popup = NULL;

/* Hover target currently pending (waiting out its panel's tooltip_delay_ms)
 * or shown. */
static Panel *g_panel = NULL;
static PanelWidget *g_widget = NULL;
static int g_local_x = 0;
static int g_anchor_x = 0, g_anchor_w = 0;
static char g_text[256];
static uint64_t g_since_ms = 0;
static uint64_t g_last_refresh_ms = 0;
static uint64_t g_last_thumb_paint_ms = 0;
static int g_shown = 0;
static int g_closable = 0;
static void *g_ctx = NULL;

/* Set alongside g_text whenever the current hover target implements
 * get_tooltip_mpris() and reports an active player -- see mpris.c and
 * PanelWidgetOps.get_tooltip_mpris's doc comment in xispanel.h. */
static int g_has_mpris = 0;
static char g_mpris_busname[128];
static int g_mpris_playing = 0;

/* Set alongside g_text whenever the current hover target implements
 * get_tooltip_thumb() and reports a window to draw a live thumbnail of
 * -- see thumb.c and PanelWidgetOps.get_tooltip_thumb's doc comment in
 * xispanel.h. */
static int g_has_thumb = 0;
static Window g_thumb_win = None;

/* Set alongside g_text whenever the current hover target implements
 * get_tooltip_group() and reports a grouped (count > 1) item -- see
 * PanelWidgetOps.get_tooltip_group's doc comment in xispanel.h. When set,
 * this entirely replaces the normal text/close/mpris/thumb rendering
 * with a multi-window grid (see TooltipPopup's group_* fields). */
static int g_has_group = 0;
static TooltipGroupItem g_group_items[TOOLTIP_GROUP_MAX_ITEMS];
static int g_group_n = 0;

/* 0 = no close pending. Set on LeaveNotify from either the panel widget or
 * the popup itself; cleared on EnterNotify to either -- see the file
 * comment on why this replaces menu.c's grab-based dismissal here. */
static uint64_t g_close_deadline_ms = 0;

static void destroy_popup(void)
{
    if (!g_popup) {
        return;
    }
    if (g_popup->back_cr) {
        cairo_destroy(g_popup->back_cr);
    }
    if (g_popup->back) {
        cairo_surface_destroy(g_popup->back);
    }
    if (g_popup->cr) {
        cairo_destroy(g_popup->cr);
    }
    if (g_popup->surface) {
        cairo_surface_destroy(g_popup->surface);
    }
    XDestroyWindow(g_dpy, g_popup->win);
    free(g_popup);
    g_popup = NULL;
    XFlush(g_dpy);
}

void tooltip_close(void)
{
    destroy_popup();
    g_panel = NULL;
    g_widget = NULL;
    g_text[0] = 0;
    g_since_ms = 0;
    g_shown = 0;
    g_closable = 0;
    g_ctx = NULL;
    g_has_mpris = 0;
    g_mpris_busname[0] = 0;
    g_mpris_playing = 0;
    g_has_thumb = 0;
    g_thumb_win = None;
    g_has_group = 0;
    g_group_n = 0;
    g_close_deadline_ms = 0;
    thumb_unwatch_all();
}

/* Queries get_tooltip_mpris() (if `w` implements it) for `local_x`,
 * updating g_has_mpris/g_mpris_busname/g_mpris_playing. Cheap: mpris.c's
 * side of this is a lookup against its own periodically-polled cache, no
 * DBus traffic happens here. */
static void query_mpris(PanelWidget *w, int local_x)
{
    g_has_mpris = 0;
    g_mpris_busname[0] = 0;
    g_mpris_playing = 0;
    if (!w->ops->get_tooltip_mpris) {
        return;
    }
    char busname[128];
    int playing = 0;
    if (w->ops->get_tooltip_mpris(w, local_x, busname, sizeof(busname), &playing)) {
        g_has_mpris = 1;
        snprintf(g_mpris_busname, sizeof(g_mpris_busname), "%s", busname);
        g_mpris_playing = playing;
    }
}

/* Queries get_tooltip_thumb() (if `w` implements it) for `local_x`,
 * updating g_has_thumb/g_thumb_win. thumb_available() itself is cheap
 * (a cached extension check + one XGetSelectionOwner), so there's no
 * need to gate this call on anything beyond the widget implementing the
 * optional callback at all. */
static void query_thumb(PanelWidget *w, int local_x)
{
    g_has_thumb = 0;
    g_thumb_win = None;
    if (!w->ops->get_tooltip_thumb || !thumb_available()) {
        return;
    }
    Window win = None;
    if (w->ops->get_tooltip_thumb(w, local_x, &win)) {
        g_has_thumb = 1;
        g_thumb_win = win;
    }
}

/* Queries get_tooltip_group() (if `w` implements it) for `local_x`,
 * updating g_has_group/g_group_items/g_group_n. */
static void query_group(PanelWidget *w, int local_x)
{
    g_has_group = 0;
    g_group_n = 0;
    if (!w->ops->get_tooltip_group) {
        return;
    }
    int n = 0;
    if (w->ops->get_tooltip_group(w, local_x, g_group_items, TOOLTIP_GROUP_MAX_ITEMS, &n)) {
        g_has_group = 1;
        g_group_n = n;
    }
}

/* g_panel->font_size_px (system-detected or THEME's font_size=) if set,
 * else the historical fixed constant -- same layering panel_text_size()
 * (xispanel.c) applies to in-panel widget text, just for tooltip popups,
 * which are always owned by a specific panel (g_panel) so can follow
 * that same panel's setting. */
static double tooltip_font_size(void)
{
    return g_panel && g_panel->font_size_px > 0 ? g_panel->font_size_px : TOOLTIP_FONT_SIZE;
}

/* g_panel->tooltip_close_delay_ms if a panel is currently tracked, else the
 * historical fixed default -- mirrors tooltip_font_size()'s fallback
 * shape. Used both when the pointer leaves the source widget and when it
 * leaves the popup itself, so both dismissal paths share one setting. */
static uint64_t close_delay_ms(void)
{
    return (uint64_t)(g_panel ? g_panel->tooltip_close_delay_ms : 300);
}

/* Baseline repaint cadence for a shown live thumbnail, on top of (not
 * instead of) the XDamage-driven repaint -- see thumb_take_dirty()'s
 * call site in tooltip_tick(). XDamage gives near-zero-latency updates
 * when it works, but on at least one real setup damage notifications for
 * a GPU-presented (video) window stopped arriving entirely a few frames
 * after the tooltip opened, confirmed via timestamped logging: the X
 * server/compositor simply never sent another XDamageNotify, while the
 * real window kept rendering fine. That's outside this file's control to
 * fix (likely a server/compositor-side Present+Composite propagation
 * limitation), so instead of treating this as a rare safety net, it's a
 * real polling driver -- thumb_paint() re-fetching the composited pixmap
 * directly is *always* correct when called (verified live), the only
 * thing damage timing affected was how often that happened.
 *
 * Paced to half the tooltip's own panel's output refresh rate (a
 * thumbnail doesn't need to match the source window's own frame rate 1:1
 * to read as "live", and matching a high-refresh output's full rate
 * would just burn X round-trips for no visible benefit at this size) --
 * falls back to THUMB_FALLBACK_DEFAULT_MS when the rate is unknown
 * (RandR reported no usable mode timing, or the panel spans "*"/every
 * output, see Panel::out_refresh_hz). Only affordable to poll this often
 * at all because thumb_paint() caches the resolved composited window
 * instead of re-discovering (and XSync'ing) it on every single call --
 * see ThumbWatch::target's doc comment in thumb.c. */
static uint64_t thumb_fallback_interval_ms(void)
{
    double hz = g_panel ? g_panel->out_refresh_hz : 0;
    if (hz <= 1.0) {
        return THUMB_FALLBACK_DEFAULT_MS;
    }
    uint64_t ms = (uint64_t)(1000.0 / (hz / 2.0));
    if (ms < 8) {
        ms = 8; /* don't let a very high refresh rate turn this into a busy-loop */
    }
    return ms;
}

/* Splits g_text on '\n' into up to TOOLTIP_MAX_LINES lines and measures
 * them against `cr` (which must already have the tooltip font set at
 * `font_size`). */
static int measure_lines(cairo_t *cr, double font_size, char lines[TOOLTIP_MAX_LINES][128], int *out_text_w,
                          int *out_h)
{
    int n = 0;
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", g_text);
    char *save = NULL;
    char *tok = strtok_r(buf, "\n", &save);
    while (tok && n < TOOLTIP_MAX_LINES) {
        snprintf(lines[n], sizeof(lines[0]), "%s", tok);
        n++;
        tok = strtok_r(NULL, "\n", &save);
    }

    double line_h = font_size * 1.4;
    int max_w = 0;
    for (int i = 0; i < n; i++) {
        cairo_text_extents_t ext;
        cairo_text_extents(cr, lines[i], &ext);
        if ((int)ext.x_advance > max_w) {
            max_w = (int)ext.x_advance;
        }
    }
    *out_text_w = max_w;
    *out_h = (int)(n * line_h) + TOOLTIP_PAD_Y * 2;
    return n;
}

/* Draws every laid-out cell from show_popup_group_layout() -- thumbnail
 * or plain title, plus a per-item close icon -- and the trailing "+N
 * mais" note if the grid had to cap how many members fit on screen. */
static void paint_popup_group(void)
{
    Panel *p = g_panel;
    cairo_t *cr = g_popup->back_cr;
    if (g_font_face) {
        cairo_set_font_face(cr, g_font_face);
    }
    cairo_set_font_size(cr, tooltip_font_size());

    for (int i = 0; i < g_popup->group_shown_n; i++) {
        int ix = g_popup->group_item_x[i];
        int iy = g_popup->group_item_y[i];
        int ih = g_popup->group_item_h[i];
        char title[128];
        snprintf(title, sizeof(title), "%s", g_group_items[i].title);

        if (g_popup->group_thumbs) {
            if (!thumb_paint(cr, g_group_items[i].win, ix, iy, GROUP_THUMB_W, GROUP_THUMB_H)) {
                /* Window closed/unmapped, or compositor just stopped -- same
                 * graceful fallback as the single-window thumbnail: leave
                 * the reserved space blank rather than resizing mid-display. */
            }
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.95);
            /* Leave room for the close icon at the row's right edge -- title
             * is left-aligned in what's left, not centered under the whole
             * thumbnail, so it never runs under the icon. */
            trim_to_width(cr, title, sizeof(title), GROUP_THUMB_W - TOOLTIP_CLOSE_ICON - 8);
            cairo_text_extents_t ext;
            cairo_text_extents(cr, title, &ext);
            double row_y = iy + GROUP_THUMB_H;
            double tx = ix - ext.x_bearing;
            double ty = row_y + (GROUP_TITLE_ROW_H - ext.height) / 2.0 - ext.y_bearing;
            cairo_move_to(cr, tx, ty);
            cairo_show_text(cr, title);
        } else {
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.95);
            trim_to_width(cr, title, sizeof(title), GROUP_TITLE_MAXW);
            cairo_text_extents_t ext;
            cairo_text_extents(cr, title, &ext);
            double ty = iy + (ih - ext.height) / 2.0 - ext.y_bearing;
            cairo_move_to(cr, ix, ty);
            cairo_show_text(cr, title);
        }

        double cx = g_popup->group_close_x[i], cy = g_popup->group_close_y[i];
        double s = TOOLTIP_CLOSE_ICON;
        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.85);
        cairo_set_line_width(cr, 1.4);
        cairo_move_to(cr, cx + 3, cy + 3);
        cairo_line_to(cr, cx + s - 3, cy + s - 3);
        cairo_stroke(cr);
        cairo_move_to(cr, cx + 3, cy + s - 3);
        cairo_line_to(cr, cx + s - 3, cy + 3);
        cairo_stroke(cr);
    }

    if (g_popup->group_more > 0) {
        int i = g_popup->group_shown_n; /* the trailing reserved cell */
        char more[32];
        snprintf(more, sizeof(more), "+%d mais", g_popup->group_more);
        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.6);
        cairo_text_extents_t ext;
        cairo_text_extents(cr, more, &ext);
        int ix = g_popup->group_item_x[i], iy = g_popup->group_item_y[i];
        int iw = g_popup->group_item_w[i], ih = g_popup->group_item_h[i];
        double tx = ix + (iw - ext.width) / 2.0 - ext.x_bearing;
        double ty = iy + (ih - ext.height) / 2.0 - ext.y_bearing;
        cairo_move_to(cr, tx, ty);
        cairo_show_text(cr, more);
    }
}

/* Blits the fully-composed offscreen buffer onto the popup's real X
 * window in one shot -- the only point in this file that ever draws to
 * g_popup->cr (the window-backed surface), which is what keeps a
 * damage-driven thumbnail repaint from ever showing the window mid-draw
 * (background, then border, then text, then thumbnail, each as a
 * separate visible frame) -- see TooltipPopup's back/back_cr doc
 * comment. */
static void blit_and_flush(void)
{
    cairo_t *wcr = g_popup->cr;
    cairo_set_operator(wcr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_surface(wcr, g_popup->back, 0, 0);
    cairo_paint(wcr);
    cairo_surface_flush(g_popup->surface);
    XFlush(g_dpy);
}

static void paint_popup(void)
{
    if (!g_popup || !g_panel) {
        return;
    }
    Panel *p = g_panel;
    cairo_t *cr = g_popup->back_cr;
    cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_rgba(cr, p->bg_r, p->bg_g, p->bg_b, p->bg_a);
    cairo_paint(cr);
    cairo_set_operator(cr, CAIRO_OPERATOR_OVER);
    cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.15);
    cairo_rectangle(cr, 0.5, 0.5, g_popup->width - 1, g_popup->height - 1);
    cairo_set_line_width(cr, 1);
    cairo_stroke(cr);

    if (g_has_group) {
        paint_popup_group();
        blit_and_flush();
        return;
    }

    if (g_has_thumb) {
        double thumb_x = (g_popup->width - THUMB_W) / 2.0;
        if (!thumb_paint(cr, g_thumb_win, thumb_x, 0, THUMB_W, THUMB_H)) {
            /* Window closed/unmapped between query_thumb() and now, or
             * the compositor just stopped -- fall through with just the
             * reserved blank space rather than resizing the popup
             * mid-display. */
        }
    }

    double fsz = tooltip_font_size();
    if (g_font_face) {
        cairo_set_font_face(cr, g_font_face);
    }
    cairo_set_font_size(cr, fsz);

    char lines[TOOLTIP_MAX_LINES][128];
    int text_w, h;
    int n = measure_lines(cr, fsz, lines, &text_w, &h);
    double line_h = fsz * 1.4;
    int content_y0 = g_popup->content_y0;

    cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, p->fg_a);
    for (int i = 0; i < n; i++) {
        cairo_text_extents_t ext;
        cairo_text_extents(cr, lines[i], &ext);
        double ty = content_y0 + TOOLTIP_PAD_Y + i * line_h + (line_h - ext.height) / 2.0 - ext.y_bearing;
        cairo_move_to(cr, TOOLTIP_PAD_X, ty);
        cairo_show_text(cr, lines[i]);
    }

    if (g_closable) {
        double cx = g_popup->close_x, cy = g_popup->close_y;
        double s = TOOLTIP_CLOSE_ICON;
        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.85);
        cairo_set_line_width(cr, 1.4);
        cairo_move_to(cr, cx + 3, cy + 3);
        cairo_line_to(cr, cx + s - 3, cy + s - 3);
        cairo_stroke(cr);
        cairo_move_to(cr, cx + 3, cy + s - 3);
        cairo_line_to(cr, cx + s - 3, cy + 3);
        cairo_stroke(cr);
    }

    if (g_has_mpris) {
        double s = g_popup->mpris_btn_size;
        double by = g_popup->mpris_btn_y;
        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.85);

        /* previous: two left-pointing triangles */
        double bx = g_popup->mpris_btn_x[0];
        double cy = by + s / 2.0;
        cairo_move_to(cr, bx + s * 0.55, by + s * 0.2);
        cairo_line_to(cr, bx + s * 0.2, cy);
        cairo_line_to(cr, bx + s * 0.55, by + s * 0.8);
        cairo_close_path(cr);
        cairo_fill(cr);
        cairo_move_to(cr, bx + s * 0.85, by + s * 0.2);
        cairo_line_to(cr, bx + s * 0.5, cy);
        cairo_line_to(cr, bx + s * 0.85, by + s * 0.8);
        cairo_close_path(cr);
        cairo_fill(cr);

        /* play (triangle) or pause (two bars), depending on current state */
        bx = g_popup->mpris_btn_x[1];
        if (g_mpris_playing) {
            cairo_rectangle(cr, bx + s * 0.28, by + s * 0.2, s * 0.16, s * 0.6);
            cairo_fill(cr);
            cairo_rectangle(cr, bx + s * 0.56, by + s * 0.2, s * 0.16, s * 0.6);
            cairo_fill(cr);
        } else {
            cairo_move_to(cr, bx + s * 0.28, by + s * 0.18);
            cairo_line_to(cr, bx + s * 0.78, cy);
            cairo_line_to(cr, bx + s * 0.28, by + s * 0.82);
            cairo_close_path(cr);
            cairo_fill(cr);
        }

        /* next: two right-pointing triangles */
        bx = g_popup->mpris_btn_x[2];
        cairo_move_to(cr, bx + s * 0.15, by + s * 0.2);
        cairo_line_to(cr, bx + s * 0.5, cy);
        cairo_line_to(cr, bx + s * 0.15, by + s * 0.8);
        cairo_close_path(cr);
        cairo_fill(cr);
        cairo_move_to(cr, bx + s * 0.45, by + s * 0.2);
        cairo_line_to(cr, bx + s * 0.8, cy);
        cairo_line_to(cr, bx + s * 0.45, by + s * 0.8);
        cairo_close_path(cr);
        cairo_fill(cr);
    }

    blit_and_flush();
}

/* Original single-item layout (text + optional close icon/mpris row/
 * thumbnail) -- unchanged from before grouped tooltips existed, just
 * extracted so show_popup() can pick between this and
 * show_popup_group_layout() below. */
static void show_popup_single_layout(TooltipPopup *pop)
{
    /* Measure against a throwaway surface first -- need width/height to
     * create the real window. */
    cairo_surface_t *probe_surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 1, 1);
    cairo_t *probe_cr = cairo_create(probe_surf);
    double fsz = tooltip_font_size();
    if (g_font_face) {
        cairo_set_font_face(probe_cr, g_font_face);
    }
    cairo_set_font_size(probe_cr, fsz);
    char lines[TOOLTIP_MAX_LINES][128];
    int text_w, text_h;
    measure_lines(probe_cr, fsz, lines, &text_w, &text_h);
    cairo_destroy(probe_cr);
    cairo_surface_destroy(probe_surf);

    int close_reserve = g_closable ? (TOOLTIP_CLOSE_ICON + 6) : 0;
    pop->width = text_w + TOOLTIP_PAD_X * 2 + close_reserve;
    /* `body_h`/`pop->height` below are relative to content_y0, i.e. they
     * don't yet know about the thumbnail reserved above them -- that's
     * added once, right at the end, by shifting everything down. */
    int body_h = text_h;
    if (g_closable && body_h < TOOLTIP_CLOSE_ICON + TOOLTIP_PAD_Y * 2) {
        body_h = TOOLTIP_CLOSE_ICON + TOOLTIP_PAD_Y * 2;
    }
    int close_y_in_body = (body_h - TOOLTIP_CLOSE_ICON) / 2;

    if (g_has_mpris) {
        int mpris_row_w = 3 * MPRIS_BTN_SIZE + 2 * MPRIS_BTN_GAP + TOOLTIP_PAD_X * 2;
        if (mpris_row_w > pop->width) {
            pop->width = mpris_row_w;
        }
        pop->mpris_btn_y = body_h;
        body_h += MPRIS_ROW_H;
        int row_x0 = (pop->width - (3 * MPRIS_BTN_SIZE + 2 * MPRIS_BTN_GAP)) / 2;
        for (int i = 0; i < 3; i++) {
            pop->mpris_btn_x[i] = row_x0 + i * (MPRIS_BTN_SIZE + MPRIS_BTN_GAP);
        }
        pop->mpris_btn_size = MPRIS_BTN_SIZE;
    }

    if (g_has_thumb) {
        int thumb_row_w = THUMB_W + TOOLTIP_PAD_X * 2;
        if (thumb_row_w > pop->width) {
            pop->width = thumb_row_w;
        }
        pop->content_y0 = THUMB_H + THUMB_MARGIN;
    } else {
        pop->content_y0 = 0;
    }
    pop->height = pop->content_y0 + body_h;
    if (g_has_mpris) {
        pop->mpris_btn_y += pop->content_y0;
    }

    if (pop->width < 1) {
        pop->width = 1;
    }
    if (pop->height < 1) {
        pop->height = 1;
    }
    pop->close_x = pop->width - TOOLTIP_CLOSE_ICON - 6;
    pop->close_y = pop->content_y0 + close_y_in_body;
    pop->close_w = TOOLTIP_CLOSE_ICON;
    pop->close_h = TOOLTIP_CLOSE_ICON;
}

/* Splits n_items cells of cell_w x cell_h (plus GROUP_CELL_GAP/
 * GROUP_ROW_GAP between them) into a row-major grid that fits within
 * avail_w x avail_h: as many columns as fit the width, wrapping to more
 * rows for the rest -- capped at as many rows as fit the height too. If
 * even that isn't enough for every item, the last cell of the capped grid
 * is reserved for a "+N mais" note instead of silently dropping items with
 * no indication more exist. */
static void compute_group_grid(int n_items, int cell_w, int cell_h, int avail_w, int avail_h, int *out_cols,
                                int *out_rows, int *out_shown, int *out_more)
{
    int cols = avail_w / (cell_w + GROUP_CELL_GAP);
    if (cols < 1) {
        cols = 1;
    }
    if (cols > n_items) {
        cols = n_items > 0 ? n_items : 1;
    }
    int rows_for_all = (n_items + cols - 1) / cols;
    int max_rows = avail_h / (cell_h + GROUP_ROW_GAP);
    if (max_rows < 1) {
        max_rows = 1;
    }

    if (rows_for_all <= max_rows) {
        *out_cols = cols;
        *out_rows = rows_for_all;
        *out_shown = n_items;
        *out_more = 0;
        return;
    }

    int max_cells = cols * max_rows;
    int shown = max_cells - 1;
    if (shown < 1) {
        shown = 1;
    }
    if (shown >= n_items) {
        shown = n_items > 1 ? n_items - 1 : 0;
    }
    *out_cols = cols;
    *out_rows = max_rows;
    *out_shown = shown;
    *out_more = n_items - shown;
}

/* Grouped-item layout: a grid of thumbnails (if a compositor's running) or
 * plain title rows (if not), wrapped/capped to fit the output rectangle --
 * see compute_group_grid()'s doc comment for the overflow behavior. */
static void show_popup_group_layout(TooltipPopup *pop)
{
    Panel *p = g_panel;
    pop->group_thumbs = thumb_available();
    pop->content_y0 = 0;

    cairo_surface_t *probe_surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 1, 1);
    cairo_t *probe_cr = cairo_create(probe_surf);
    if (g_font_face) {
        cairo_set_font_face(probe_cr, g_font_face);
    }
    cairo_set_font_size(probe_cr, tooltip_font_size());

    int cell_w, cell_h;
    if (pop->group_thumbs) {
        cell_w = GROUP_THUMB_W;
        cell_h = GROUP_THUMB_H + GROUP_TITLE_ROW_H;
    } else {
        /* Widest title across every member (capped), so every row's close
         * icon lines up in the same column. */
        int max_tw = 0;
        for (int i = 0; i < g_group_n; i++) {
            char t[128];
            snprintf(t, sizeof(t), "%s", g_group_items[i].title);
            trim_to_width(probe_cr, t, sizeof(t), GROUP_TITLE_MAXW);
            cairo_text_extents_t ext;
            cairo_text_extents(probe_cr, t, &ext);
            if ((int)ext.x_advance > max_tw) {
                max_tw = (int)ext.x_advance;
            }
        }
        cell_w = max_tw + 10 + TOOLTIP_CLOSE_ICON + 6;
        cell_h = TOOLTIP_CLOSE_ICON + 6;
    }
    cairo_destroy(probe_cr);
    cairo_surface_destroy(probe_surf);

    int avail_w = p->out_w - 2 * GROUP_SCREEN_MARGIN;
    int avail_h = p->out_h - 2 * GROUP_SCREEN_MARGIN;
    if (avail_w < cell_w) {
        avail_w = cell_w;
    }
    if (avail_h < cell_h) {
        avail_h = cell_h;
    }

    int cols, rows, shown, more;
    compute_group_grid(g_group_n, cell_w, cell_h, avail_w, avail_h, &cols, &rows, &shown, &more);
    pop->group_shown_n = shown;
    pop->group_more = more;

    int total_cells = shown + (more > 0 ? 1 : 0);
    for (int i = 0; i < total_cells && i < TOOLTIP_GROUP_MAX_ITEMS; i++) {
        int row = i / cols;
        int col = i % cols;
        int ix = TOOLTIP_PAD_X + col * (cell_w + GROUP_CELL_GAP);
        int iy = TOOLTIP_PAD_Y + row * (cell_h + GROUP_ROW_GAP);
        pop->group_item_x[i] = ix;
        pop->group_item_y[i] = iy;
        pop->group_item_w[i] = cell_w;
        pop->group_item_h[i] = cell_h;
        if (pop->group_thumbs) {
            /* Title row, under the thumbnail -- not overlapping it -- same
             * "close icon at the row's right edge" convention as the
             * single-window tooltip's own close icon. */
            pop->group_close_x[i] = ix + cell_w - TOOLTIP_CLOSE_ICON;
            pop->group_close_y[i] = iy + GROUP_THUMB_H + (GROUP_TITLE_ROW_H - TOOLTIP_CLOSE_ICON) / 2;
        } else {
            pop->group_close_x[i] = ix + cell_w - TOOLTIP_CLOSE_ICON;
            pop->group_close_y[i] = iy + (cell_h - TOOLTIP_CLOSE_ICON) / 2;
        }
    }

    int used_cols = total_cells < cols ? total_cells : cols;
    if (used_cols < 1) {
        used_cols = 1;
    }
    int used_rows = (total_cells + cols - 1) / cols;
    if (used_rows < 1) {
        used_rows = 1;
    }
    (void)rows;
    pop->width = TOOLTIP_PAD_X * 2 + used_cols * cell_w + (used_cols - 1) * GROUP_CELL_GAP;
    pop->height = TOOLTIP_PAD_Y * 2 + used_rows * cell_h + (used_rows - 1) * GROUP_ROW_GAP;
    if (pop->width < 1) {
        pop->width = 1;
    }
    if (pop->height < 1) {
        pop->height = 1;
    }
}

static void show_popup(void)
{
    if (!g_panel || !g_widget || (!g_has_group && !g_text[0])) {
        return;
    }

    /* tooltip_reuse=1: keep the same X window (and Cairo surface) across
     * successive tooltips instead of destroying and recreating it. Only
     * the window's geometry/content changes (XMoveResizeWindow +
     * cairo_xlib_surface_set_size below), which lets a compositor's
     * "geometry change" animation (e.g. KWin) smooth the transition
     * instead of a create/destroy flicker. Every layout field pop gets
     * written below is set unconditionally by show_popup_single_layout()/
     * show_popup_group_layout() whenever it's actually read by
     * paint_popup() (gated behind the same g_has_mpris/g_has_thumb/
     * g_has_group flags), so leftover values from a previous popup's
     * layout are never drawn -- no need to zero the struct out again. */
    int reuse = g_panel->tooltip_reuse_window && g_popup != NULL;
    TooltipPopup *pop;
    if (reuse) {
        pop = g_popup;
    } else {
        destroy_popup();
        pop = calloc(1, sizeof(TooltipPopup));
        if (!pop) {
            return;
        }
    }

    if (g_has_group) {
        show_popup_group_layout(pop);
    } else {
        show_popup_single_layout(pop);
    }

    /* Glued to the panel's outer edge, centered on the anchor item --
     * plasmashell-style, never overlapping the panel itself. */
    Panel *p = g_panel;
    int panel_anchor_x = g_widget->x + g_anchor_x;
    int screen_x, screen_y;
    if (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM) {
        int anchor_screen_x0 = p->x + panel_anchor_x;
        screen_x = anchor_screen_x0 + g_anchor_w / 2 - pop->width / 2;
        screen_y = (p->edge == EDGE_TOP) ? (p->y + p->h + TOOLTIP_GAP) : (p->y - pop->height - TOOLTIP_GAP);
        if (screen_x + pop->width > p->out_x + p->out_w) {
            screen_x = p->out_x + p->out_w - pop->width;
        }
        if (screen_x < p->out_x) {
            screen_x = p->out_x;
        }
    } else {
        int anchor_screen_y0 = p->y + panel_anchor_x;
        screen_y = anchor_screen_y0 + g_anchor_w / 2 - pop->height / 2;
        screen_x = (p->edge == EDGE_LEFT) ? (p->x + p->w + TOOLTIP_GAP) : (p->x - pop->width - TOOLTIP_GAP);
        if (screen_y + pop->height > p->out_y + p->out_h) {
            screen_y = p->out_y + p->out_h - pop->height;
        }
        if (screen_y < p->out_y) {
            screen_y = p->out_y;
        }
    }

    if (reuse) {
        XMoveResizeWindow(g_dpy, pop->win, screen_x, screen_y, (unsigned)pop->width, (unsigned)pop->height);
        cairo_xlib_surface_set_size(pop->surface, pop->width, pop->height);
        XRaiseWindow(g_dpy, pop->win);
    } else {
        XSetWindowAttributes attrs;
        memset(&attrs, 0, sizeof(attrs));
        attrs.override_redirect = True;
        attrs.colormap = p->cmap;
        attrs.border_pixel = 0;
        attrs.background_pixel = 0;
        attrs.event_mask = ExposureMask | EnterWindowMask | LeaveWindowMask | ButtonPressMask;

        pop->win = XCreateWindow(g_dpy, g_root, screen_x, screen_y, (unsigned)pop->width, (unsigned)pop->height, 0,
                                  p->depth, InputOutput, p->visual,
                                  CWOverrideRedirect | CWColormap | CWBorderPixel | CWBackPixel | CWEventMask, &attrs);
        XChangeProperty(g_dpy, pop->win, g_atom_wm_window_type, XA_ATOM, 32, PropModeReplace,
                         (unsigned char *)&g_atom_wm_window_type_tooltip, 1);

        pop->surface = cairo_xlib_surface_create(g_dpy, pop->win, p->visual, pop->width, pop->height);
        pop->cr = cairo_create(pop->surface);

        XMapWindow(g_dpy, pop->win);
        XRaiseWindow(g_dpy, pop->win);
    }

    /* (Re)create the offscreen composition buffer at the current size --
     * needed on every call, not just non-reuse ones, since content/size
     * can change on a reused popup too. See TooltipPopup's back/back_cr
     * doc comment and blit_and_flush(). */
    if (pop->back_cr) {
        cairo_destroy(pop->back_cr);
    }
    if (pop->back) {
        cairo_surface_destroy(pop->back);
    }
    pop->back = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, pop->width, pop->height);
    pop->back_cr = cairo_create(pop->back);

    g_popup = pop;
    paint_popup();
    g_shown = 1;
    g_last_refresh_ms = now_ms();
    g_last_thumb_paint_ms = g_last_refresh_ms;

    /* Live-thumbnail tracking: re-sync the XDamage watch set to whatever
     * window(s) this paint actually shows a thumbnail of, so later
     * content changes repaint just this popup instead of it staying a
     * one-shot snapshot from the moment it opened -- see thumb_watch()/
     * thumb_take_dirty() in thumb.c and the dirty-flag check in
     * tooltip_tick(). Unwatch-then-rewatch on every show_popup() call
     * (not every repaint) keeps this cheap: it only runs when the tracked
     * item/text actually changed, not on every damage-triggered repaint. */
    thumb_unwatch_all();
    if (g_has_thumb) {
        thumb_watch(g_thumb_win);
    } else if (g_has_group && pop->group_thumbs) {
        for (int i = 0; i < pop->group_shown_n; i++) {
            thumb_watch(g_group_items[i].win);
        }
    }
}

/* Re-queries get_tooltip() for the current hover target and updates
 * g_text/g_closable/g_ctx, returning 1 if the text actually changed. Used
 * both to detect a different sub-item under the pointer and to keep shown
 * content (e.g. a ticking clock) current without requiring pointer
 * movement. */
static int refresh_text(void)
{
    if (!g_widget || !g_widget->ops->get_tooltip) {
        return 0;
    }
    char buf[256];
    int ax = 0, aw = g_widget->len;
    int closable = 0;
    void *ctx = NULL;
    if (!g_widget->ops->get_tooltip(g_widget, g_local_x, buf, sizeof(buf), &ax, &aw, &closable, &ctx)) {
        return 0;
    }
    int had_mpris = g_has_mpris;
    int was_playing = g_mpris_playing;
    query_mpris(g_widget, g_local_x);
    int had_thumb = g_has_thumb;
    query_thumb(g_widget, g_local_x);
    int had_group = g_has_group;
    query_group(g_widget, g_local_x);
    int changed = strcmp(g_text, buf) != 0 || g_closable != closable || had_mpris != g_has_mpris ||
                  was_playing != g_mpris_playing || had_thumb != g_has_thumb || had_group != g_has_group;
    snprintf(g_text, sizeof(g_text), "%s", buf);
    g_anchor_x = ax;
    g_anchor_w = aw;
    g_closable = closable;
    g_ctx = ctx;
    return changed;
}

void tooltip_notice_motion(Panel *p, int axis_pos)
{
    PanelWidget *hit = NULL;
    for (int i = 0; i < p->n_widgets; i++) {
        PanelWidget *w = &p->widgets[i];
        if (axis_pos >= w->x && axis_pos < w->x + w->len) {
            hit = w;
            break;
        }
    }

    if (!hit || !hit->ops->get_tooltip) {
        /* Moved onto a widget (or dead space, e.g. a spacer) that has no
         * tooltip of its own -- same hover-intent grace period as actually
         * leaving the panel (tooltip_notice_leave()), not an instant close,
         * so a quick pass over a spacer between two tooltip-bearing widgets
         * doesn't kill a tooltip the pointer is still effectively near. */
        if (g_panel == p && g_widget) {
            g_close_deadline_ms = now_ms() + close_delay_ms();
        }
        return;
    }

    int local_x = axis_pos - hit->x;
    char buf[256];
    int ax = 0, aw = hit->len;
    int closable = 0;
    void *ctx = NULL;
    if (!hit->ops->get_tooltip(hit, local_x, buf, sizeof(buf), &ax, &aw, &closable, &ctx)) {
        /* Inside a widget that has tooltips (tasklist, tray) but between
         * two sub-items (button/icon padding) -- same grace period as the
         * "no tooltip at all" branch above, not an instant close, so a
         * quick pass over that padding doesn't kill a tooltip the pointer
         * is still effectively near (and, with tooltip_reuse=1, so the
         * still-open window is there to reuse once it reaches the next
         * sub-item instead of having already been torn down). */
        if (g_panel == p && g_widget) {
            g_close_deadline_ms = now_ms() + close_delay_ms();
        }
        return;
    }

    g_close_deadline_ms = 0; /* pointer is over the source widget again */

    if (g_widget == hit && g_anchor_x == ax && g_anchor_w == aw) {
        /* Same sub-item as before: keep waiting, or keep showing (and
         * refresh in case content changed under a stationary pointer). */
        g_local_x = local_x;
        g_ctx = ctx;
        int had_mpris = g_has_mpris;
        int was_playing = g_mpris_playing;
        query_mpris(hit, local_x);
        query_thumb(hit, local_x);
        int had_group = g_has_group;
        int had_group_n = g_group_n;
        query_group(hit, local_x);
        if (strcmp(g_text, buf) != 0 || g_closable != closable || had_mpris != g_has_mpris ||
            was_playing != g_mpris_playing || had_group != g_has_group || had_group_n != g_group_n) {
            snprintf(g_text, sizeof(g_text), "%s", buf);
            g_closable = closable;
            if (g_shown) {
                show_popup(); /* size may have changed (group membership) -- not just a repaint */
            }
        }
        return;
    }

    /* Different item: restart the delay timer. In tooltip_reuse mode,
     * leave a currently-shown popup's window up (still showing the old
     * item's content) instead of destroying it here -- once the new
     * item's delay elapses, show_popup() will move/resize/repaint that
     * same window rather than recreating one from scratch. */
    if (!(p->tooltip_reuse_window && g_shown)) {
        destroy_popup();
    }
    g_shown = 0;
    g_panel = p;
    g_widget = hit;
    g_local_x = local_x;
    g_anchor_x = ax;
    g_anchor_w = aw;
    g_closable = closable;
    g_ctx = ctx;
    query_mpris(hit, local_x);
    query_thumb(hit, local_x);
    query_group(hit, local_x);
    snprintf(g_text, sizeof(g_text), "%s", buf);
    g_since_ms = now_ms();
}

void tooltip_notice_leave(Panel *p)
{
    if (g_panel == p && g_widget) {
        /* Don't close outright: the pointer may be crossing straight into
         * the popup itself (TOOLTIP_GAP is 0, so that's one continuous
         * motion, not a click into empty space) -- give it a short grace
         * window, cancelled by EnterNotify on either the source widget or
         * the popup. Applies uniformly, even to non-closable tooltips
         * (clock, winctl) -- one consistent hover behavior for every
         * tooltip rather than two different dismissal rules to reason
         * about. */
        g_close_deadline_ms = now_ms() + close_delay_ms();
    }
}

void tooltip_tick(uint64_t now)
{
    if (g_close_deadline_ms && now >= g_close_deadline_ms) {
        tooltip_close();
        return;
    }
    if (!g_widget) {
        return;
    }
    if (!g_shown) {
        if (now - g_since_ms >= (uint64_t)g_panel->tooltip_delay_ms) {
            show_popup();
        }
        return;
    }
    if (now - g_last_refresh_ms >= TOOLTIP_REFRESH_MS) {
        g_last_refresh_ms = now;
        if (refresh_text()) {
            show_popup(); /* size may have changed (e.g. group membership), not just content */
            return; /* show_popup() already repainted */
        }
    }
    /* Live-thumbnail repaint: primarily driven by XDamage notifications
     * for the watched window(s) (thumb_handle_event(), called from
     * xispanel.c's main event loop, sets the dirty flag as soon as one
     * arrives) -- repaints exactly when the source window's content
     * actually changed, not on a blind cadence. thumb_fallback_interval_
     * ms()'s poll is a backstop on top of that for when damage
     * notifications stop arriving for reasons outside this file's
     * control (see its doc comment) -- without it, that looks like the
     * thumbnail silently freezing instead of just becoming a little less
     * than instant. */
    if (g_has_thumb || (g_has_group && g_popup && g_popup->group_thumbs)) {
        int dirty = thumb_take_dirty();
        if (dirty || now - g_last_thumb_paint_ms >= thumb_fallback_interval_ms()) {
            g_last_thumb_paint_ms = now;
            paint_popup();
        }
    }
}

uint64_t tooltip_next_wake_ms(void)
{
    uint64_t wake = 0;
    if (g_close_deadline_ms) {
        wake = g_close_deadline_ms;
    }
    if (g_widget) {
        uint64_t w2 = g_shown ? (g_last_refresh_ms + TOOLTIP_REFRESH_MS)
                               : (g_since_ms + (uint64_t)g_panel->tooltip_delay_ms);
        if (wake == 0 || w2 < wake) {
            wake = w2;
        }
        /* Bounds select()'s timeout so thumb_fallback_interval_ms()'s
         * backstop poll (tooltip_tick()) actually fires on schedule even
         * with zero X activity in between -- the fast path (XDamage)
         * doesn't need an entry here since it wakes select() via the X
         * fd on its own. */
        if (g_shown && (g_has_thumb || (g_has_group && g_popup && g_popup->group_thumbs))) {
            uint64_t w3 = g_last_thumb_paint_ms + thumb_fallback_interval_ms();
            if (wake == 0 || w3 < wake) {
                wake = w3;
            }
        }
    }
    return wake;
}

/* Fires the click action for `local_x/local_y` (popup-local) if the
 * tooltip is closable, then closes it -- mirrors menu.c's
 * select-and-close pattern. */
static void handle_popup_click(int local_x, int local_y)
{
    if (!g_widget) {
        tooltip_close();
        return;
    }

    if (g_has_group && g_popup) {
        for (int i = 0; i < g_popup->group_shown_n; i++) {
            int ix = g_popup->group_item_x[i], iy = g_popup->group_item_y[i];
            int iw = g_popup->group_item_w[i], ih = g_popup->group_item_h[i];
            if (local_x < ix || local_x >= ix + iw || local_y < iy || local_y >= iy + ih) {
                continue;
            }
            Window win = g_group_items[i].win;
            int on_close = local_x >= g_popup->group_close_x[i] &&
                            local_x < g_popup->group_close_x[i] + TOOLTIP_CLOSE_ICON &&
                            local_y >= g_popup->group_close_y[i] &&
                            local_y < g_popup->group_close_y[i] + TOOLTIP_CLOSE_ICON;
            tooltip_close();
            if (on_close) {
                ewmh_close(win);
            } else {
                ewmh_activate(win);
            }
            XFlush(g_dpy);
            return;
        }
        /* Click landed on the popup but not on any item cell (e.g. the
         * "+N mais" note, or the padding around the grid) -- just dismiss,
         * same as clicking a non-closable single-item tooltip's body. */
        tooltip_close();
        return;
    }

    if (g_has_mpris && g_popup) {
        int s = g_popup->mpris_btn_size;
        int by = g_popup->mpris_btn_y;
        for (int i = 0; i < 3; i++) {
            int bx = g_popup->mpris_btn_x[i];
            if (local_x >= bx && local_x < bx + s && local_y >= by && local_y < by + s) {
                /* Unlike the thumbnail/close-icon zones, media transport
                 * buttons only perform their action -- the tooltip stays
                 * open so play/pause/next/prev can be clicked repeatedly
                 * without reopening the popup each time. Re-query mpris
                 * right away so a play<->pause icon flip shows up
                 * immediately instead of waiting for the ~1s periodic
                 * refresh. */
                char busname[128];
                snprintf(busname, sizeof(busname), "%s", g_mpris_busname);
                if (i == 0) {
                    mpris_previous(busname);
                } else if (i == 1) {
                    mpris_play_pause(busname);
                } else {
                    mpris_next(busname);
                }
                query_mpris(g_widget, g_local_x);
                paint_popup();
                return;
            }
        }
    }

    if (!g_closable) {
        tooltip_close();
        return;
    }
    PanelWidget *w = g_widget;
    void *ctx = g_ctx;
    int on_close_icon = g_popup && local_x >= g_popup->close_x && local_x < g_popup->close_x + g_popup->close_w &&
                         local_y >= g_popup->close_y && local_y < g_popup->close_y + g_popup->close_h;
    tooltip_close();
    if (on_close_icon) {
        if (w->ops->tooltip_close_item) {
            w->ops->tooltip_close_item(w, ctx);
        }
    } else {
        if (w->ops->tooltip_activate) {
            w->ops->tooltip_activate(w, ctx);
        }
    }
}

int tooltip_handle_event(const XEvent *ev)
{
    if (!g_popup) {
        return 0;
    }
    if (ev->type == Expose && ev->xexpose.window == g_popup->win) {
        paint_popup();
        return 1;
    }
    if (ev->type == EnterNotify && ev->xcrossing.window == g_popup->win) {
        g_close_deadline_ms = 0;
        return 1;
    }
    if (ev->type == LeaveNotify && ev->xcrossing.window == g_popup->win) {
        g_close_deadline_ms = now_ms() + close_delay_ms();
        return 1;
    }
    if (ev->type == ButtonPress && ev->xbutton.window == g_popup->win) {
        handle_popup_click(ev->xbutton.x, ev->xbutton.y);
        return 1;
    }
    return 0;
}
