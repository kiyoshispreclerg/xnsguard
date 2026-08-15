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
 * default 500, 0 = instant) -- see Panel::tooltip_delay_ms. */
#define TOOLTIP_REFRESH_MS 1000 /* how often to re-poll get_tooltip() while shown */
#define TOOLTIP_CLOSE_GRACE_MS 200 /* hover-intent window before an actual close */
#define TOOLTIP_GAP 0 /* no dead zone between panel and popup, so the pointer
                        * can cross directly from one to the other */
#define TOOLTIP_PAD_X 10
#define TOOLTIP_PAD_Y 6
#define TOOLTIP_FONT_SIZE 13.0
#define TOOLTIP_MAX_LINES 4
#define TOOLTIP_CLOSE_ICON 14

typedef struct {
    Window win;
    cairo_surface_t *surface;
    cairo_t *cr;
    int width, height;
    /* Close-icon hit-rect, in popup-local coordinates; only meaningful
     * when g_closable. */
    int close_x, close_y, close_w, close_h;
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
static int g_shown = 0;
static int g_closable = 0;
static void *g_ctx = NULL;

/* 0 = no close pending. Set on LeaveNotify from either the panel widget or
 * the popup itself; cleared on EnterNotify to either -- see the file
 * comment on why this replaces menu.c's grab-based dismissal here. */
static uint64_t g_close_deadline_ms = 0;

static void destroy_popup(void)
{
    if (!g_popup) {
        return;
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
    g_close_deadline_ms = 0;
}

/* Splits g_text on '\n' into up to TOOLTIP_MAX_LINES lines and measures
 * them against `cr` (which must already have the tooltip font set). */
static int measure_lines(cairo_t *cr, char lines[TOOLTIP_MAX_LINES][128], int *out_text_w, int *out_h)
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

    double line_h = TOOLTIP_FONT_SIZE * 1.4;
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

static void paint_popup(void)
{
    if (!g_popup || !g_panel) {
        return;
    }
    Panel *p = g_panel;
    cairo_t *cr = g_popup->cr;
    cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_rgba(cr, p->bg_r, p->bg_g, p->bg_b, p->bg_a);
    cairo_paint(cr);
    cairo_set_operator(cr, CAIRO_OPERATOR_OVER);
    cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.15);
    cairo_rectangle(cr, 0.5, 0.5, g_popup->width - 1, g_popup->height - 1);
    cairo_set_line_width(cr, 1);
    cairo_stroke(cr);

    if (g_font_face) {
        cairo_set_font_face(cr, g_font_face);
    }
    cairo_set_font_size(cr, TOOLTIP_FONT_SIZE);

    char lines[TOOLTIP_MAX_LINES][128];
    int text_w, h;
    int n = measure_lines(cr, lines, &text_w, &h);
    double line_h = TOOLTIP_FONT_SIZE * 1.4;

    cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, p->fg_a);
    for (int i = 0; i < n; i++) {
        cairo_text_extents_t ext;
        cairo_text_extents(cr, lines[i], &ext);
        double ty = TOOLTIP_PAD_Y + i * line_h + (line_h - ext.height) / 2.0 - ext.y_bearing;
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

    cairo_surface_flush(g_popup->surface);
    XFlush(g_dpy);
}

static void show_popup(void)
{
    if (!g_panel || !g_widget || !g_text[0]) {
        return;
    }
    destroy_popup();

    TooltipPopup *pop = calloc(1, sizeof(TooltipPopup));
    if (!pop) {
        return;
    }

    /* Measure against a throwaway surface first -- need width/height to
     * create the real window. */
    cairo_surface_t *probe_surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 1, 1);
    cairo_t *probe_cr = cairo_create(probe_surf);
    if (g_font_face) {
        cairo_set_font_face(probe_cr, g_font_face);
    }
    cairo_set_font_size(probe_cr, TOOLTIP_FONT_SIZE);
    char lines[TOOLTIP_MAX_LINES][128];
    int text_w, text_h;
    measure_lines(probe_cr, lines, &text_w, &text_h);
    cairo_destroy(probe_cr);
    cairo_surface_destroy(probe_surf);

    int close_reserve = g_closable ? (TOOLTIP_CLOSE_ICON + 6) : 0;
    pop->width = text_w + TOOLTIP_PAD_X * 2 + close_reserve;
    pop->height = text_h;
    if (g_closable && pop->height < TOOLTIP_CLOSE_ICON + TOOLTIP_PAD_Y * 2) {
        pop->height = TOOLTIP_CLOSE_ICON + TOOLTIP_PAD_Y * 2;
    }
    if (pop->width < 1) {
        pop->width = 1;
    }
    if (pop->height < 1) {
        pop->height = 1;
    }
    pop->close_x = pop->width - TOOLTIP_CLOSE_ICON - 6;
    pop->close_y = (pop->height - TOOLTIP_CLOSE_ICON) / 2;
    pop->close_w = TOOLTIP_CLOSE_ICON;
    pop->close_h = TOOLTIP_CLOSE_ICON;

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

    g_popup = pop;
    paint_popup();
    g_shown = 1;
    g_last_refresh_ms = now_ms();
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
    int changed = strcmp(g_text, buf) != 0 || g_closable != closable;
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
        tooltip_close();
        return;
    }

    int local_x = axis_pos - hit->x;
    char buf[256];
    int ax = 0, aw = hit->len;
    int closable = 0;
    void *ctx = NULL;
    if (!hit->ops->get_tooltip(hit, local_x, buf, sizeof(buf), &ax, &aw, &closable, &ctx)) {
        tooltip_close();
        return;
    }

    g_close_deadline_ms = 0; /* pointer is over the source widget again */

    if (g_widget == hit && g_anchor_x == ax && g_anchor_w == aw) {
        /* Same sub-item as before: keep waiting, or keep showing (and
         * refresh in case content changed under a stationary pointer). */
        g_local_x = local_x;
        g_ctx = ctx;
        if (strcmp(g_text, buf) != 0 || g_closable != closable) {
            snprintf(g_text, sizeof(g_text), "%s", buf);
            g_closable = closable;
            if (g_shown) {
                paint_popup();
            }
        }
        return;
    }

    /* Different item: restart the delay timer. */
    destroy_popup();
    g_shown = 0;
    g_panel = p;
    g_widget = hit;
    g_local_x = local_x;
    g_anchor_x = ax;
    g_anchor_w = aw;
    g_closable = closable;
    g_ctx = ctx;
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
        g_close_deadline_ms = now_ms() + TOOLTIP_CLOSE_GRACE_MS;
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
    }
    return wake;
}

/* Fires the click action for `local_x/local_y` (popup-local) if the
 * tooltip is closable, then closes it -- mirrors menu.c's
 * select-and-close pattern. */
static void handle_popup_click(int local_x, int local_y)
{
    if (!g_closable || !g_widget) {
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
        g_close_deadline_ms = now_ms() + TOOLTIP_CLOSE_GRACE_MS;
        return 1;
    }
    if (ev->type == ButtonPress && ev->xbutton.window == g_popup->win) {
        handle_popup_click(ev->xbutton.x, ev->xbutton.y);
        return 1;
    }
    return 0;
}
