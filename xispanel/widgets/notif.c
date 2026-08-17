/*
 * notif widget - bell icon + unread-count badge over notifd.c's ring
 * buffer (see xispanel.h's NotifEntry API doc comment). Thin view only:
 * never stores anything of its own, just queries notifd_count()/
 * notifd_get()/notifd_unread_count() on demand.
 *
 * Click opens the history as a normal panel_menu_open() popup (reused,
 * not a bespoke layout) -- same widget-agnostic menu mechanism tasklist's
 * right-click context menu uses. Opening the history also marks every
 * currently-held notification read (clearing the badge), the same
 * "viewing the list dismisses the count" convention most desktop
 * notification centers use -- there's no per-item read/unread affordance
 * in the menu itself.
 *
 * corner= (bottom-right (default), bottom-left, bottom-center, top-right,
 * top-left, top-center, center-left, center-right) and timeout=<ms>
 * (default 5000) don't affect this widget's own layout at all -- both
 * are forwarded straight to the single global toast stack
 * (toast_set_corner()/notifd_set_default_expire_ms() in xispanel.h),
 * since only one stack of toast popups exists regardless of how many
 * `notif` widgets/panels are configured. The last `notif` widget to
 * init() (or reload) wins if more than one sets either. timeout= only
 * changes what a sender that didn't request its own expire_timeout gets
 * -- see notifd_set_default_expire_ms()'s doc comment.
 *
 * The toast stack is also confined to *this* widget's own panel's
 * output (toast_set_output_rect(), see xispanel.h) -- never the whole
 * multi-monitor screen -- and painted in this panel's own bg/fg theme
 * colors (toast_set_colors()), so toasts visually match the panel that
 * owns the bell icon rather than using a hardcoded look.
 */
#include "../xispanel.h"

#include <X11/Xlib.h>

#include <stdio.h>
#include <string.h>

#define NOTIF_MENU_MAX 64

typedef struct {
    unsigned int last_shown_count; /* just to know when to re-dirty, see on_tick */
} NotifPriv;

static ToastCorner parse_corner(const char *s)
{
    if (!strcmp(s, "bottom-left") || !strcmp(s, "bl")) {
        return TOAST_CORNER_BOTTOM_LEFT;
    }
    if (!strcmp(s, "bottom-center") || !strcmp(s, "bc")) {
        return TOAST_CORNER_BOTTOM_CENTER;
    }
    if (!strcmp(s, "top-right") || !strcmp(s, "tr")) {
        return TOAST_CORNER_TOP_RIGHT;
    }
    if (!strcmp(s, "top-left") || !strcmp(s, "tl")) {
        return TOAST_CORNER_TOP_LEFT;
    }
    if (!strcmp(s, "top-center") || !strcmp(s, "tc")) {
        return TOAST_CORNER_TOP_CENTER;
    }
    if (!strcmp(s, "center-left") || !strcmp(s, "cl")) {
        return TOAST_CORNER_CENTER_LEFT;
    }
    if (!strcmp(s, "center-right") || !strcmp(s, "cr")) {
        return TOAST_CORNER_CENTER_RIGHT;
    }
    return TOAST_CORNER_BOTTOM_RIGHT;
}

/* This panel's own output, shrunk by its own dock strip (if it reserves
 * one) -- see toast_set_output_rect()'s doc comment. Only this panel's
 * own strip is accounted for (not any *other* panel/dock that might
 * also sit on the same output), same pragmatic scope the rest of this
 * feature keeps: exactly right for the common single-panel-per-output
 * setup, a reasonable approximation otherwise. */
static void compute_output_rect(Panel *p, int *out_x, int *out_y, int *out_w, int *out_h)
{
    *out_x = p->out_x;
    *out_y = p->out_y;
    *out_w = p->out_w;
    *out_h = p->out_h;
    if (p->mode != MODE_DOCK) {
        return;
    }
    switch (p->edge) {
    case EDGE_TOP:
        *out_y += p->thickness;
        *out_h -= p->thickness;
        break;
    case EDGE_BOTTOM:
        *out_h -= p->thickness;
        break;
    case EDGE_LEFT:
        *out_x += p->thickness;
        *out_w -= p->thickness;
        break;
    case EDGE_RIGHT:
        *out_w -= p->thickness;
        break;
    }
}

static int notif_init(PanelWidget *w)
{
    char buf[32];
    if (kv_get(w->config_kv, "corner", buf, sizeof(buf))) {
        toast_set_corner(parse_corner(buf));
    }
    /* ms a toast stays on screen when its sender didn't request its own
     * expire_timeout (the common case) -- see notifd_set_default_expire_
     * ms()'s doc comment. */
    int timeout_ms = kv_get_int(w->config_kv, "timeout", 0);
    if (timeout_ms > 0) {
        notifd_set_default_expire_ms(timeout_ms);
    }

    /* Deliberately NOT syncing output rect/colors here: init() runs from
     * load_config(), which calls a WIDGET line's init() the moment it's
     * parsed -- *before* any THEME line for this panel (conventionally
     * listed after its WIDGET lines) has been applied, and before
     * panel_activate() has resolved out_x/out_y/out_w/out_h/thickness at
     * all (that only happens afterward, once every PANEL/WIDGET/THEME
     * line has been read -- see reload_all_panels()). Reading the
     * panel's bg/fg colors or out_x/out_y/out_w/out_h this early would
     * capture stale pre-THEME/pre-geometry values. See notif_on_tick(). */
    w->next_tick_ms = now_ms();
    return 0;
}

static int notif_on_tick(PanelWidget *w, uint64_t now)
{
    NotifPriv *np = w->priv;
    w->next_tick_ms = now + 1000;

    /* Where output rect/colors actually get synced to toast.c (see
     * notif_init()'s doc comment for why not there) -- cheap to just
     * always re-sync rather than trying to hook "geometry/theme just
     * became final": both setters are no-ops when nothing changed, and
     * this also keeps toasts in sync within a second of a later RELOAD
     * changing the panel's theme or a monitor being reconfigured. This
     * affects the *toasts*, not this widget's own paint, so it doesn't
     * by itself warrant a panel repaint. */
    Panel *p = w->panel;
    int ox, oy, ow, oh;
    compute_output_rect(p, &ox, &oy, &ow, &oh);
    toast_set_output_rect(ox, oy, ow, oh);
    toast_set_colors(p->bg_r, p->bg_g, p->bg_b, p->bg_a, p->fg_r, p->fg_g, p->fg_b, p->fg_a);

    /* The one thing this widget draws that changes on its own (a new
     * Notify() arriving, or a toast/menu marking one read) is the unread
     * badge -- repaint only when that count changes. */
    unsigned int unread = (unsigned int)notifd_unread_count();
    if (unread == np->last_shown_count) {
        return 0;
    }
    np->last_shown_count = unread;
    return 1;
}

static void notif_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    (void)cross_axis;
    int icon_px = icon_size_for(w->thickness, 0);
    *out_len = icon_px;
    *out_min_len = icon_px;
}

/* Simple hand-drawn bell (no themed icon lookup -- there's no reliable
 * cross-theme "notification" icon name the way tray/launcher icons have a
 * real freedesktop icon-theme grid to resolve against) -- a body arc plus
 * a small clapper, filled with the panel's fg color. */
static void draw_bell(cairo_t *cr, double x, double y, double size, double r, double g, double b)
{
    double cx = x + size / 2.0;
    double top = y + size * 0.14;
    double body_r = size * 0.32;
    double body_cy = top + body_r;

    cairo_save(cr);
    cairo_set_source_rgba(cr, r, g, b, 0.92);
    cairo_move_to(cr, cx - body_r, body_cy);
    cairo_arc(cr, cx, body_cy, body_r, 3.14159265, 0);
    cairo_line_to(cr, cx + body_r * 1.15, body_cy + size * 0.22);
    cairo_line_to(cr, cx - body_r * 1.15, body_cy + size * 0.22);
    cairo_close_path(cr);
    cairo_fill(cr);

    double clapper_cy = body_cy + size * 0.22 + size * 0.08;
    cairo_arc(cr, cx, clapper_cy, size * 0.06, 0, 2 * 3.14159265);
    cairo_fill(cr);
    cairo_restore(cr);
}

static void draw_badge(cairo_t *cr, double icon_x, double icon_y, double icon_px, int count)
{
    char label[8];
    if (count > 99) {
        snprintf(label, sizeof(label), "99+");
    } else {
        snprintf(label, sizeof(label), "%d", count);
    }
    double fs = icon_px * 0.32;
    double tw = 0;
    pango_text_extents_ellipsized(cr, label, fs, 0, &tw, NULL);
    double pad = icon_px * 0.14;
    double bw = tw + pad * 2;
    double bh = fs + pad * 1.2;
    if (bw < bh) {
        bw = bh; /* keep single-digit counts circular, not a thin pill */
    }
    double bx = icon_x + icon_px - bw * 0.7;
    double by = icon_y - bh * 0.3;

    cairo_save(cr);
    cairo_set_source_rgba(cr, 0.85, 0.15, 0.15, 0.95);
    double radius = bh / 2.0;
    cairo_new_sub_path(cr);
    cairo_arc(cr, bx + radius, by + radius, radius, 3.14159265 * 0.5, 3.14159265 * 1.5);
    cairo_arc(cr, bx + bw - radius, by + radius, radius, -3.14159265 * 0.5, 3.14159265 * 0.5);
    cairo_close_path(cr);
    cairo_fill(cr);

    cairo_set_source_rgb(cr, 1, 1, 1);
    pango_show_text_boxed(cr, bx + (bw - tw) / 2.0, by, bh, bw, fs, label, NULL);
    cairo_restore(cr);
}

static void notif_paint(PanelWidget *w, cairo_t *cr)
{
    int ox, oy, owidth, oheight;
    widget_get_rect(w, &ox, &oy, &owidth, &oheight);
    (void)owidth;
    (void)oheight;

    int icon_px = icon_size_for(w->thickness, 0);
    double icon_y = oy + (w->thickness - icon_px) / 2.0;
    Panel *p = w->panel;
    draw_bell(cr, ox, icon_y, icon_px, p->fg_r, p->fg_g, p->fg_b);

    int unread = notifd_unread_count();
    if (unread > 0) {
        draw_badge(cr, ox, icon_y, icon_px, unread);
    }
}

/* Every currently-held notification's summary (falling back to its
 * app_name if empty) as one flat MenuItem list, newest first -- there's
 * no natural nesting to a notification history the way a folder or
 * DBusmenu tree has, so panel_menu_open() (not the _tree variant) is all
 * this needs. */
static void notif_menu_select(Panel *panel, PanelWidget *widget, void *ctx, int index)
{
    (void)panel;
    (void)widget;
    (void)ctx;
    (void)index;
    /* Nothing to do on selection -- there's no per-item action (no
     * "activate"/"close" affordance for a past notification), viewing the
     * list already marked everything read on open. A click just closes
     * the menu, same as clicking any other disabled-feeling info list. */
}

static int notif_on_button(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y)
{
    (void)local_x;
    (void)local_y;
    (void)root_x;
    (void)root_y;
    if (button != Button1) {
        return 0;
    }

    int n = notifd_count();
    MenuItem items[NOTIF_MENU_MAX];
    int nitems = 0;
    if (n == 0) {
        snprintf(items[0].label, sizeof(items[0].label), "Sem notifica\xc3\xa7\xc3\xb5""es");
        items[0].enabled = 0;
        items[0].is_separator = 0;
        nitems = 1;
    } else {
        for (int i = n - 1; i >= 0 && nitems < NOTIF_MENU_MAX; i--) {
            const NotifEntry *e = notifd_get(i);
            if (!e) {
                continue;
            }
            const char *text = e->summary[0] ? e->summary : e->app_name;
            if (e->app_name[0] && e->summary[0]) {
                snprintf(items[nitems].label, sizeof(items[nitems].label), "%s: %s", e->app_name, e->summary);
            } else {
                snprintf(items[nitems].label, sizeof(items[nitems].label), "%s", text);
            }
            items[nitems].enabled = 0; /* informational only, see notif_menu_select() */
            items[nitems].is_separator = 0;
            nitems++;
            notifd_mark_read(e->id);
        }
    }

    panel_menu_open(w->panel, w, 0, w->len, items, nitems, NULL, notif_menu_select);
    w->panel->dirty = 1;
    return 1;
}

const PanelWidgetOps notif_ops = {
    .type_name = "notif",
    .priv_size = sizeof(NotifPriv),
    .init = notif_init,
    .paint = notif_paint,
    .measure = notif_measure,
    .on_button = notif_on_button,
    .on_tick = notif_on_tick,
};
