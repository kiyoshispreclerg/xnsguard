/*
 * toast.c - notification toast popups, see the doc comment in xispanel.h.
 *
 * Each toast is its own small override-redirect window (same pattern as
 * tooltip.c/menu.c's popups: XMatchVisualInfo for a 32-bit ARGB visual if
 * one's available, falling back to the default visual/opaque background
 * otherwise), stacked bottom-up in the bottom-right corner of the default
 * screen. Fixed compact layout (icon + two ellipsized text lines) rather
 * than word-wrapping the body -- keeps sizing/positioning trivial, matches
 * how tooltip.c already treats a window title (one ellipsized line, not a
 * paragraph layout).
 *
 * g_toasts is kept as a dense array in arrival order (oldest first, newest
 * last) so restacking after a dismissal/expiry is just "shift the tail
 * down one slot" -- reposition_all() then recomputes every window's screen
 * position from its array index alone.
 */
#include "xispanel.h"

#include <X11/Xatom.h>
#include <X11/Xutil.h>
#include <cairo/cairo-xlib.h>

#include <stdio.h>
#include <string.h>

/* Hard upper bound on the array itself -- the *actual* number shown at
 * once is computed dynamically from the usable screen height (see
 * toast_capacity() below), never a fixed count. This is just generous
 * headroom no real screen height could plausibly exceed. */
#define TOAST_ARRAY_CAP 32
#define TOAST_W 320
#define TOAST_H 72
#define TOAST_PAD 12
#define TOAST_ICON 40
#define TOAST_GAP 8
#define TOAST_MARGIN 16
#define TOAST_SUMMARY_SIZE 14.0
#define TOAST_BODY_SIZE 12.0

typedef struct {
    unsigned int notif_id;
    Window win;
    cairo_surface_t *surface;
    cairo_t *cr;
    uint64_t expire_ms; /* 0 = never auto-expire */
    /* Original requested lifetime in ms (0 = never-expire), kept alongside
     * expire_ms so a LeaveNotify can restart the full countdown rather
     * than just resuming from wherever it was paused -- see hovered
     * below. */
    uint64_t timeout_ms;
    /* 1 while the pointer sits inside this toast -- toast_tick() skips
     * the expiry check entirely for a hovered toast, so parking the mouse
     * on one keeps it on screen indefinitely; leaving restarts expire_ms
     * from `now + timeout_ms` (a fresh full countdown, not a resume). */
    int hovered;
    char app_name[NOTIFD_APP_NAME_MAX];
    char summary[NOTIFD_SUMMARY_MAX];
    char body[NOTIFD_BODY_MAX];
    /* Borrowed from notifd.c's ring entry, not owned/freed here -- only
     * safe because a toast's own ~5s default lifetime is always far
     * shorter than it'd take NOTIFD_MAX (50) more notifications to arrive
     * and evict the entry this pointer came from. */
    cairo_surface_t *icon;
} Toast;

static Toast g_toasts[TOAST_ARRAY_CAP];
static int g_n = 0;
static ToastCorner g_corner = TOAST_CORNER_BOTTOM_RIGHT;

/* The rect toasts are confined to -- set by widgets/notif.c's init() to
 * its own panel's output, minus that panel's own dock strip (see
 * toast_set_output_rect()'s doc comment). area_w == 0 means "never set",
 * in which case toast_area() falls back to the whole default screen. */
static int g_area_x = 0, g_area_y = 0, g_area_w = 0, g_area_h = 0;

/* Panel theme colors, mirrored from widgets/notif.c's own panel via
 * toast_set_colors() -- defaults match the original hardcoded look
 * (dark, near-opaque background / white text) until a notif widget
 * actually sets them. */
static double g_bg_r = 0.12, g_bg_g = 0.12, g_bg_b = 0.12, g_bg_a = 0.92;
static double g_fg_r = 1.0, g_fg_g = 1.0, g_fg_b = 1.0, g_fg_a = 1.0;

static Visual *g_visual = NULL;
static int g_depth = 0;
static Colormap g_cmap = None;
static int g_visual_ready = 0;

static void ensure_visual(void)
{
    if (g_visual_ready) {
        return;
    }
    g_visual_ready = 1;
    XVisualInfo vinfo;
    if (XMatchVisualInfo(g_dpy, g_screen, 32, TrueColor, &vinfo)) {
        g_visual = vinfo.visual;
        g_depth = vinfo.depth;
        g_cmap = XCreateColormap(g_dpy, g_root, g_visual, AllocNone);
    } else {
        g_visual = DefaultVisual(g_dpy, g_screen);
        g_depth = DefaultDepth(g_dpy, g_screen);
        g_cmap = DefaultColormap(g_dpy, g_screen);
    }
}

/* The rect toasts are confined to: whatever widgets/notif.c last set via
 * toast_set_output_rect() (its own panel's *output*, not the whole
 * possibly-multi-monitor screen -- see that function's doc comment),
 * falling back to the whole default screen if no notif widget has set
 * one yet. */
static void toast_area(int *out_x, int *out_y, int *out_w, int *out_h)
{
    if (g_area_w > 0 && g_area_h > 0) {
        *out_x = g_area_x;
        *out_y = g_area_y;
        *out_w = g_area_w;
        *out_h = g_area_h;
    } else {
        *out_x = 0;
        *out_y = 0;
        *out_w = DisplayWidth(g_dpy, g_screen);
        *out_h = DisplayHeight(g_dpy, g_screen);
    }
}

/* How many toasts fit stacked in the current toast_area() without any of
 * them spilling past its far edge -- see the file comment on why this
 * replaces a fixed count. Always >= 1: a single toast is let through even
 * if it technically overflows a tiny/unusual area, same "never just
 * silently show nothing" spirit as the rest of xispanel's degrade-
 * gracefully helpers. */
static int toast_capacity(void)
{
    int ax, ay, aw, ah;
    toast_area(&ax, &ay, &aw, &ah);
    (void)ax;
    (void)ay;
    (void)aw;
    int usable = ah - 2 * TOAST_MARGIN;
    if (usable < TOAST_H) {
        return 1;
    }
    int cap = 1 + (usable - TOAST_H) / (TOAST_H + TOAST_GAP);
    return cap < 1 ? 1 : cap;
}

/* Screen position for the toast currently at array index `idx` (0 =
 * oldest) -- the newest toast (index g_n-1) sits closest to g_corner,
 * older ones stacked away from it. Positioned within toast_area(), not
 * the raw screen, so toasts stay on the right output and never sit under
 * a panel. Horizontal anchor (left/center/right) and vertical anchor
 * (top/center/bottom) are independent; the vertical anchor also decides
 * stack direction -- top stacks downward, bottom stacks upward, center
 * stacks downward from the vertical midpoint (an arbitrary but
 * unambiguous default, same as top's). */
static void toast_screen_pos(int idx, int *out_x, int *out_y)
{
    int from_corner = g_n - 1 - idx;
    int ax, ay, aw, ah;
    toast_area(&ax, &ay, &aw, &ah);

    int at_left = (g_corner == TOAST_CORNER_TOP_LEFT || g_corner == TOAST_CORNER_CENTER_LEFT ||
                   g_corner == TOAST_CORNER_BOTTOM_LEFT);
    int at_right = (g_corner == TOAST_CORNER_TOP_RIGHT || g_corner == TOAST_CORNER_CENTER_RIGHT ||
                    g_corner == TOAST_CORNER_BOTTOM_RIGHT);
    int at_top = (g_corner == TOAST_CORNER_TOP_LEFT || g_corner == TOAST_CORNER_TOP_CENTER ||
                  g_corner == TOAST_CORNER_TOP_RIGHT);
    int at_bottom = (g_corner == TOAST_CORNER_BOTTOM_LEFT || g_corner == TOAST_CORNER_BOTTOM_CENTER ||
                     g_corner == TOAST_CORNER_BOTTOM_RIGHT);

    if (at_left) {
        *out_x = ax + TOAST_MARGIN;
    } else if (at_right) {
        *out_x = ax + aw - TOAST_MARGIN - TOAST_W;
    } else {
        *out_x = ax + (aw - TOAST_W) / 2;
    }

    int base_y = at_top ? ay + TOAST_MARGIN : at_bottom ? ay + ah - TOAST_MARGIN - TOAST_H : ay + (ah - TOAST_H) / 2;
    int step = from_corner * (TOAST_H + TOAST_GAP);
    *out_y = at_bottom ? base_y - step : base_y + step;
}

static void paint_toast(Toast *t)
{
    cairo_t *cr = t->cr;
    cairo_save(cr);
    cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_rgba(cr, g_bg_r, g_bg_g, g_bg_b, g_bg_a);
    cairo_paint(cr);
    cairo_restore(cr);

    cairo_set_source_rgba(cr, g_fg_r, g_fg_g, g_fg_b, 0.15);
    cairo_set_line_width(cr, 1);
    cairo_rectangle(cr, 0.5, 0.5, TOAST_W - 1, TOAST_H - 1);
    cairo_stroke(cr);

    double text_x = TOAST_PAD;
    double text_w = TOAST_W - TOAST_PAD * 2;
    if (t->icon) {
        draw_icon_scaled(cr, t->icon, TOAST_PAD, (TOAST_H - TOAST_ICON) / 2.0, TOAST_ICON);
        text_x = TOAST_PAD * 2 + TOAST_ICON;
        text_w = TOAST_W - text_x - TOAST_PAD;
    }

    cairo_set_source_rgba(cr, g_fg_r, g_fg_g, g_fg_b, g_fg_a);
    const char *summary = t->summary[0] ? t->summary : t->app_name;
    pango_show_text_boxed(cr, text_x, TOAST_PAD - 2, TOAST_SUMMARY_SIZE + 6, text_w, TOAST_SUMMARY_SIZE, summary,
                           NULL);
    if (t->body[0]) {
        cairo_set_source_rgba(cr, g_fg_r, g_fg_g, g_fg_b, g_fg_a * 0.75);
        pango_show_text_boxed(cr, text_x, TOAST_PAD - 2 + TOAST_SUMMARY_SIZE + 6, TOAST_BODY_SIZE + 6, text_w,
                               TOAST_BODY_SIZE, t->body, NULL);
    }
}

static void destroy_toast_window(Toast *t)
{
    if (t->cr) {
        cairo_destroy(t->cr);
    }
    if (t->surface) {
        cairo_surface_destroy(t->surface);
    }
    if (t->win) {
        XDestroyWindow(g_dpy, t->win);
    }
    memset(t, 0, sizeof(*t));
}

static void reposition_all(void)
{
    for (int i = 0; i < g_n; i++) {
        int x, y;
        toast_screen_pos(i, &x, &y);
        XMoveWindow(g_dpy, g_toasts[i].win, x, y);
    }
    XFlush(g_dpy);
}

/* Removes the toast at array index `idx`, shifting the tail down and
 * restacking everyone still visible. */
static void remove_toast(int idx)
{
    if (idx < 0 || idx >= g_n) {
        return;
    }
    destroy_toast_window(&g_toasts[idx]);
    for (int i = idx; i < g_n - 1; i++) {
        g_toasts[i] = g_toasts[i + 1];
    }
    g_n--;
    memset(&g_toasts[g_n], 0, sizeof(g_toasts[g_n]));
    reposition_all();
}

static void toast_on_arrived(const NotifEntry *e, int expire_timeout_ms)
{
    ensure_visual();
    /* Room for one more, freeing up as many oldest-first as it takes --
     * normally at most one eviction, but a loop (not a single if) since
     * the workarea can also have shrunk since the last arrival (e.g.
     * another panel/dock appeared), which could put the cap below g_n by
     * more than one. Cap it at TOAST_ARRAY_CAP too so a pathological
     * capacity (huge screen) never overflows the fixed-size array. */
    int cap = toast_capacity();
    if (cap > TOAST_ARRAY_CAP) {
        cap = TOAST_ARRAY_CAP;
    }
    while (g_n >= cap && g_n > 0) {
        remove_toast(0); /* drop the oldest visible toast to make room */
    }

    Toast *t = &g_toasts[g_n];
    memset(t, 0, sizeof(*t));
    t->notif_id = e->id;
    snprintf(t->app_name, sizeof(t->app_name), "%s", e->app_name);
    snprintf(t->summary, sizeof(t->summary), "%s", e->summary);
    snprintf(t->body, sizeof(t->body), "%s", e->body);
    t->icon = e->icon;
    /* expire_timeout_ms is already resolved by notifd.c (see the
     * NotifArrivedFn doc comment in xispanel.h) -- widgets/notif.c's
     * timeout= config only ever changes what notifd.c substitutes for a
     * sender that didn't request its own, so a negative value should
     * never actually reach here, but treat it the same as 0 (immediate
     * default) rather than trust it blindly. */
    t->timeout_ms = expire_timeout_ms > 0 ? (uint64_t)expire_timeout_ms : 0;
    t->expire_ms = t->timeout_ms != 0 ? now_ms() + t->timeout_ms : 0;

    g_n++; /* toast_screen_pos() positions by index within the *new* total
             * count, so this new toast counts itself -- incrementing first
             * makes toast_screen_pos(g_n - 1, ...) below identical to what
             * reposition_all() computes for the same slot right after. */

    int x, y;
    toast_screen_pos(g_n - 1, &x, &y);

    XSetWindowAttributes attrs;
    memset(&attrs, 0, sizeof(attrs));
    attrs.override_redirect = True;
    attrs.colormap = g_cmap;
    attrs.border_pixel = 0;
    attrs.background_pixel = 0;
    attrs.event_mask = ExposureMask | ButtonPressMask | EnterWindowMask | LeaveWindowMask;

    t->win = XCreateWindow(g_dpy, g_root, x, y, TOAST_W, TOAST_H, 0, g_depth, InputOutput, g_visual,
                            CWOverrideRedirect | CWColormap | CWBorderPixel | CWBackPixel | CWEventMask, &attrs);
    XChangeProperty(g_dpy, t->win, g_atom_wm_window_type, XA_ATOM, 32, PropModeReplace,
                     (unsigned char *)&g_atom_wm_window_type_tooltip, 1);
    t->surface = cairo_xlib_surface_create(g_dpy, t->win, g_visual, TOAST_W, TOAST_H);
    t->cr = cairo_create(t->surface);

    XMapWindow(g_dpy, t->win);
    XRaiseWindow(g_dpy, t->win);
    paint_toast(t);

    /* Every already-visible toast was positioned as "closest to the
     * corner" at its *own* arrival time -- this new one just took that
     * slot, so everyone else needs to shift away from the corner one step.
     * reposition_all() recomputes every window's position from scratch off
     * the current g_n/array order, so it's simplest to just always call it
     * here rather than only moving the older ones by hand. */
    reposition_all();
}

void toast_init(void)
{
    notifd_set_arrived_callback(toast_on_arrived);
}

/* Changing corners while toasts are already showing (a config RELOAD)
 * just relocates them where the new corner puts them, rather than
 * dismissing/recreating anything -- reposition_all() already recomputes
 * every window's position from g_corner alone. */
void toast_set_corner(ToastCorner corner)
{
    if (g_corner == corner) {
        return;
    }
    g_corner = corner;
    reposition_all();
}

/* See g_area_x/y/w/h's doc comment. reposition_all() is a no-op when
 * g_n == 0 (nothing showing yet), which is the common case (this is set
 * from a widget's init(), before any toast has ever arrived). */
void toast_set_output_rect(int x, int y, int w, int h)
{
    if (g_area_x == x && g_area_y == y && g_area_w == w && g_area_h == h) {
        return;
    }
    g_area_x = x;
    g_area_y = y;
    g_area_w = w;
    g_area_h = h;
    reposition_all();
}

void toast_set_colors(double bg_r, double bg_g, double bg_b, double bg_a, double fg_r, double fg_g, double fg_b,
                       double fg_a)
{
    g_bg_r = bg_r;
    g_bg_g = bg_g;
    g_bg_b = bg_b;
    g_bg_a = bg_a;
    g_fg_r = fg_r;
    g_fg_g = fg_g;
    g_fg_b = fg_b;
    g_fg_a = fg_a;
    for (int i = 0; i < g_n; i++) {
        paint_toast(&g_toasts[i]);
    }
    if (g_n > 0) {
        XFlush(g_dpy);
    }
}

void toast_tick(uint64_t now)
{
    /* Walk front-to-back and only ever remove one per call -- remove_toast()
     * already restacks everyone else, and another expiry (if any) gets
     * caught on the very next tick, which is cheap enough (main loop ticks
     * at least once a second regardless, see xispanel.c's timeout_ms
     * fallback) not to bother batching. A hovered toast is skipped
     * entirely -- see the `hovered` doc comment on Toast. */
    for (int i = 0; i < g_n; i++) {
        if (!g_toasts[i].hovered && g_toasts[i].expire_ms != 0 && now >= g_toasts[i].expire_ms) {
            remove_toast(i);
            return;
        }
    }
}

uint64_t toast_next_wake_ms(void)
{
    uint64_t soonest = 0;
    for (int i = 0; i < g_n; i++) {
        if (g_toasts[i].hovered || g_toasts[i].expire_ms == 0) {
            continue;
        }
        if (soonest == 0 || g_toasts[i].expire_ms < soonest) {
            soonest = g_toasts[i].expire_ms;
        }
    }
    return soonest;
}

int toast_handle_event(const XEvent *ev)
{
    if (ev->type == ButtonPress) {
        for (int i = 0; i < g_n; i++) {
            if (g_toasts[i].win == ev->xbutton.window) {
                notifd_mark_read(g_toasts[i].notif_id);
                remove_toast(i);
                return 1;
            }
        }
    } else if (ev->type == Expose) {
        for (int i = 0; i < g_n; i++) {
            if (g_toasts[i].win == ev->xexpose.window) {
                paint_toast(&g_toasts[i]);
                XFlush(g_dpy);
                return 1;
            }
        }
    } else if (ev->type == EnterNotify) {
        for (int i = 0; i < g_n; i++) {
            if (g_toasts[i].win == ev->xcrossing.window) {
                g_toasts[i].hovered = 1;
                return 1;
            }
        }
    } else if (ev->type == LeaveNotify) {
        for (int i = 0; i < g_n; i++) {
            if (g_toasts[i].win == ev->xcrossing.window) {
                g_toasts[i].hovered = 0;
                /* Restart the full countdown rather than resuming --
                 * see the `hovered`/`timeout_ms` doc comment on Toast. */
                if (g_toasts[i].timeout_ms != 0) {
                    g_toasts[i].expire_ms = now_ms() + g_toasts[i].timeout_ms;
                }
                return 1;
            }
        }
    }
    return 0;
}
