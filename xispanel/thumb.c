/*
 * thumb.c - live window thumbnails for tasklist's tooltip (show_thumbs=
 * yes), via the XComposite + XDamage extensions. Gated on both an active
 * compositor (checked by looking for an owner of the _NET_WM_CM_S<screen>
 * selection -- the same convention every compositing WM/EWMH client uses
 * to detect one) and, per the Makefile, whether libXcomposite/libXdamage
 * were available at build time at all -- see thumb_stub.c for the
 * build-time fallback.
 *
 * Once a compositor is running, every top-level window is automatically
 * redirected to an offscreen pixmap (that's what "compositing" means),
 * so unlike an explicit-compositor implementation, this never needs to
 * call XCompositeRedirectWindow itself -- XCompositeNameWindowPixmap()
 * on a *redirected* window just works. thumb_paint() re-fetches that
 * pixmap fresh every call rather than caching a surface across calls --
 * simpler, and avoids the classic stale-composite-pixmap pitfall (the
 * pixmap ID silently stops updating across certain window state changes
 * like unmap/map or resize). *When* it's called is driven by XDamage,
 * not a blind timer: thumb_watch()/thumb_handle_event()/thumb_take_
 * dirty() (below) let tooltip.c repaint the popup exactly when the
 * watched window's content actually changed (server-side damage
 * tracking), which is what makes it look genuinely live -- the earlier
 * fixed-interval-repaint approach looked like a slideshow of periodic
 * screenshots instead, since it repainted at some arbitrary rate
 * regardless of whether anything had actually changed.
 *
 * The catch: on a reparenting WM, the window `_NET_CLIENT_LIST` reports
 * is not necessarily the one that's actually redirected -- some WMs
 * (confirmed on this repo's own KWin fork) wrap the client in one or
 * more of their own frame windows, and it's an *ancestor* frame that's
 * redirected, not the raw client window, which fails with a `BadMatch`.
 * `thumb_paint()` retries up the `XQueryTree()` parent chain (capped at
 * 4 hops) until one succeeds or it hits the root, rather than assuming
 * either "always the client" or "always the immediate parent".
 *
 * XCompositeNameWindowPixmap can also raise a BadMatch for an entirely
 * unrelated reason -- the window closed between the tasklist poll that
 * found it and this paint -- so every call here runs under a temporary,
 * deliberately-permissive XErrorHandler regardless. (xispanel.c also
 * installs a permanent permissive handler for the whole process, since
 * this general "window disappeared mid-query" race isn't unique to
 * thumbnails -- see x_error_handler() there.)
 */
#include "xispanel.h"

#include <X11/Xlib.h>
#include <X11/extensions/Xcomposite.h>
#include <X11/extensions/Xdamage.h>
#include <cairo/cairo-xlib.h>

#include <signal.h>
#include <stdio.h>

static int g_composite_checked = 0;
static int g_composite_ext_present = 0;

static int g_damage_checked = 0;
static int g_damage_ext_present = 0;
static int g_damage_event_base = 0;
static int g_damage_error_base = 0;

static volatile sig_atomic_t g_thumb_had_error;

static Window resolve_composited_window(Window win, XWindowAttributes *out_wa, Pixmap *out_pix);

static int thumb_error_handler(Display *dpy, XErrorEvent *ev)
{
    (void)dpy;
    (void)ev;
    g_thumb_had_error = 1;
    return 0;
}

int thumb_available(void)
{
    if (!g_composite_checked) {
        g_composite_checked = 1;
        int event_base, error_base;
        g_composite_ext_present = XCompositeQueryExtension(g_dpy, &event_base, &error_base);
    }
    if (!g_composite_ext_present) {
        return 0;
    }

    char prop_name[32];
    snprintf(prop_name, sizeof(prop_name), "_NET_WM_CM_S%d", g_screen);
    Atom cm_atom = XInternAtom(g_dpy, prop_name, False);
    return XGetSelectionOwner(g_dpy, cm_atom) != None;
}

static int damage_available(void)
{
    if (!g_damage_checked) {
        g_damage_checked = 1;
        g_damage_ext_present = XDamageQueryExtension(g_dpy, &g_damage_event_base, &g_damage_error_base);
    }
    return g_damage_ext_present;
}

/* Live-thumbnail tracking: tooltip.c calls thumb_watch() for every window
 * a shown tooltip currently displays a thumbnail of (re-synced on every
 * show_popup(), see there), and thumb_unwatch_all() once that tooltip
 * closes or moves to different window(s). Each watched window gets an
 * XDamage handle (XDamageReportNonEmpty -- only care *that* something
 * changed, not the precise region); thumb_handle_event(), called from
 * xispanel.c's main event loop, sets g_thumb_dirty as notifications for a
 * watched window arrive, and tooltip_tick() polls/clears that flag once
 * per iteration via thumb_take_dirty() to decide whether to repaint.
 * This is what makes the thumbnail track the window's actual live
 * content (like plasmashell's/compiz's own live previews) instead of
 * being a single snapshot taken when the tooltip first opened, or --
 * worse -- looking like a slideshow of periodic screenshots if driven by
 * a blind timer instead of real damage events. */
#define THUMB_MAX_WATCHES 8
typedef struct {
    Window win; /* as passed by the caller (tooltip.c) -- only used for the idempotency check below */
    Damage damage;
    /* The ancestor thumb_watch() actually resolved `win` to (see
     * resolve_composited_window()) -- cached here so thumb_paint() can
     * skip straight to it on every subsequent frame instead of redoing
     * the whole "try the client window, fail, walk up to the parent"
     * dance (with its XSync round-trip) on every single repaint. At
     * video framerates that dance was the entire bottleneck: retried
     * every frame, it capped the achievable repaint rate at a couple of
     * frames a second regardless of how fast damage events arrived. */
    Window target;
} ThumbWatch;
static ThumbWatch g_watches[THUMB_MAX_WATCHES];
static int g_n_watches = 0;
static volatile sig_atomic_t g_thumb_dirty = 0;

void thumb_watch(Window win)
{
    if (win == None || !thumb_available() || !damage_available()) {
        return;
    }
    for (int i = 0; i < g_n_watches; i++) {
        if (g_watches[i].win == win) {
            return; /* already watching */
        }
    }
    if (g_n_watches >= THUMB_MAX_WATCHES) {
        return; /* group tooltips stay well under this cap */
    }

    XErrorHandler prev = XSetErrorHandler(thumb_error_handler);

    /* Must create the Damage handle on the *same* window thumb_paint()
     * actually reads a composited pixmap from, not blindly on `win` --
     * on this KWin fork, `win` (the raw client window _NET_CLIENT_LIST
     * reports) very often isn't the one that's composite-redirected, an
     * ancestor frame is (see resolve_composited_window()'s doc comment).
     * Watching the wrong window silently never generates the damage
     * events this whole mechanism depends on -- it doesn't error, it
     * just never fires, which is much harder to notice than a crash. */
    XWindowAttributes wa;
    Pixmap pix = None;
    Window target = resolve_composited_window(win, &wa, &pix);
    if (target == None) {
        XSetErrorHandler(prev);
        return;
    }
    XFreePixmap(g_dpy, pix); /* only needed it to find `target`, not to keep */

    g_thumb_had_error = 0;
    Damage d = XDamageCreate(g_dpy, target, XDamageReportNonEmpty);
    XSync(g_dpy, False);
    XSetErrorHandler(prev);
    if (g_thumb_had_error) {
        return; /* window closed between resolving `target` and here */
    }
    g_watches[g_n_watches].win = win;
    g_watches[g_n_watches].damage = d;
    g_watches[g_n_watches].target = target;
    g_n_watches++;
}

void thumb_unwatch_all(void)
{
    if (g_n_watches == 0) {
        return;
    }
    XErrorHandler prev = XSetErrorHandler(thumb_error_handler);
    for (int i = 0; i < g_n_watches; i++) {
        g_thumb_had_error = 0;
        XDamageDestroy(g_dpy, g_watches[i].damage); /* BadDamage if the window already closed -- ignored, same as everywhere else */
    }
    XSetErrorHandler(prev);
    g_n_watches = 0;
    g_thumb_dirty = 0;
}

int thumb_handle_event(const XEvent *ev)
{
    if (!damage_available() || ev->type != g_damage_event_base + XDamageNotify) {
        return 0;
    }
    const XDamageNotifyEvent *dev = (const XDamageNotifyEvent *)ev;
    /* Acknowledges the event and resets the reported region -- required
     * even for a damage handle we're no longer tracking (a stale event
     * for a just-unwatched window), otherwise the server keeps queuing
     * more for it. */
    XDamageSubtract(g_dpy, dev->damage, None, None);
    for (int i = 0; i < g_n_watches; i++) {
        if (g_watches[i].damage == dev->damage) {
            g_thumb_dirty = 1;
            break;
        }
    }
    return 1;
}

int thumb_take_dirty(void)
{
    if (!g_thumb_dirty) {
        return 0;
    }
    g_thumb_dirty = 0;
    return 1;
}

/* Tries to get a live composited pixmap for exactly `win`. Returns None
 * (leaving *out_wa untouched) on any failure -- BadMatch is common here
 * on a reparenting WM, where the *client* window itself was never
 * individually redirected, only its WM-added frame around it (see
 * thumb_paint()'s fallback below). */
static Pixmap try_name_window_pixmap(Window win, XWindowAttributes *out_wa)
{
    if (!XGetWindowAttributes(g_dpy, win, out_wa) || g_thumb_had_error || out_wa->map_state != IsViewable ||
        out_wa->width <= 0 || out_wa->height <= 0) {
        return None;
    }
    Pixmap pix = XCompositeNameWindowPixmap(g_dpy, win);
    XSync(g_dpy, False);
    if (g_thumb_had_error || pix == None) {
        return None;
    }
    return pix;
}

/* Walks from `win` up through its ancestors (capped at 4 hops) looking
 * for whichever one actually names a live composited pixmap --
 * reparenting WMs (KWin included) often only redirect the frame window
 * they wrap the client in, not the raw client window _NET_CLIENT_LIST
 * reports (see the file comment). Returns None (leaving out_wa/out_pix
 * untouched) if nothing up the chain works. Must be called with the
 * permissive thumb_error_handler already installed (both thumb_paint()
 * and thumb_watch() do this themselves) -- every X call here can fail on
 * an ordinary "window closed mid-query" race, not just the redirect
 * mismatch this is nominally for. */
static Window resolve_composited_window(Window win, XWindowAttributes *out_wa, Pixmap *out_pix)
{
    g_thumb_had_error = 0;
    Pixmap pix = try_name_window_pixmap(win, out_wa);
    if (pix != None) {
        *out_pix = pix;
        return win;
    }

    g_thumb_had_error = 0;
    Window root_ret, parent, *kids = NULL;
    unsigned int n_kids = 0;
    Window probe = win;
    for (int hops = 0; hops < 4; hops++) {
        g_thumb_had_error = 0; /* stale failure from the previous hop's try_name_window_pixmap()
                                 * would otherwise look like *this* hop's XQueryTree failed */
        if (!XQueryTree(g_dpy, probe, &root_ret, &parent, &kids, &n_kids) || g_thumb_had_error) {
            break;
        }
        if (kids) {
            XFree(kids);
            kids = NULL;
        }
        if (parent == None || parent == root_ret) {
            break;
        }
        pix = try_name_window_pixmap(parent, out_wa);
        if (pix != None) {
            *out_pix = pix;
            return parent;
        }
        probe = parent;
    }
    return None;
}

int thumb_paint(cairo_t *cr, Window win, double x, double y, double max_w, double max_h)
{
    if (!thumb_available()) {
        return 0;
    }

    XErrorHandler prev = XSetErrorHandler(thumb_error_handler);
    g_thumb_had_error = 0;

    XWindowAttributes wa;
    Pixmap pix = None;

    /* Fast path: if `win` is currently being watched, thumb_watch() has
     * already done the one-time "which ancestor is actually composite-
     * redirected" discovery (see ThumbWatch::target's doc comment) --
     * skip straight to it with a single XGetWindowAttributes +
     * XCompositeNameWindowPixmap, no XSync. This is what lets damage-
     * driven repaints (many times a second for video content) actually
     * keep up -- redoing the full "try the client, fail, walk up to the
     * parent, XSync to confirm" dance from scratch on every frame (the
     * slow path below) was the entire bottleneck, capping the real-world
     * repaint rate at a couple of frames a second no matter how fast
     * damage events arrived. Any async X error from a since-closed
     * window is silently absorbed by the process-wide permissive handler
     * once this function's own temporary one is restored below -- same
     * "log and continue" tradeoff already made everywhere else here. */
    for (int i = 0; i < g_n_watches; i++) {
        if (g_watches[i].win == win) {
            Window target = g_watches[i].target;
            if (XGetWindowAttributes(g_dpy, target, &wa) && !g_thumb_had_error && wa.map_state == IsViewable &&
                wa.width > 0 && wa.height > 0) {
                pix = XCompositeNameWindowPixmap(g_dpy, target);
            }
            break;
        }
    }

    if (pix == None) {
        /* No cache entry (win isn't currently watched -- e.g. the very
         * first frame, painted before show_popup() calls thumb_watch()),
         * or the fast path above didn't even get a pixmap ID back --
         * fall back to the full resolve, a one-off cost in that case. */
        g_thumb_had_error = 0;
        if (resolve_composited_window(win, &wa, &pix) == None) {
            XSetErrorHandler(prev);
            return 0;
        }
    }

    cairo_surface_t *surf = cairo_xlib_surface_create(g_dpy, pix, wa.visual, wa.width, wa.height);
    if (cairo_surface_status(surf) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(surf);
        XFreePixmap(g_dpy, pix);
        XSetErrorHandler(prev);
        return 0;
    }

    double scale = max_w / wa.width < max_h / wa.height ? max_w / wa.width : max_h / wa.height;
    if (scale > 1.0) {
        scale = 1.0; /* never upscale a small window past its real size */
    }
    double draw_w = wa.width * scale;
    double draw_h = wa.height * scale;
    double dx = x + (max_w - draw_w) / 2.0;
    double dy = y + (max_h - draw_h) / 2.0;

    cairo_save(cr);
    cairo_translate(cr, dx, dy);
    cairo_scale(cr, scale, scale);
    cairo_set_source_surface(cr, surf, 0, 0);
    cairo_paint(cr);
    cairo_restore(cr);

    cairo_surface_destroy(surf);
    XFreePixmap(g_dpy, pix);
    XSetErrorHandler(prev);
    return 1;
}
