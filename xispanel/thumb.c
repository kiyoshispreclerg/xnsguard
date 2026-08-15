/*
 * thumb.c - live window thumbnails for tasklist's tooltip (show_thumbs=
 * yes), via the XComposite extension. Gated on both an active compositor
 * (checked by looking for an owner of the _NET_WM_CM_S<screen> selection
 * -- the same convention every compositing WM/EWMH client uses to detect
 * one) and, per the Makefile, whether libXcomposite was available at
 * build time at all -- see thumb_stub.c for the build-time fallback.
 *
 * Once a compositor is running, every top-level window is automatically
 * redirected to an offscreen pixmap (that's what "compositing" means),
 * so unlike an explicit-compositor implementation, this never needs to
 * call XCompositeRedirectWindow itself -- XCompositeNameWindowPixmap()
 * on a *redirected* window just works. thumb_paint() re-fetches that
 * pixmap fresh every call (tooltip.c repaints the popup ~1/s while
 * shown, via the same refresh path clock's tooltip uses) rather than
 * caching a surface across calls -- simpler, and avoids the classic
 * stale-composite-pixmap pitfall (the pixmap ID silently stops updating
 * across certain window state changes like unmap/map or resize).
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
#include <cairo/cairo-xlib.h>

#include <signal.h>
#include <stdio.h>

static int g_composite_checked = 0;
static int g_composite_ext_present = 0;

static volatile sig_atomic_t g_thumb_had_error;

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

int thumb_paint(cairo_t *cr, Window win, double x, double y, double max_w, double max_h)
{
    if (!thumb_available()) {
        return 0;
    }

    XErrorHandler prev = XSetErrorHandler(thumb_error_handler);
    g_thumb_had_error = 0;

    XWindowAttributes wa;
    Pixmap pix = try_name_window_pixmap(win, &wa);
    if (pix == None) {
        /* Reparenting WMs (KWin included) often only redirect the frame
         * window they wrap the client in, not the raw client window
         * _NET_CLIENT_LIST reports -- retry once against the immediate
         * parent (skip straight to the root's direct child, in case of
         * multiple nested wrapper windows) before giving up. */
        g_thumb_had_error = 0;
        Window root_ret, parent, *kids = NULL;
        unsigned int n_kids = 0;
        Window probe = win;
        for (int hops = 0; hops < 4 && pix == None; hops++) {
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
            pix = try_name_window_pixmap(parent, &wa);
            probe = parent;
        }
    }
    if (pix == None) {
        XSetErrorHandler(prev);
        return 0;
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
