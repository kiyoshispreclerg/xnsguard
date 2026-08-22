/*
 * density.c - X-DENSITY client support (see TESTS/X-DENSITY.md for the
 * full protocol spec): lets a compositor optically zoom into one of
 * xispanel's own panel windows, transiently, without the panel's real
 * on-screen geometry ever changing.
 *
 * Detection is the manager-selection convention the spec describes in
 * its own section 5.2 (same idea as _NET_WM_CM_S<screen>): a compositor
 * that actually supports this protocol holds ownership of
 * _X_DENSITY_MANAGER_S<screen> for as long as (and only as long as) it's
 * ready to consume it. Everything below is gated on that, tracked live
 * via XFixes -- not on the three data atoms merely existing, which per
 * the spec's own section 5.1 just means *some* client interned them once,
 * possibly in a past session, not that anyone is listening right now.
 *
 * Rendering: reuses panel_paint_content() (xispanel.c) -- the same
 * logical-coordinate widget paint() calls that build the normal on-screen
 * buffer, just pointed at a bigger surface with a cairo_scale(density,
 * density) pushed first. Cairo's own vector/text rasterization redraws
 * crisp at any scale this way. One known, deliberate limitation: icons
 * are pre-rendered fixed-size ARGB32 bitmaps (see ewmh_get_icon_surface()/
 * resolve_icon_theme_name()'s target_size), so they scale up as bitmaps
 * rather than gaining any real extra sharpness -- fixing that would mean
 * re-fetching every icon at a density-scaled target size for this render
 * pass alone, a larger change than this first cut makes. Text, borders,
 * hover/active highlights, and the pager's own vector grid all render
 * genuinely sharper.
 */
#include "xispanel.h"

#include <X11/Xatom.h>
#include <X11/extensions/Xfixes.h>
#include <cairo/cairo-xlib.h>

#include <stdio.h>
#include <string.h>

static Atom g_atom_density_manager;
static Atom g_atom_density_requested;
static Atom g_atom_density_scale;
static Atom g_atom_density_pixmap;

static int g_xfixes_event_base;
static int g_xfixes_error_base;
static int g_xfixes_available;
static int g_compositor_present;

/* True once (and only once) some compositor holds the manager selection
 * -- every entry point below bails out immediately when this is false,
 * per the spec's "ignore _X_DENSITY_REQUESTED entirely, don't even read
 * it" rule (section 5.2). */
static int compositor_present(void)
{
    return g_xfixes_available && g_compositor_present;
}

void density_init(void)
{
    char mgr_name[32];
    snprintf(mgr_name, sizeof(mgr_name), "_X_DENSITY_MANAGER_S%d", g_screen);
    g_atom_density_manager = XInternAtom(g_dpy, mgr_name, False);
    g_atom_density_requested = XInternAtom(g_dpy, "_X_DENSITY_REQUESTED", False);
    g_atom_density_scale = XInternAtom(g_dpy, "_X_DENSITY_SCALE", False);
    g_atom_density_pixmap = XInternAtom(g_dpy, "_X_DENSITY_PIXMAP", False);

    g_xfixes_available = XFixesQueryExtension(g_dpy, &g_xfixes_event_base, &g_xfixes_error_base);
    if (!g_xfixes_available) {
        fprintf(stderr, "xispanel: XFixes unavailable -- X-DENSITY support disabled\n");
        return;
    }
    g_compositor_present = XGetSelectionOwner(g_dpy, g_atom_density_manager) != None;
    XFixesSelectSelectionInput(g_dpy, g_root, g_atom_density_manager,
                                XFixesSetSelectionOwnerNotifyMask | XFixesSelectionWindowDestroyNotifyMask |
                                    XFixesSelectionClientCloseNotifyMask);
    if (g_compositor_present) {
        fprintf(stderr, "xispanel: X-DENSITY-compatible compositor detected\n");
    }
}

/* Snaps one panel back to 1/1 and drops its auxiliary pixmap -- the
 * compositor that would have sampled it is gone, so continuing to
 * publish one would leave it visibly frozen/blank instead of just "not
 * specially sharp" (see the spec's section 5.2 decision rules). */
static void reset_one_panel_density(Panel *p, void *ctx)
{
    (void)ctx;
    if (p->density_num != 1 || p->density_den != 1) {
        p->density_num = 1;
        p->density_den = 1;
        XDeleteProperty(g_dpy, p->win, g_atom_density_scale);
        XDeleteProperty(g_dpy, p->win, g_atom_density_pixmap);
    }
    density_panel_destroyed(p);
}

static void density_reset_all_panels(void)
{
    panel_foreach(reset_one_panel_density, NULL);
}

int density_handle_xfixes_event(const XEvent *ev)
{
    if (!g_xfixes_available || ev->type != g_xfixes_event_base + XFixesSelectionNotify) {
        return 0;
    }
    int now_present = XGetSelectionOwner(g_dpy, g_atom_density_manager) != None;
    if (now_present != g_compositor_present) {
        g_compositor_present = now_present;
        fprintf(stderr, "xispanel: X-DENSITY compositor %s\n", now_present ? "appeared" : "disappeared");
        if (!now_present) {
            density_reset_all_panels();
        }
    }
    return 1;
}

int density_handle_property(Panel *p, const XPropertyEvent *ev)
{
    if (ev->window != p->win || ev->atom != g_atom_density_requested) {
        return 0;
    }
    if (!compositor_present()) {
        /* Per spec: without a confirmed compositor, ignore the request
         * entirely -- don't even read it. Whoever wrote it either isn't a
         * real compositor, or the selection hasn't propagated to us yet. */
        return 1;
    }
    Atom actual_type;
    int actual_format;
    unsigned long n_items, bytes_after;
    unsigned char *prop = NULL;
    int num = 1, den = 1;
    if (XGetWindowProperty(g_dpy, p->win, g_atom_density_requested, 0, 2, False, XA_CARDINAL, &actual_type,
                            &actual_format, &n_items, &bytes_after, &prop) == Success &&
        prop) {
        if (n_items >= 2) {
            long *v = (long *)(void *)prop;
            if (v[0] > 0 && v[1] > 0) {
                num = (int)v[0];
                den = (int)v[1];
            }
        }
        XFree(prop);
    }
    if (num != p->density_num || den != p->density_den) {
        p->density_num = num;
        p->density_den = den;
        p->dirty = 1; /* next repaint picks up density_render() below with the new factor */
    }
    return 1;
}

/* (Re)creates p->density_pixmap/surface/cr (and the CPU-side img_surface/
 * img_cr widgets actually paint into -- see the doc comment on those
 * fields in xispanel.h) at pw x ph if the size (or pixmap itself) doesn't
 * already match -- same "only touch what changed" shape as
 * panel_create_surface()'s own resize path. */
static int density_ensure_pixmap(Panel *p, int pw, int ph)
{
    if (p->density_pixmap != None && p->density_pixmap_w == pw && p->density_pixmap_h == ph) {
        return 1;
    }
    density_panel_destroyed(p);
    p->density_pixmap = XCreatePixmap(g_dpy, p->win, (unsigned)pw, (unsigned)ph, (unsigned)p->depth);
    if (p->density_pixmap == None) {
        return 0;
    }
    p->density_surface = cairo_xlib_surface_create(g_dpy, p->density_pixmap, p->visual, pw, ph);
    p->density_cr = cairo_create(p->density_surface);
    p->density_img_surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, pw, ph);
    p->density_img_cr = cairo_create(p->density_img_surface);
    if (g_font_face) {
        cairo_set_font_face(p->density_img_cr, g_font_face);
    }
    cairo_set_font_size(p->density_img_cr, panel_text_size(p));
    p->density_pixmap_w = pw;
    p->density_pixmap_h = ph;
    return 1;
}

void density_render(Panel *p)
{
    if (p->density_num == 1 && p->density_den == 1) {
        return; /* the vastly common case -- nothing requested, nothing to do */
    }
    if (!compositor_present()) {
        /* The compositor vanished between the property write and this
         * repaint (density_handle_xfixes_event() already resets on that
         * path normally, but a request could in principle land in the
         * same event-loop iteration as the disappearance) -- don't publish
         * a pixmap nobody will read. */
        return;
    }
    double scale = (double)p->density_num / p->density_den;
    int pw = (int)(p->w * scale + 0.5);
    int ph = (int)(p->h * scale + 0.5);
    if (pw < 1 || ph < 1) {
        return;
    }
    if (!density_ensure_pixmap(p, pw, ph)) {
        return;
    }

    /* Draw off-screen first, one atomic blit onto the actual pixmap after
     * -- see the doc comment on density_img_surface/density_cr in
     * xispanel.h for why (a Pixmap has no auto-Damage, so writing widgets
     * to it directly, one X request per fill/stroke, let a Damage-
     * tracking compositor resample mid-frame -- visible as flicker). */
    panel_paint_content(p, p->density_img_cr, scale);
    cairo_surface_flush(p->density_img_surface);

    /* Content first, announce after (spec section 4) -- avoids the
     * compositor sampling a stale-sized or half-drawn pixmap. */
    cairo_save(p->density_cr);
    cairo_set_operator(p->density_cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_surface(p->density_cr, p->density_img_surface, 0, 0);
    cairo_paint(p->density_cr);
    cairo_restore(p->density_cr);
    cairo_surface_flush(p->density_surface);

    long scale_val[2] = {p->density_num, p->density_den};
    XChangeProperty(g_dpy, p->win, g_atom_density_scale, XA_CARDINAL, 32, PropModeReplace, (unsigned char *)scale_val,
                     2);
    /* Rewriting the same XID every frame is deliberate, not redundant --
     * a Pixmap generates no Damage/Expose of its own when its content
     * changes (it's just memory, not a live surface), so this PropertyNotify
     * is the compositor's only signal to resample, even when the XID
     * itself hasn't changed since last frame (spec section 4). */
    long pixmap_val = (long)p->density_pixmap;
    XChangeProperty(g_dpy, p->win, g_atom_density_pixmap, XA_CARDINAL, 32, PropModeReplace,
                     (unsigned char *)&pixmap_val, 1);
    XFlush(g_dpy);
}

void density_panel_destroyed(Panel *p)
{
    if (p->density_img_cr) {
        cairo_destroy(p->density_img_cr);
        p->density_img_cr = NULL;
    }
    if (p->density_img_surface) {
        cairo_surface_destroy(p->density_img_surface);
        p->density_img_surface = NULL;
    }
    if (p->density_cr) {
        cairo_destroy(p->density_cr);
        p->density_cr = NULL;
    }
    if (p->density_surface) {
        cairo_surface_destroy(p->density_surface);
        p->density_surface = NULL;
    }
    if (p->density_pixmap != None) {
        XFreePixmap(g_dpy, p->density_pixmap);
        p->density_pixmap = None;
    }
    p->density_pixmap_w = 0;
    p->density_pixmap_h = 0;
}
