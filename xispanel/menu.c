/*
 * menu.c - generic context-menu popup.
 *
 * Any widget can open one via panel_menu_open() with its own item list,
 * an opaque ctx pointer, and a selection callback -- this file doesn't
 * know or care what the items mean, only how to draw/position/dismiss
 * the popup and report which index got picked.
 *
 * Dismissal relies on an exclusive pointer grab with owner_events=False,
 * which reports every button/motion event relative to the menu window
 * regardless of what's physically under the pointer: a click whose
 * coordinates fall outside [0,width)x[0,height) is therefore always a
 * "clicked outside" and just dismisses the menu, without re-delivering
 * that click to whatever was actually underneath it (a known, accepted
 * simplification -- the user just has to click again for that).
 *
 * Only one menu can be open at a time (a second panel_menu_open() call
 * closes whatever was already open first).
 */
#include "xispanel.h"

#include <X11/Xatom.h>
#include <X11/keysym.h>
#include <cairo/cairo-xlib.h>

#include <stdlib.h>
#include <string.h>

typedef struct {
    Window win;
    cairo_surface_t *surface;
    cairo_t *cr;
    MenuItem items[24]; /* bumped from 8 to fit flattened DBusMenu menus (tray items like
                          * fcitx5's input-method switcher can have a dozen+ entries) */
    int n_items;
    int item_h;
    int width, height;
    int hover_index;
    Panel *owner_panel;
    PanelWidget *owner_widget;
    void *ctx;
    MenuSelectFn on_select;
} PanelMenu;

static PanelMenu *g_menu = NULL;

void panel_menu_close(void)
{
    if (!g_menu) {
        return;
    }
    XUngrabKeyboard(g_dpy, CurrentTime);
    XUngrabPointer(g_dpy, CurrentTime);
    if (g_menu->cr) {
        cairo_destroy(g_menu->cr);
    }
    if (g_menu->surface) {
        cairo_surface_destroy(g_menu->surface);
    }
    XDestroyWindow(g_dpy, g_menu->win);
    free(g_menu);
    g_menu = NULL;
    XFlush(g_dpy);
}

static void panel_menu_paint(void)
{
    PanelMenu *m = g_menu;
    if (!m) {
        return;
    }
    Panel *p = m->owner_panel;
    cairo_set_operator(m->cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_rgba(m->cr, p->bg_r, p->bg_g, p->bg_b, p->bg_a);
    cairo_paint(m->cr);
    cairo_set_operator(m->cr, CAIRO_OPERATOR_OVER);
    if (g_font_face) {
        cairo_set_font_face(m->cr, g_font_face);
    }
    cairo_set_font_size(m->cr, m->item_h * 0.5);
    for (int i = 0; i < m->n_items; i++) {
        int y = i * m->item_h;
        MenuItem *it = &m->items[i];
        if (it->is_separator) {
            cairo_set_source_rgba(m->cr, p->fg_r, p->fg_g, p->fg_b, 0.15);
            cairo_move_to(m->cr, 6, y + m->item_h / 2.0);
            cairo_line_to(m->cr, m->width - 6, y + m->item_h / 2.0);
            cairo_set_line_width(m->cr, 1);
            cairo_stroke(m->cr);
            continue;
        }
        if (i == m->hover_index && it->enabled) {
            cairo_set_source_rgba(m->cr, p->fg_r, p->fg_g, p->fg_b, 0.12);
            cairo_rectangle(m->cr, 0, y, m->width, m->item_h);
            cairo_fill(m->cr);
        }
        cairo_set_source_rgba(m->cr, p->fg_r, p->fg_g, p->fg_b, it->enabled ? 0.95 : 0.4);
        cairo_text_extents_t ext;
        cairo_text_extents(m->cr, it->label, &ext);
        cairo_move_to(m->cr, 10, y + (m->item_h - ext.height) / 2.0 - ext.y_bearing);
        cairo_show_text(m->cr, it->label);
    }
    cairo_surface_flush(m->surface);
    XFlush(g_dpy);
}

void panel_menu_open(Panel *owner_panel, PanelWidget *owner_widget, int anchor_x, int anchor_w, const MenuItem *items,
                      int n_items, void *ctx, MenuSelectFn on_select)
{
    (void)anchor_w; /* only the leading edge is needed for a dropdown-style menu */
    if (g_menu) {
        panel_menu_close();
    }
    int max_items = (int)(sizeof(((PanelMenu *)0)->items) / sizeof(MenuItem));
    if (n_items <= 0 || n_items > max_items) {
        return;
    }

    PanelMenu *m = calloc(1, sizeof(PanelMenu));
    if (!m) {
        return;
    }
    memcpy(m->items, items, sizeof(MenuItem) * (size_t)n_items);
    m->n_items = n_items;
    m->owner_panel = owner_panel;
    m->owner_widget = owner_widget;
    m->ctx = ctx;
    m->on_select = on_select;
    m->hover_index = -1;

    m->item_h = (int)(owner_panel->thickness * 0.7);
    if (m->item_h < 20) {
        m->item_h = 20;
    }

    /* Measure against a throwaway surface (no mapped menu window/cairo
     * context exists yet to measure against). */
    cairo_surface_t *probe_surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 1, 1);
    cairo_t *probe_cr = cairo_create(probe_surf);
    if (g_font_face) {
        cairo_set_font_face(probe_cr, g_font_face);
    }
    cairo_set_font_size(probe_cr, m->item_h * 0.5);
    int max_w = 80;
    for (int i = 0; i < n_items; i++) {
        if (m->items[i].is_separator) {
            continue;
        }
        cairo_text_extents_t ext;
        cairo_text_extents(probe_cr, m->items[i].label, &ext);
        int w = (int)ext.x_advance + 20;
        if (w > max_w) {
            max_w = w;
        }
    }
    cairo_destroy(probe_cr);
    cairo_surface_destroy(probe_surf);

    m->width = max_w;
    m->height = m->item_h * n_items;

    /* Glued to the panel's outer edge (below a top panel, above a bottom
     * one, beside a left/right one), leading edge aligned to the anchor
     * item -- same convention as plasmashell's taskbar context menus,
     * not "wherever the click happened to land". */
    int screen_x, screen_y;
    if (owner_panel->edge == EDGE_TOP || owner_panel->edge == EDGE_BOTTOM) {
        screen_x = owner_panel->x + owner_widget->x + anchor_x;
        screen_y = (owner_panel->edge == EDGE_TOP) ? (owner_panel->y + owner_panel->h) : (owner_panel->y - m->height);
    } else {
        screen_x = (owner_panel->edge == EDGE_LEFT) ? (owner_panel->x + owner_panel->w) : (owner_panel->x - m->width);
        screen_y = owner_panel->y + owner_widget->x + anchor_x;
    }

    if (screen_x + m->width > owner_panel->out_x + owner_panel->out_w) {
        screen_x = owner_panel->out_x + owner_panel->out_w - m->width;
    }
    if (screen_y + m->height > owner_panel->out_y + owner_panel->out_h) {
        screen_y = owner_panel->out_y + owner_panel->out_h - m->height;
    }
    if (screen_x < owner_panel->out_x) {
        screen_x = owner_panel->out_x;
    }
    if (screen_y < owner_panel->out_y) {
        screen_y = owner_panel->out_y;
    }

    XSetWindowAttributes attrs;
    memset(&attrs, 0, sizeof(attrs));
    attrs.override_redirect = True;
    attrs.colormap = owner_panel->cmap;
    attrs.border_pixel = 0;
    attrs.background_pixel = 0;
    attrs.event_mask = ButtonPressMask | PointerMotionMask | ExposureMask | KeyPressMask;

    m->win = XCreateWindow(g_dpy, g_root, screen_x, screen_y, (unsigned)m->width, (unsigned)m->height, 0,
                            owner_panel->depth, InputOutput, owner_panel->visual,
                            CWOverrideRedirect | CWColormap | CWBorderPixel | CWBackPixel | CWEventMask, &attrs);
    XChangeProperty(g_dpy, m->win, g_atom_wm_window_type, XA_ATOM, 32, PropModeReplace,
                     (unsigned char *)&g_atom_wm_window_type_popup_menu, 1);

    m->surface = cairo_xlib_surface_create(g_dpy, m->win, owner_panel->visual, m->width, m->height);
    m->cr = cairo_create(m->surface);

    XMapWindow(g_dpy, m->win);
    XRaiseWindow(g_dpy, m->win);

    if (XGrabPointer(g_dpy, m->win, False, ButtonPressMask | PointerMotionMask, GrabModeAsync, GrabModeAsync, None,
                      None, CurrentTime) != GrabSuccess) {
        cairo_destroy(m->cr);
        cairo_surface_destroy(m->surface);
        XDestroyWindow(g_dpy, m->win);
        free(m);
        return;
    }
    XGrabKeyboard(g_dpy, m->win, False, GrabModeAsync, GrabModeAsync, CurrentTime);

    g_menu = m;
    panel_menu_paint();
}

/* Fires the callback for `idx` (if selectable) and closes the menu.
 * Copies out everything the callback needs before panel_menu_close()
 * frees `m`. */
static void panel_menu_select_and_close(int idx)
{
    PanelMenu *m = g_menu;
    if (!m || idx < 0 || idx >= m->n_items || m->items[idx].is_separator || !m->items[idx].enabled) {
        panel_menu_close();
        return;
    }
    Panel *op = m->owner_panel;
    PanelWidget *ow = m->owner_widget;
    void *ctx = m->ctx;
    MenuSelectFn cb = m->on_select;
    panel_menu_close();
    if (cb) {
        cb(op, ow, ctx, idx);
    }
}

int panel_menu_handle_event(const XEvent *ev)
{
    if (!g_menu) {
        return 0;
    }
    PanelMenu *m = g_menu;

    if (ev->type == Expose && ev->xexpose.window == m->win) {
        panel_menu_paint();
        return 1;
    }
    if (ev->type == MotionNotify && ev->xmotion.window == m->win) {
        int idx = (ev->xmotion.y >= 0 && ev->xmotion.y < m->height) ? ev->xmotion.y / m->item_h : -1;
        if (idx < 0 || idx >= m->n_items || m->items[idx].is_separator || !m->items[idx].enabled) {
            idx = -1;
        }
        if (m->hover_index != idx) {
            m->hover_index = idx;
            panel_menu_paint();
        }
        return 1;
    }
    if (ev->type == ButtonPress && ev->xbutton.window == m->win) {
        int x = ev->xbutton.x, y = ev->xbutton.y;
        int idx = (x >= 0 && x < m->width && y >= 0 && y < m->height) ? y / m->item_h : -1;
        panel_menu_select_and_close(idx);
        return 1;
    }
    if (ev->type == KeyPress && ev->xkey.window == m->win) {
        KeySym ks = XLookupKeysym((XKeyEvent *)&ev->xkey, 0);
        if (ks == XK_Escape) {
            panel_menu_close();
        } else if (ks == XK_Return || ks == XK_KP_Enter) {
            panel_menu_select_and_close(m->hover_index);
        }
        return 1;
    }
    return 0;
}
