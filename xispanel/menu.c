/*
 * menu.c - generic context-menu popup, with real cascading submenus.
 *
 * Any widget can open one via panel_menu_open() (flat, one level) or
 * panel_menu_open_tree() (a flat items[]/depth[] pair encoding an
 * implicit tree -- see xispanel.h) with its own item list, an opaque ctx
 * pointer, and a selection callback -- this file doesn't know or care
 * what the items mean, only how to draw/position/dismiss the popup(s)
 * and report which flat index got picked.
 *
 * A tree menu is rendered as a *stack of separate popup windows*
 * ("frames"), one per open nesting level, each positioned beside its
 * parent frame at the row that spawned it -- classic Windows/GTK/Qt menu
 * style, not everything flattened into one indented list. Only the first
 * (root) frame takes the pointer/keyboard grab (owner_events=False, so
 * every event is reported relative to *that* window regardless of what's
 * physically under the pointer); every other frame is just a plain mapped
 * window with no grab of its own. Hit-testing therefore always works off
 * the event's *root*-relative x_root/y_root (which stay meaningful
 * regardless of which window an owner_events=False grab reports events
 * against), translated into whichever open frame's screen rect actually
 * contains that point.
 *
 * Hovering an item with children opens its submenu as a new frame after
 * owner_panel->tooltip_delay_ms (the same open-delay tooltips use --
 * "respecting the same open/close popup delays" was an explicit design
 * goal, not just for tooltips); clicking such an item opens it
 * immediately. Moving the pointer to a different item in an already-open
 * ancestor frame closes whatever deeper frames no longer apply. Moving
 * the pointer off of every open frame for owner_panel->tooltip_close_
 * delay_ms closes the whole menu, same grace-period idea tooltip.c uses
 * -- clicking a leaf item, or Escape, close it immediately as before.
 *
 * A click whose root coordinates fall outside every open frame is
 * "clicked outside" and just dismisses the whole menu, without
 * re-delivering that click to whatever was actually underneath it -- a
 * known, accepted simplification (click again to interact with that).
 *
 * Only one menu (root + however many of its own submenu frames are open)
 * can be open at a time -- a second panel_menu_open()/panel_menu_open_tree()
 * call closes whatever was already open first.
 */
#include "xispanel.h"

#include <X11/Xatom.h>
#include <X11/keysym.h>
#include <cairo/cairo-xlib.h>

#include <stdlib.h>
#include <string.h>

#define MENU_MAX_FRAMES 6
#define MENU_ARROW_RESERVE 16 /* extra right-edge width reserved when any item in a frame has children */

typedef struct {
    Window win;
    cairo_surface_t *surface;
    cairo_t *cr;
    int idx[MENU_TREE_MAX_ITEMS]; /* flat indices (into PanelMenu::items/depth) shown in this frame, in order */
    int n;
    int hover; /* slot within idx[], -1 = none */
    int width, height;
    int screen_x, screen_y; /* absolute (root) coordinates */
    /* Which slot of the *parent* frame this frame was opened from -- lets
     * handle_motion() tell "still hovering the branch that's open" from
     * "hovering a different item, this frame should collapse away" for
     * frames[i+1] relative to frames[i]. -1 for frame 0 (no parent). */
    int spawned_from_slot;
} MenuFrame;

typedef struct {
    MenuItem items[MENU_TREE_MAX_ITEMS];
    int depth[MENU_TREE_MAX_ITEMS];
    int has_children[MENU_TREE_MAX_ITEMS];
    int n_items;
    int item_h;
    double font_size; /* panel_text_size()-equivalent, resolved once at open time */

    MenuFrame frames[MENU_MAX_FRAMES];
    int n_frames;

    Panel *owner_panel;
    PanelWidget *owner_widget;
    void *ctx;
    MenuSelectFn on_select;
    MenuHoverRootFn on_hover_root;
    MenuCloseFn on_close;

    /* Pending submenu open: frames[pending_frame]'s slot pending_slot has
     * been continuously hovered since pending_since_ms; opens once
     * owner_panel->tooltip_delay_ms elapses. 0 = nothing pending. */
    uint64_t pending_since_ms;
    int pending_frame, pending_slot;

    /* Pointer isn't over any open frame right now; closes the whole menu
     * once owner_panel->tooltip_close_delay_ms elapses. 0 = pointer is
     * over some frame (or we haven't left one yet). */
    uint64_t close_deadline_ms;
} PanelMenu;

static PanelMenu *g_menu = NULL;

static void destroy_frame_resources(MenuFrame *f)
{
    if (f->cr) {
        cairo_destroy(f->cr);
    }
    if (f->surface) {
        cairo_surface_destroy(f->surface);
    }
    if (f->win) {
        XDestroyWindow(g_dpy, f->win);
    }
    memset(f, 0, sizeof(*f));
}

void panel_menu_close(void)
{
    if (!g_menu) {
        return;
    }
    void *ctx = g_menu->ctx;
    MenuCloseFn on_close = g_menu->on_close;
    XUngrabKeyboard(g_dpy, CurrentTime);
    XUngrabPointer(g_dpy, CurrentTime);
    for (int i = 0; i < g_menu->n_frames; i++) {
        destroy_frame_resources(&g_menu->frames[i]);
    }
    free(g_menu);
    g_menu = NULL;
    XFlush(g_dpy);
    if (on_close) {
        on_close(ctx);
    }
}

/* Destroys every frame at `level` and deeper -- used both when collapsing
 * back to a shallower level (pointer moved to a different branch) and as
 * a building block before opening a fresh submenu under some frame. */
static void close_frames_from(int level)
{
    PanelMenu *m = g_menu;
    for (int i = m->n_frames - 1; i >= level; i--) {
        destroy_frame_resources(&m->frames[i]);
    }
    if (level < m->n_frames) {
        m->n_frames = level;
    }
    if (m->pending_since_ms && m->pending_frame >= level) {
        m->pending_since_ms = 0;
    }
}

static void paint_frame(PanelMenu *m, MenuFrame *f)
{
    if (!f->win) {
        return;
    }
    Panel *p = m->owner_panel;
    cairo_t *cr = f->cr;
    cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_rgba(cr, p->bg_r, p->bg_g, p->bg_b, p->bg_a);
    cairo_paint(cr);
    cairo_set_operator(cr, CAIRO_OPERATOR_OVER);
    if (g_font_face) {
        cairo_set_font_face(cr, g_font_face);
    }
    cairo_set_font_size(cr, m->font_size);
    for (int s = 0; s < f->n; s++) {
        int idx = f->idx[s];
        MenuItem *it = &m->items[idx];
        int y = s * m->item_h;
        if (it->is_separator) {
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.15);
            cairo_move_to(cr, 6, y + m->item_h / 2.0);
            cairo_line_to(cr, f->width - 6, y + m->item_h / 2.0);
            cairo_set_line_width(cr, 1);
            cairo_stroke(cr);
            continue;
        }
        if (s == f->hover && it->enabled) {
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.12);
            cairo_rectangle(cr, 0, y, f->width, m->item_h);
            cairo_fill(cr);
        }
        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, it->enabled ? 0.95 : 0.4);
        cairo_text_extents_t ext;
        cairo_text_extents(cr, it->label, &ext);
        cairo_move_to(cr, 10, y + (m->item_h - ext.height) / 2.0 - ext.y_bearing);
        cairo_show_text(cr, it->label);

        if (m->has_children[idx]) {
            double ax = f->width - MENU_ARROW_RESERVE + 4;
            double ay = y + m->item_h / 2.0;
            cairo_set_line_width(cr, 1.4);
            cairo_move_to(cr, ax, ay - 4);
            cairo_line_to(cr, ax + 5, ay);
            cairo_line_to(cr, ax, ay + 4);
            cairo_stroke(cr);
        }
    }
    cairo_surface_flush(f->surface);
    XFlush(g_dpy);
}

/* Fills out_idx[] (and out_n) with the flat indices of parent_idx's
 * *immediate* children (depth[parent_idx]+1), stopping at the first item
 * whose depth
 * drops back to <= depth[parent_idx] -- the boundary of parent_idx's
 * whole subtree in the flat DFS array. */
static void children_of(PanelMenu *m, int parent_idx, int *out_idx, int *out_n)
{
    int n = 0;
    int pd = m->depth[parent_idx];
    for (int k = parent_idx + 1; k < m->n_items && m->depth[k] > pd && n < MENU_TREE_MAX_ITEMS; k++) {
        if (m->depth[k] == pd + 1) {
            out_idx[n++] = k;
        }
    }
    *out_n = n;
}

static int measure_frame_width(PanelMenu *m, const int *idx, int n)
{
    cairo_surface_t *probe_surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 1, 1);
    cairo_t *probe_cr = cairo_create(probe_surf);
    if (g_font_face) {
        cairo_set_font_face(probe_cr, g_font_face);
    }
    cairo_set_font_size(probe_cr, m->font_size);
    int max_w = 80;
    int any_children = 0;
    for (int i = 0; i < n; i++) {
        int fi = idx[i];
        if (m->items[fi].is_separator) {
            continue;
        }
        if (m->has_children[fi]) {
            any_children = 1;
        }
        cairo_text_extents_t ext;
        cairo_text_extents(probe_cr, m->items[fi].label, &ext);
        int w = (int)ext.x_advance + 20;
        if (w > max_w) {
            max_w = w;
        }
    }
    cairo_destroy(probe_cr);
    cairo_surface_destroy(probe_surf);
    return any_children ? max_w + MENU_ARROW_RESERVE : max_w;
}

/* Creates, maps, and paints a frame window for `f` (idx[]/n/width/height/
 * screen_x/screen_y already filled in by the caller) -- shared by the
 * root frame's creation and every submenu frame's. Does *not* grab
 * anything -- only the root frame (frame 0) ever does that. */
static int create_frame_window(PanelMenu *m, MenuFrame *f, int want_grab)
{
    Panel *p = m->owner_panel;
    XSetWindowAttributes attrs;
    memset(&attrs, 0, sizeof(attrs));
    attrs.override_redirect = True;
    attrs.colormap = p->cmap;
    attrs.border_pixel = 0;
    attrs.background_pixel = 0;
    attrs.event_mask = ExposureMask | (want_grab ? (ButtonPressMask | PointerMotionMask | KeyPressMask) : 0);

    f->win = XCreateWindow(g_dpy, g_root, f->screen_x, f->screen_y, (unsigned)f->width, (unsigned)f->height, 0,
                            p->depth, InputOutput, p->visual,
                            CWOverrideRedirect | CWColormap | CWBorderPixel | CWBackPixel | CWEventMask, &attrs);
    XChangeProperty(g_dpy, f->win, g_atom_wm_window_type, XA_ATOM, 32, PropModeReplace,
                     (unsigned char *)&g_atom_wm_window_type_popup_menu, 1);

    f->surface = cairo_xlib_surface_create(g_dpy, f->win, p->visual, f->width, f->height);
    f->cr = cairo_create(f->surface);

    XMapWindow(g_dpy, f->win);
    XRaiseWindow(g_dpy, f->win);

    if (want_grab) {
        if (XGrabPointer(g_dpy, f->win, False, ButtonPressMask | PointerMotionMask, GrabModeAsync, GrabModeAsync,
                          None, None, CurrentTime) != GrabSuccess) {
            destroy_frame_resources(f);
            return 0;
        }
        XGrabKeyboard(g_dpy, f->win, False, GrabModeAsync, GrabModeAsync, CurrentTime);
    }
    return 1;
}

/* Opens parent_idx's (frames[parent_frame]'s slot parent_slot) children as
 * a new frame beside parent_frame, closing any previously-open deeper
 * frames first. Returns 0 (no-op) if that item has no children or the
 * cascade is already as deep as MENU_MAX_FRAMES allows. */
static int open_submenu(PanelMenu *m, int parent_frame, int parent_slot)
{
    MenuFrame *pf = &m->frames[parent_frame];
    int parent_idx = pf->idx[parent_slot];
    int child_idx[MENU_TREE_MAX_ITEMS], child_n;
    children_of(m, parent_idx, child_idx, &child_n);
    if (child_n <= 0) {
        return 0;
    }
    int level = parent_frame + 1;
    if (level >= MENU_MAX_FRAMES) {
        return 0;
    }
    close_frames_from(level);

    MenuFrame *f = &m->frames[level];
    memset(f, 0, sizeof(*f));
    memcpy(f->idx, child_idx, sizeof(int) * (size_t)child_n);
    f->n = child_n;
    f->hover = -1;
    f->spawned_from_slot = parent_slot;
    f->width = measure_frame_width(m, f->idx, f->n);
    f->height = f->n * m->item_h;

    Panel *p = m->owner_panel;
    f->screen_x = pf->screen_x + pf->width;
    f->screen_y = pf->screen_y + parent_slot * m->item_h;
    if (f->screen_x + f->width > p->out_x + p->out_w) {
        f->screen_x = pf->screen_x - f->width; /* flip to the left of the parent frame instead */
    }
    if (f->screen_x < p->out_x) {
        f->screen_x = p->out_x;
    }
    if (f->screen_y + f->height > p->out_y + p->out_h) {
        f->screen_y = p->out_y + p->out_h - f->height;
    }
    if (f->screen_y < p->out_y) {
        f->screen_y = p->out_y;
    }

    if (!create_frame_window(m, f, 0)) {
        return 0;
    }
    m->n_frames = level + 1;
    paint_frame(m, f);
    return 1;
}

/* Fires the callback for `idx` (a flat index) and closes the whole menu.
 * Copies out everything the callback needs before panel_menu_close()
 * frees `m`. */
static void select_and_close(int idx)
{
    PanelMenu *m = g_menu;
    Panel *op = m->owner_panel;
    PanelWidget *ow = m->owner_widget;
    void *ctx = m->ctx;
    MenuSelectFn cb = m->on_select;
    panel_menu_close();
    if (cb) {
        cb(op, ow, ctx, idx);
    }
}

/* Root coordinates -> (frame, slot) currently under the pointer, or
 * frame=-1 if the point isn't inside any open frame at all. slot is -1 if
 * inside the frame's rect but past its last item (e.g. bottom padding, or
 * an empty frame). */
static void hit_test(PanelMenu *m, int root_x, int root_y, int *out_frame, int *out_slot)
{
    for (int i = 0; i < m->n_frames; i++) {
        MenuFrame *f = &m->frames[i];
        if (root_x >= f->screen_x && root_x < f->screen_x + f->width && root_y >= f->screen_y &&
            root_y < f->screen_y + f->height) {
            int slot = (root_y - f->screen_y) / m->item_h;
            *out_frame = i;
            *out_slot = (slot >= 0 && slot < f->n) ? slot : -1;
            return;
        }
    }
    *out_frame = -1;
    *out_slot = -1;
}

static uint64_t close_delay_ms(PanelMenu *m)
{
    return (uint64_t)(m->owner_panel->tooltip_close_delay_ms);
}

static uint64_t open_delay_ms(PanelMenu *m)
{
    return (uint64_t)(m->owner_panel->tooltip_delay_ms);
}

static void handle_motion(int root_x, int root_y)
{
    PanelMenu *m = g_menu;
    if (m->on_hover_root) {
        m->on_hover_root(m->ctx, root_x, root_y);
    }

    int frame, slot;
    hit_test(m, root_x, root_y, &frame, &slot);
    if (frame < 0) {
        if (!m->close_deadline_ms) {
            m->close_deadline_ms = now_ms() + close_delay_ms(m);
        }
        m->pending_since_ms = 0;
        return;
    }
    m->close_deadline_ms = 0;

    MenuFrame *f = &m->frames[frame];
    if (f->hover != slot) {
        f->hover = slot;
        paint_frame(m, f);
    }

    /* A deeper frame is open under this one -- collapse it away unless
     * we're still hovering exactly the slot that spawned it. */
    if (frame + 1 < m->n_frames && m->frames[frame + 1].spawned_from_slot != slot) {
        close_frames_from(frame + 1);
    }

    int has_open_child_here = frame + 1 < m->n_frames && m->frames[frame + 1].spawned_from_slot == slot;
    if (slot >= 0 && m->has_children[f->idx[slot]] && !has_open_child_here) {
        if (m->pending_frame != frame || m->pending_slot != slot) {
            m->pending_frame = frame;
            m->pending_slot = slot;
            m->pending_since_ms = now_ms();
        }
    } else {
        m->pending_since_ms = 0;
    }
}

static void handle_click(int root_x, int root_y)
{
    PanelMenu *m = g_menu;
    int frame, slot;
    hit_test(m, root_x, root_y, &frame, &slot);
    if (frame < 0 || slot < 0) {
        panel_menu_close();
        return;
    }
    int idx = m->frames[frame].idx[slot];
    if (m->items[idx].is_separator || !m->items[idx].enabled) {
        panel_menu_close();
        return;
    }
    if (m->has_children[idx]) {
        open_submenu(m, frame, slot);
        return; /* leaf selection happens on a later click, inside the new submenu */
    }
    select_and_close(idx);
}

void panel_menu_open_tree(Panel *owner_panel, PanelWidget *owner_widget, int anchor_x, int anchor_w,
                           const MenuItem *items, const int *depth, int n_items, void *ctx, MenuSelectFn on_select,
                           MenuHoverRootFn on_hover_root, MenuCloseFn on_close)
{
    (void)anchor_w; /* only the leading edge is needed for a dropdown-style menu */
    if (g_menu) {
        panel_menu_close();
    }
    if (n_items <= 0 || n_items > MENU_TREE_MAX_ITEMS) {
        return;
    }

    PanelMenu *m = calloc(1, sizeof(PanelMenu));
    if (!m) {
        return;
    }
    memcpy(m->items, items, sizeof(MenuItem) * (size_t)n_items);
    memcpy(m->depth, depth, sizeof(int) * (size_t)n_items);
    m->n_items = n_items;
    for (int i = 0; i < n_items; i++) {
        /* Item i's children (if any) always immediately follow it in a
         * DFS-flattened tree, at depth[i]+1 -- see dbusmenu_fetch()'s doc
         * comment on the shape this array is expected to have. */
        m->has_children[i] = (i + 1 < n_items && depth[i + 1] == depth[i] + 1);
    }
    m->owner_panel = owner_panel;
    m->owner_widget = owner_widget;
    m->ctx = ctx;
    m->on_select = on_select;
    m->on_hover_root = on_hover_root;
    m->on_close = on_close;

    m->item_h = (int)(owner_panel->thickness * 0.7);
    if (m->item_h < 20) {
        m->item_h = 20;
    }
    /* font_size_px if set (system-detected or THEME's font_size=), else
     * the historical item_h-proportional size -- same layering
     * panel_text_size() applies to in-panel widget text. */
    m->font_size = owner_panel->font_size_px > 0 ? owner_panel->font_size_px : m->item_h * 0.5;
    if (m->item_h < m->font_size * 1.6) {
        m->item_h = (int)(m->font_size * 1.6); /* keep rows tall enough for a bigger-than-usual font size */
    }

    MenuFrame *f0 = &m->frames[0];
    f0->n = 0;
    for (int i = 0; i < n_items; i++) {
        if (depth[i] == 0 && f0->n < MENU_TREE_MAX_ITEMS) {
            f0->idx[f0->n++] = i;
        }
    }
    f0->hover = -1;
    f0->spawned_from_slot = -1;
    f0->width = measure_frame_width(m, f0->idx, f0->n);
    f0->height = f0->n * m->item_h;

    /* Glued to the panel's outer edge (below a top panel, above a bottom
     * one, beside a left/right one), leading edge aligned to the anchor
     * item -- same convention as plasmashell's taskbar context menus,
     * not "wherever the click happened to land". */
    int screen_x, screen_y;
    if (owner_panel->edge == EDGE_TOP || owner_panel->edge == EDGE_BOTTOM) {
        screen_x = owner_panel->x + owner_widget->x + anchor_x;
        screen_y = (owner_panel->edge == EDGE_TOP) ? (owner_panel->y + owner_panel->h) : (owner_panel->y - f0->height);
    } else {
        screen_x = (owner_panel->edge == EDGE_LEFT) ? (owner_panel->x + owner_panel->w) : (owner_panel->x - f0->width);
        screen_y = owner_panel->y + owner_widget->x + anchor_x;
    }
    if (screen_x + f0->width > owner_panel->out_x + owner_panel->out_w) {
        screen_x = owner_panel->out_x + owner_panel->out_w - f0->width;
    }
    if (screen_y + f0->height > owner_panel->out_y + owner_panel->out_h) {
        screen_y = owner_panel->out_y + owner_panel->out_h - f0->height;
    }
    if (screen_x < owner_panel->out_x) {
        screen_x = owner_panel->out_x;
    }
    if (screen_y < owner_panel->out_y) {
        screen_y = owner_panel->out_y;
    }
    f0->screen_x = screen_x;
    f0->screen_y = screen_y;

    if (!create_frame_window(m, f0, 1)) {
        free(m);
        return;
    }

    m->n_frames = 1;
    g_menu = m;
    paint_frame(m, f0);
}

void panel_menu_open(Panel *owner_panel, PanelWidget *owner_widget, int anchor_x, int anchor_w, const MenuItem *items,
                      int n_items, void *ctx, MenuSelectFn on_select)
{
    if (n_items <= 0 || n_items > MENU_TREE_MAX_ITEMS) {
        return;
    }
    int depth[MENU_TREE_MAX_ITEMS];
    memset(depth, 0, sizeof(int) * (size_t)n_items);
    panel_menu_open_tree(owner_panel, owner_widget, anchor_x, anchor_w, items, depth, n_items, ctx, on_select, NULL,
                          NULL);
}

void panel_menu_tick(uint64_t now)
{
    if (!g_menu) {
        return;
    }
    PanelMenu *m = g_menu;
    if (m->close_deadline_ms && now >= m->close_deadline_ms) {
        panel_menu_close();
        return;
    }
    if (m->pending_since_ms && now - m->pending_since_ms >= open_delay_ms(m)) {
        int pf = m->pending_frame, ps = m->pending_slot;
        m->pending_since_ms = 0;
        open_submenu(m, pf, ps);
    }
}

uint64_t panel_menu_next_wake_ms(void)
{
    if (!g_menu) {
        return 0;
    }
    PanelMenu *m = g_menu;
    uint64_t wake = 0;
    if (m->close_deadline_ms) {
        wake = m->close_deadline_ms;
    }
    if (m->pending_since_ms) {
        uint64_t w2 = m->pending_since_ms + open_delay_ms(m);
        if (wake == 0 || w2 < wake) {
            wake = w2;
        }
    }
    return wake;
}

int panel_menu_handle_event(const XEvent *ev)
{
    if (!g_menu) {
        return 0;
    }
    PanelMenu *m = g_menu;

    if (ev->type == Expose) {
        for (int i = 0; i < m->n_frames; i++) {
            if (ev->xexpose.window == m->frames[i].win) {
                paint_frame(m, &m->frames[i]);
                return 1;
            }
        }
        return 0;
    }
    /* The root frame (frames[0]) holds the only grab -- owner_events=False
     * means every motion/button/key event is reported relative to *that*
     * window regardless of what's physically under the pointer, so these
     * checks are really just "is this event part of the open menu at
     * all" -- actual hit-testing uses x_root/y_root against every open
     * frame's own screen rect (see hit_test()). */
    if (ev->type == MotionNotify && ev->xmotion.window == m->frames[0].win) {
        handle_motion(ev->xmotion.x_root, ev->xmotion.y_root);
        return 1;
    }
    if (ev->type == ButtonPress && ev->xbutton.window == m->frames[0].win) {
        handle_click(ev->xbutton.x_root, ev->xbutton.y_root);
        return 1;
    }
    if (ev->type == KeyPress && ev->xkey.window == m->frames[0].win) {
        KeySym ks = XLookupKeysym((XKeyEvent *)&ev->xkey, 0);
        if (ks == XK_Escape) {
            panel_menu_close();
        } else if (ks == XK_Return || ks == XK_KP_Enter) {
            MenuFrame *f = &m->frames[m->n_frames - 1];
            if (f->hover >= 0) {
                int idx = f->idx[f->hover];
                if (!m->items[idx].is_separator && m->items[idx].enabled) {
                    if (m->has_children[idx]) {
                        open_submenu(m, m->n_frames - 1, f->hover);
                    } else {
                        select_and_close(idx);
                    }
                }
            }
        }
        return 1;
    }
    return 0;
}
