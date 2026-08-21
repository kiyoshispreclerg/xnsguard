/*
 * menu.c - generic context-menu popup, with real cascading submenus,
 * on-demand (lazy) subtree population, and paging for overflowing frames.
 *
 * Any widget can open one via panel_menu_open() (flat, one level),
 * panel_menu_open_tree() (a flat items[]/depth[] pair encoding an
 * implicit tree -- see xispanel.h), or panel_menu_open_tree_lazy() (same,
 * plus a `lazy` array marking items whose children should be fetched on
 * demand via a callback instead of being present up front) with its own
 * item list, an opaque ctx pointer, and a selection callback -- this file
 * doesn't know or care what the items mean, only how to draw/position/
 * dismiss the popup(s) and report which flat index got picked.
 *
 * Internally every item's parent is tracked by an explicit flat index
 * (PanelMenu::parent[], built once from the caller's depth[] array at
 * open time), not by DFS-array-position contiguity -- lazily-fetched
 * children get appended to the end of the item pool whenever their
 * parent is first expanded, wherever m->n_items happens to be at that
 * moment, so contiguity with their parent can't be assumed the way it
 * can for an eagerly-supplied tree. children_of() is the one place that
 * matters.
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
 * A frame with more items than fit the output vertically *pages* instead
 * of overflowing off-screen: its height is capped to the output's own
 * height, reserving one row at the top and bottom for a dim/bright
 * up/down arrow (dim = no previous/next page, same look tasklist's own
 * overflow arrows use) -- clicking a bright arrow jumps a whole page at
 * once, not a continuous scroll. Width still spans every item across
 * every page, so paging never resizes the frame. See frame_row_to_pos().
 *
 * Hovering an item with children opens its submenu as a new frame after
 * owner_panel->tooltip_delay_ms (the same open-delay tooltips use --
 * "respecting the same open/close popup delays" was an explicit design
 * goal, not just for tooltips); clicking such an item opens it
 * immediately (fetching its children first, if lazy). Moving the pointer
 * to a different item in an already-open ancestor frame closes whatever
 * deeper frames no longer apply. Moving the pointer off of every open
 * frame does NOT close the whole menu on its own -- only an explicit
 * click outside every frame (still caught by this file's own pointer
 * grab, see handle_click()'s frame<0 branch), Escape, or selecting a leaf
 * item closes it. This is deliberate: a menu is meant to stay put while
 * the pointer wanders elsewhere (e.g. over a tooltip-bearing widget on
 * the panel) rather than evaporating from a hover-away timeout the way a
 * tooltip does -- see tooltip.c's panel_menu_is_open() check, which
 * relies on this to keep tooltips suppressed for the whole time the menu
 * is actually still open.
 *
 * A click whose root coordinates fall outside every open frame is
 * "clicked outside" and just dismisses the whole menu, without
 * re-delivering that click to whatever was actually underneath it -- a
 * known, accepted simplification (click again to interact with that).
 *
 * Only one menu (root + however many of its own submenu frames are open)
 * can be open at a time -- a second panel_menu_open()/panel_menu_open_
 * tree()/panel_menu_open_tree_lazy() call closes whatever was already
 * open first.
 */
#include "xispanel.h"

#include <X11/Xatom.h>
#include <X11/keysym.h>
#include <cairo/cairo-xlib.h>

#include <stdlib.h>
#include <string.h>

#define MENU_MAX_FRAMES 6
#define MENU_ARROW_RESERVE 16 /* extra right-edge width reserved when any item in a frame has children */
#define MENU_PARENT_STACK_DEPTH 64 /* see depth_to_parent() -- deeper than any real menu/folder tree goes */

/* Row->position sentinels -- see frame_row_to_pos(). */
#define MENU_ROW_NONE (-1)
#define MENU_ROW_PREV (-2)
#define MENU_ROW_NEXT (-3)

typedef struct {
    Window win;
    cairo_surface_t *surface;
    cairo_t *cr;
    int idx[MENU_TREE_MAX_ITEMS]; /* flat indices (into PanelMenu::items/parent) shown in this frame, in order */
    int n; /* total items across every page */
    int paging; /* 1 if n doesn't fit in one page */
    int items_per_page;
    int page, page_count;
    int visible_rows; /* rows actually rendered (== n if !paging, else items_per_page+2 for the arrow rows) */
    int hover_row; /* on-screen row currently hovered, -1 = none */
    int width, height;
    int screen_x, screen_y; /* absolute (root) coordinates */
    /* Which idx[]-position of the *parent* frame this frame was opened
     * from -- lets handle_motion() tell "still hovering the branch
     * that's open" from "hovering a different item, this frame should
     * collapse away" for frames[i+1] relative to frames[i]. -1 for frame
     * 0 (no parent). */
    int spawned_from_pos;
    /* 1 if any item shown in *this* frame has an icon -- reserves a
     * left-hand icon column (see menu_icon_size()) for every item in the
     * frame, icon or not, so labels all still line up in one column
     * whether or not each individual item happens to have an icon. Set
     * once by measure_frame_width(), alongside f->width. A frame with no
     * icons at all keeps the old label-starts-at-10px layout untouched. */
    int has_icon;
} MenuFrame;

typedef struct {
    MenuItem items[MENU_TREE_MAX_ITEMS];
    int parent[MENU_TREE_MAX_ITEMS]; /* flat index of each item's parent, -1 = top level */
    int has_children[MENU_TREE_MAX_ITEMS]; /* already-populated children exist, or lazy[i] is still pending */
    int lazy[MENU_TREE_MAX_ITEMS]; /* 1 = children not fetched yet, fetch via on_lazy on first expand */
    int n_items;
    int item_h;
    double font_size; /* panel_text_size()-equivalent, resolved once at open time */

    MenuFrame frames[MENU_MAX_FRAMES];
    int n_frames;

    Panel *owner_panel;
    PanelWidget *owner_widget;
    void *ctx;
    MenuSelectFn on_select;
    MenuLazyFn on_lazy;
    MenuHoverRootFn on_hover_root;
    MenuCloseFn on_close;

    /* Pending submenu open: frames[pending_frame]'s position pending_pos
     * has been continuously hovered since pending_since_ms; opens once
     * owner_panel->tooltip_delay_ms elapses. 0 = nothing pending. */
    uint64_t pending_since_ms;
    int pending_frame, pending_pos;

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

int panel_menu_is_open(void)
{
    return g_menu != NULL;
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

/* Maps an on-screen row (0..visible_rows-1) to either an idx[]-position
 * (0..n-1) or one of the MENU_ROW_* sentinels above. When not paging,
 * row and position are the same number. */
static int frame_row_to_pos(const MenuFrame *f, int row)
{
    if (!f->paging) {
        return (row >= 0 && row < f->n) ? row : MENU_ROW_NONE;
    }
    if (row == 0) {
        return MENU_ROW_PREV;
    }
    if (row == f->visible_rows - 1) {
        return MENU_ROW_NEXT;
    }
    int pos = f->page * f->items_per_page + (row - 1);
    return (row - 1 < f->items_per_page && pos < f->n) ? pos : MENU_ROW_NONE;
}

/* Inverse of frame_row_to_pos() for a position known to be on the
 * *currently displayed* page (true right when it was just clicked/
 * hovered, which is the only time this is needed -- to position a freshly
 * opened submenu beside the row its parent item currently occupies). */
static int frame_pos_to_row(const MenuFrame *f, int pos)
{
    return f->paging ? (1 + pos - f->page * f->items_per_page) : pos;
}

static int menu_icon_size(const PanelMenu *m);
static int menu_icon_column_w(const PanelMenu *m);

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

    for (int row = 0; row < f->visible_rows; row++) {
        int y = row * m->item_h;
        int pos = frame_row_to_pos(f, row);

        if (pos == MENU_ROW_PREV || pos == MENU_ROW_NEXT) {
            int active = (pos == MENU_ROW_PREV) ? (f->page > 0) : (f->page < f->page_count - 1);
            if (row == f->hover_row && active) {
                cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.12);
                cairo_rectangle(cr, 0, y, f->width, m->item_h);
                cairo_fill(cr);
            }
            double cx = f->width / 2.0;
            double half = m->item_h / 2.0;
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, active ? 0.85 : 0.25);
            if (pos == MENU_ROW_PREV) {
                cairo_move_to(cr, cx - 5, y + half + 3);
                cairo_line_to(cr, cx + 5, y + half + 3);
                cairo_line_to(cr, cx, y + half - 4);
            } else {
                cairo_move_to(cr, cx - 5, y + half - 3);
                cairo_line_to(cr, cx + 5, y + half - 3);
                cairo_line_to(cr, cx, y + half + 4);
            }
            cairo_close_path(cr);
            cairo_fill(cr);
            continue;
        }
        if (pos == MENU_ROW_NONE) {
            continue;
        }

        int idx = f->idx[pos];
        MenuItem *it = &m->items[idx];
        if (it->is_separator) {
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.15);
            cairo_move_to(cr, 6, y + m->item_h / 2.0);
            cairo_line_to(cr, f->width - 6, y + m->item_h / 2.0);
            cairo_set_line_width(cr, 1);
            cairo_stroke(cr);
            continue;
        }
        if (row == f->hover_row && it->enabled) {
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.12);
            cairo_rectangle(cr, 0, y, f->width, m->item_h);
            cairo_fill(cr);
        }
        int text_x = 10;
        if (f->has_icon) {
            int icon_size = menu_icon_size(m);
            if (it->icon) {
                double icon_y = y + (m->item_h - icon_size) / 2.0;
                draw_icon_scaled(cr, it->icon, 10, icon_y, icon_size);
            }
            text_x = 10 + menu_icon_column_w(m);
        }
        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, it->enabled ? 0.95 : 0.4);
        pango_show_text_boxed(cr, text_x, y, m->item_h, 0, m->font_size, it->label, NULL);

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

/* Fills out_idx[]/out_n with the flat indices of every item whose parent
 * is `parent_idx` (top-level items when parent_idx is -1), in the order
 * they were inserted -- an eager subtree keeps its original DFS order;
 * lazily-fetched children (appended later, elsewhere in the array) come
 * back in their own fetch order too, since insertion order is preserved
 * regardless of *where* in the array a child physically landed. */
static void children_of(PanelMenu *m, int parent_idx, int *out_idx, int *out_n)
{
    int n = 0;
    for (int k = 0; k < m->n_items && n < MENU_TREE_MAX_ITEMS; k++) {
        if (m->parent[k] == parent_idx) {
            out_idx[n++] = k;
        }
    }
    *out_n = n;
}

/* Converts a depth[] array (DFS-order tree encoding, the shape callers
 * supply -- e.g. dbusmenu_fetch()'s out_depth) into explicit parent flat-
 * indices. Internally every lookup goes through parent[] (see children_
 * of()'s doc comment on why), so this conversion happens once, up front,
 * regardless of whether the tree came in eagerly or is empty and about
 * to be filled in lazily. */
static void depth_to_parent(const int *depth, int *parent, int n)
{
    int last_at_depth[MENU_PARENT_STACK_DEPTH];
    for (int i = 0; i < MENU_PARENT_STACK_DEPTH; i++) {
        last_at_depth[i] = -1;
    }
    for (int i = 0; i < n; i++) {
        int d = depth[i];
        parent[i] = (d > 0 && d - 1 < MENU_PARENT_STACK_DEPTH) ? last_at_depth[d - 1] : -1;
        if (d < MENU_PARENT_STACK_DEPTH) {
            last_at_depth[d] = i;
        }
    }
}

/* If `idx` is still marked lazy, calls on_lazy() once to fetch and append
 * its immediate children to the item pool, then clears the lazy flag (so
 * it's never re-fetched within this menu session, even if collapsed and
 * re-expanded) -- if it comes back empty, has_children[idx] is cleared
 * too so its arrow disappears. No-op if `idx` isn't lazy (already
 * resolved, or was never lazy to begin with). */
static void expand_lazy(PanelMenu *m, int idx)
{
    if (!m->lazy[idx]) {
        return;
    }
    m->lazy[idx] = 0;
    if (!m->on_lazy) {
        m->has_children[idx] = 0;
        return;
    }
    int room = MENU_TREE_MAX_ITEMS - m->n_items;
    if (room <= 0) {
        return; /* item pool is full -- leave has_children set, just can't fetch more */
    }
    MenuItem tmp_items[MENU_TREE_MAX_ITEMS];
    int tmp_lazy[MENU_TREE_MAX_ITEMS];
    int k = m->on_lazy(m->ctx, idx, tmp_items, tmp_lazy, room);
    if (k <= 0) {
        m->has_children[idx] = 0;
        return;
    }
    for (int i = 0; i < k && m->n_items < MENU_TREE_MAX_ITEMS; i++) {
        int ni = m->n_items++;
        m->items[ni] = tmp_items[i];
        m->parent[ni] = idx;
        m->lazy[ni] = tmp_lazy[i];
        m->has_children[ni] = tmp_lazy[i];
    }
}

/* Side length of an item's icon, plus the fixed 6px/left-margin gap it
 * sits in -- see paint_frame()'s icon draw and menu_icon_column_w()'s doc
 * comment for how this is used. Proportional to item_h like every other
 * menu glyph (the arrow, separators), not a fixed pixel size, so a
 * larger/smaller panel's menu rows scale the icon along with everything
 * else instead of it looking undersized/oversized at either extreme. */
static int menu_icon_size(const PanelMenu *m)
{
    int size = (int)(m->item_h * 0.6);
    return size > 8 ? size : 8;
}

/* Extra left-hand width to reserve when a frame has at least one item
 * with an icon: the icon column (menu_icon_size()) plus a 6px margin on
 * the far side of it before the label starts, on top of the existing 10px
 * left margin every label already had (see paint_frame()). */
static int menu_icon_column_w(const PanelMenu *m)
{
    return menu_icon_size(m) + 6;
}

static int measure_frame_width(PanelMenu *m, const int *idx, int n, int *out_has_icon)
{
    cairo_surface_t *probe_surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 1, 1);
    cairo_t *probe_cr = cairo_create(probe_surf);
    int max_w = 80;
    int any_children = 0;
    int any_icon = 0;
    for (int i = 0; i < n; i++) {
        int fi = idx[i];
        if (m->items[fi].is_separator) {
            continue;
        }
        if (m->has_children[fi]) {
            any_children = 1;
        }
        if (m->items[fi].icon) {
            any_icon = 1;
        }
        double tw;
        pango_text_extents_ellipsized(probe_cr, m->items[fi].label, m->font_size, 0, &tw, NULL);
        int w = (int)tw + 20;
        if (w > max_w) {
            max_w = w;
        }
    }
    cairo_destroy(probe_cr);
    cairo_surface_destroy(probe_surf);
    *out_has_icon = any_icon;
    int total = max_w;
    if (any_icon) {
        total += menu_icon_column_w(m);
    }
    return any_children ? total + MENU_ARROW_RESERVE : total;
}

/* Fills in f->width/height/paging/items_per_page/page_count/visible_rows
 * from f->idx[]/f->n (already set by the caller) and the output's own
 * height -- shared by the root frame's creation and every submenu
 * frame's, so paging behaves identically at every nesting level. Width is
 * measured across *every* page's worth of items, not just the first, so
 * the frame never resizes as you page through it. */
static void layout_frame(PanelMenu *m, MenuFrame *f)
{
    Panel *p = m->owner_panel;
    f->width = measure_frame_width(m, f->idx, f->n, &f->has_icon);

    int max_rows_fit = p->out_h / m->item_h;
    if (max_rows_fit < 1) {
        max_rows_fit = 1;
    }
    if (f->n <= max_rows_fit) {
        f->paging = 0;
        f->items_per_page = f->n;
        f->page = 0;
        f->page_count = 1;
        f->visible_rows = f->n;
    } else {
        f->paging = 1;
        f->items_per_page = max_rows_fit - 2 > 0 ? max_rows_fit - 2 : 1;
        f->page = 0;
        f->page_count = (f->n + f->items_per_page - 1) / f->items_per_page;
        f->visible_rows = f->items_per_page + 2;
    }
    f->height = f->visible_rows * m->item_h;
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

/* Opens the item at frames[parent_frame]'s idx[]-position parent_pos's
 * children as a new frame beside parent_frame, closing any previously-
 * open deeper frames first -- fetching them first via expand_lazy() if
 * they haven't been resolved yet. Returns 0 (no-op) if that item turns
 * out to have no children after all, or the cascade is already as deep
 * as MENU_MAX_FRAMES allows. */
static int open_submenu(PanelMenu *m, int parent_frame, int parent_pos)
{
    MenuFrame *pf = &m->frames[parent_frame];
    if (parent_pos < 0 || parent_pos >= pf->n) {
        return 0;
    }
    int parent_idx = pf->idx[parent_pos];
    expand_lazy(m, parent_idx);

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
    f->hover_row = -1;
    f->spawned_from_pos = parent_pos;
    layout_frame(m, f);

    Panel *p = m->owner_panel;
    int parent_row = frame_pos_to_row(pf, parent_pos);
    f->screen_x = pf->screen_x + pf->width;
    f->screen_y = pf->screen_y + parent_row * m->item_h;
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

/* Root coordinates -> (frame, row) currently under the pointer, or
 * frame=-1 if the point isn't inside any open frame at all. row is the
 * raw on-screen row (0..visible_rows-1); callers resolve it to an idx[]-
 * position or arrow sentinel via frame_row_to_pos() as needed -- kept
 * separate so hover highlighting (which needs the raw row, since arrow
 * rows aren't positions) and click/hover-open logic (which needs the
 * resolved position) can each use whichever shape they need. */
static void hit_test(PanelMenu *m, int root_x, int root_y, int *out_frame, int *out_row)
{
    for (int i = 0; i < m->n_frames; i++) {
        MenuFrame *f = &m->frames[i];
        if (root_x >= f->screen_x && root_x < f->screen_x + f->width && root_y >= f->screen_y &&
            root_y < f->screen_y + f->height) {
            int row = (root_y - f->screen_y) / m->item_h;
            *out_frame = i;
            *out_row = (row >= 0 && row < f->visible_rows) ? row : -1;
            return;
        }
    }
    *out_frame = -1;
    *out_row = -1;
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

    int frame, row;
    hit_test(m, root_x, root_y, &frame, &row);
    if (frame < 0) {
        /* Outside every open frame -- see this file's doc comment for why
         * that alone doesn't close the menu (only an explicit click does,
         * via handle_click()'s own frame<0 branch). Just stop any pending
         * submenu-open timer, since nothing is hovered right now. */
        m->pending_since_ms = 0;
        return;
    }

    MenuFrame *f = &m->frames[frame];
    if (f->hover_row != row) {
        f->hover_row = row;
        paint_frame(m, f);
    }

    int pos = row >= 0 ? frame_row_to_pos(f, row) : MENU_ROW_NONE;

    /* A deeper frame is open under this one -- collapse it away unless
     * we're still hovering exactly the position that spawned it. */
    if (frame + 1 < m->n_frames && (pos < 0 || m->frames[frame + 1].spawned_from_pos != pos)) {
        close_frames_from(frame + 1);
    }

    int has_open_child_here = frame + 1 < m->n_frames && pos >= 0 && m->frames[frame + 1].spawned_from_pos == pos;
    if (pos >= 0 && m->has_children[f->idx[pos]] && !has_open_child_here) {
        if (m->pending_frame != frame || m->pending_pos != pos) {
            m->pending_frame = frame;
            m->pending_pos = pos;
            m->pending_since_ms = now_ms();
        }
    } else {
        m->pending_since_ms = 0;
    }
}

/* Mouse wheel over a paging frame (folder's directory listings are the
 * common case, but any long enough menu pages) jumps a page in the
 * wheel's direction, from anywhere over that frame -- not just the two
 * arrow rows a click needs to land on, and deliberately NOT treated as a
 * click (X11 reports wheel motion as ButtonPress with button 4/5, so
 * without this it fell through to handle_click() and activated/opened
 * whatever item happened to be under the pointer, which only the actual
 * primary-button click should ever do). No-op if the frame under the
 * pointer isn't paging, or there's no next/previous page to move to. */
static void handle_scroll(int root_x, int root_y, int button)
{
    PanelMenu *m = g_menu;
    int frame, row;
    hit_test(m, root_x, root_y, &frame, &row);
    if (frame < 0) {
        return;
    }
    MenuFrame *f = &m->frames[frame];
    if (!f->paging) {
        return;
    }
    if (button == Button4) {
        if (f->page > 0) {
            f->page--;
            f->hover_row = -1;
            paint_frame(m, f);
        }
    } else if (button == Button5) {
        if (f->page < f->page_count - 1) {
            f->page++;
            f->hover_row = -1;
            paint_frame(m, f);
        }
    }
}

static void handle_click(int root_x, int root_y)
{
    PanelMenu *m = g_menu;
    int frame, row;
    hit_test(m, root_x, root_y, &frame, &row);
    if (frame < 0) {
        panel_menu_close();
        return;
    }
    MenuFrame *f = &m->frames[frame];
    int pos = row >= 0 ? frame_row_to_pos(f, row) : MENU_ROW_NONE;

    if (pos == MENU_ROW_PREV) {
        if (f->page > 0) {
            f->page--;
            f->hover_row = -1;
            paint_frame(m, f);
        }
        return;
    }
    if (pos == MENU_ROW_NEXT) {
        if (f->page < f->page_count - 1) {
            f->page++;
            f->hover_row = -1;
            paint_frame(m, f);
        }
        return;
    }
    if (pos < 0) {
        panel_menu_close();
        return;
    }
    int idx = f->idx[pos];
    if (m->items[idx].is_separator || !m->items[idx].enabled) {
        panel_menu_close();
        return;
    }
    if (m->has_children[idx]) {
        open_submenu(m, frame, pos);
        return; /* leaf selection happens on a later click, inside the new submenu */
    }
    select_and_close(idx);
}

/* Sets f->hover_row to the first non-separator item on its *currently
 * displayed* page, or leaves it at -1 if there isn't one -- used after
 * opening a submenu via the keyboard (Right/Enter) so Up/Down works
 * immediately in the new frame without an extra keypress to "arrive"
 * somewhere first, unlike a mouse-opened submenu which starts with
 * nothing hovered until the pointer actually moves over it. */
static void select_first_hover(MenuFrame *f)
{
    int start = f->paging ? f->page * f->items_per_page : 0;
    int end = f->paging ? start + f->items_per_page : f->n;
    if (end > f->n) {
        end = f->n;
    }
    for (int pos = start; pos < end; pos++) {
        if (!g_menu->items[f->idx[pos]].is_separator) {
            f->hover_row = frame_pos_to_row(f, pos);
            return;
        }
    }
    f->hover_row = -1;
}

/* Moves the deepest open frame's hover one selectable (non-separator)
 * item in `delta`'s direction (+1/-1), wrapping around and paging
 * automatically if needed -- the keyboard equivalent of handle_motion(),
 * but deliberately simpler: it never auto-opens a submenu after a delay
 * (that's mouse hover-intent behavior) or auto-collapses a deeper frame,
 * since by construction there's never a frame open under the deepest
 * one. Repaints the frame if the hovered row actually changed. */
static void move_hover(int delta)
{
    PanelMenu *m = g_menu;
    MenuFrame *f = &m->frames[m->n_frames - 1];
    if (f->n <= 0) {
        return;
    }
    int pos = f->hover_row >= 0 ? frame_row_to_pos(f, f->hover_row) : MENU_ROW_NONE;
    int p = (pos >= 0) ? pos : (delta > 0 ? -1 : f->n);
    for (int tries = 0; tries < f->n; tries++) {
        p += delta;
        if (p < 0) {
            p = f->n - 1;
        }
        if (p >= f->n) {
            p = 0;
        }
        if (!m->items[f->idx[p]].is_separator) {
            break;
        }
    }
    if (f->paging) {
        int target_page = p / f->items_per_page;
        if (target_page != f->page) {
            f->page = target_page;
        }
    }
    int row = frame_pos_to_row(f, p);
    if (row != f->hover_row) {
        f->hover_row = row;
        paint_frame(m, f);
    }
}

/* Opens the currently-hovered item's submenu (deepest frame) if it has
 * one -- the keyboard equivalent of hovering it with the mouse and
 * waiting out open_delay_ms, triggered immediately instead (Right/Enter
 * are explicit user intent, no need for hover-intent debouncing). */
static void open_hovered_submenu(void)
{
    PanelMenu *m = g_menu;
    MenuFrame *f = &m->frames[m->n_frames - 1];
    if (f->hover_row < 0) {
        return;
    }
    int pos = frame_row_to_pos(f, f->hover_row);
    if (pos < 0) {
        return;
    }
    int idx = f->idx[pos];
    if (m->items[idx].is_separator || !m->items[idx].enabled || !m->has_children[idx]) {
        return;
    }
    if (open_submenu(m, m->n_frames - 1, pos)) {
        select_first_hover(&m->frames[m->n_frames - 1]);
        paint_frame(m, &m->frames[m->n_frames - 1]);
    }
}

/* Closes just the deepest frame (Left key: "go back a level"), stepping
 * back to whichever item in the shallower frame spawned it -- a no-op at
 * the root frame (m->n_frames == 1), since Escape already covers "close
 * everything" and an unexpected full close on Left would surprise a
 * keyboard user just trying to step back one level. */
static void close_deepest_frame(void)
{
    PanelMenu *m = g_menu;
    if (m->n_frames <= 1) {
        return;
    }
    int spawned_from_pos = m->frames[m->n_frames - 1].spawned_from_pos;
    close_frames_from(m->n_frames - 1);
    MenuFrame *f = &m->frames[m->n_frames - 1];
    f->hover_row = frame_pos_to_row(f, spawned_from_pos);
    paint_frame(m, f);
}

void panel_menu_open_tree_lazy(Panel *owner_panel, PanelWidget *owner_widget, int anchor_x, int anchor_w,
                                const MenuItem *items, const int *depth, const int *lazy, int n_items, void *ctx,
                                MenuSelectFn on_select, MenuLazyFn on_lazy, MenuHoverRootFn on_hover_root,
                                MenuCloseFn on_close)
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
    memcpy(m->lazy, lazy, sizeof(int) * (size_t)n_items);
    m->n_items = n_items;
    depth_to_parent(depth, m->parent, n_items);
    for (int i = 0; i < n_items; i++) {
        m->has_children[i] = lazy[i] ? 1 : 0;
    }
    for (int i = 0; i < n_items; i++) {
        if (m->parent[i] >= 0) {
            m->has_children[m->parent[i]] = 1;
        }
    }
    m->owner_panel = owner_panel;
    m->owner_widget = owner_widget;
    m->ctx = ctx;
    m->on_select = on_select;
    m->on_lazy = on_lazy;
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
    children_of(m, -1, f0->idx, &f0->n);
    f0->hover_row = -1;
    f0->spawned_from_pos = -1;
    layout_frame(m, f0);

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

void panel_menu_open_tree(Panel *owner_panel, PanelWidget *owner_widget, int anchor_x, int anchor_w,
                           const MenuItem *items, const int *depth, int n_items, void *ctx, MenuSelectFn on_select,
                           MenuHoverRootFn on_hover_root, MenuCloseFn on_close)
{
    if (n_items <= 0 || n_items > MENU_TREE_MAX_ITEMS) {
        return;
    }
    int lazy[MENU_TREE_MAX_ITEMS];
    memset(lazy, 0, sizeof(int) * (size_t)n_items);
    panel_menu_open_tree_lazy(owner_panel, owner_widget, anchor_x, anchor_w, items, depth, lazy, n_items, ctx,
                               on_select, NULL, on_hover_root, on_close);
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
    if (m->pending_since_ms && now - m->pending_since_ms >= open_delay_ms(m)) {
        int pf = m->pending_frame, pp = m->pending_pos;
        m->pending_since_ms = 0;
        open_submenu(m, pf, pp);
    }
}

uint64_t panel_menu_next_wake_ms(void)
{
    if (!g_menu) {
        return 0;
    }
    PanelMenu *m = g_menu;
    uint64_t wake = 0;
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
        if (ev->xbutton.button == Button4 || ev->xbutton.button == Button5) {
            handle_scroll(ev->xbutton.x_root, ev->xbutton.y_root, (int)ev->xbutton.button);
        } else {
            handle_click(ev->xbutton.x_root, ev->xbutton.y_root);
        }
        return 1;
    }
    if (ev->type == KeyPress && ev->xkey.window == m->frames[0].win) {
        /* Full keyboard navigation of the cascade -- no mouse required.
         * Up/Down move the highlight within the deepest open frame;
         * Right/Enter open the hovered item's submenu (Enter also
         * activates a leaf item); Left steps back out of a submenu one
         * level; Escape closes the whole menu. This is what the
         * globalmenu widget's hotkey= option opens into. */
        KeySym ks = XLookupKeysym((XKeyEvent *)&ev->xkey, 0);
        if (ks == XK_Escape) {
            panel_menu_close();
        } else if (ks == XK_Down) {
            move_hover(1);
        } else if (ks == XK_Up) {
            move_hover(-1);
        } else if (ks == XK_Right) {
            open_hovered_submenu();
        } else if (ks == XK_Left) {
            close_deepest_frame();
        } else if (ks == XK_Return || ks == XK_KP_Enter) {
            MenuFrame *f = &m->frames[m->n_frames - 1];
            int pos = f->hover_row >= 0 ? frame_row_to_pos(f, f->hover_row) : MENU_ROW_NONE;
            if (pos >= 0) {
                int idx = f->idx[pos];
                if (!m->items[idx].is_separator && m->items[idx].enabled) {
                    if (m->has_children[idx]) {
                        open_hovered_submenu();
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
