/*
 * globalmenu widget - renders the active window's exported application
 * menu (File/Edit/View/... for Qt/KF5 apps that set it), using the same
 * mechanism a working reference script (krunner_appmenu.py, a KRunner
 * plugin) already relies on: Qt/KF5 apps set two X11 window properties
 * directly on their own top-level window --
 * _KDE_NET_WM_APPMENU_SERVICE_NAME (STRING, a DBus bus name) and
 * _KDE_NET_WM_APPMENU_OBJECT_PATH (STRING, a com.canonical.dbusmenu
 * object path). No registrar service (com.canonical.AppMenu.Registrar)
 * is needed at all just to *read* the menu -- that would only matter for
 * a host that also wants to be the thing apps register with, which
 * xispanel doesn't need to be here.
 *
 * Two display modes (`mode=open|closed`, default `closed`):
 *   - `open`: top-level menu names (File, Edit, ...) drawn directly in
 *     the widget, like a normal window's menu bar / macOS's global menu
 *     bar. Hovering one (or clicking it) opens *that item's* own subtree
 *     as a real cascading popup (menu.c's panel_menu_open_tree())
 *     anchored under the clicked label; once one top-level menu is open,
 *     moving the pointer over a *different* top-level label switches to
 *     that one without needing another click -- see globalmenu_hover_
 *     root() below, wired in via menu.c's MenuHoverRootFn.
 *   - `closed`: a single hamburger icon. Clicking it opens the *entire*
 *     menu tree as a cascade instead (same mechanism, just rooted at the
 *     whole tree rather than one top-level item).
 *
 * All the actual DBusMenu GetLayout/Event protocol work is shared with
 * the tray's Menu-property handling via dbusmenu.c -- this file is only
 * the EWMH property lookup, active-window tracking, and layout/paint.
 *
 * Three optional filters (all off by default, `same_desktop=yes`/
 * `same_output=yes`/`focused_only=yes`) let a multi-panel/multi-monitor
 * setup keep each panel's globalmenu limited to windows it actually
 * "owns" instead of every panel mirroring whatever's globally active --
 * see globalmenu_passes_filters().
 *
 * `hotkey=<spec>` (optional, see hotkey.c) opens the *entire* menu tree
 * as one cascade -- same action as clicking the hamburger icon in
 * `closed` mode, regardless of which mode is actually configured -- so a
 * keyboard user always has one reliable way to reach every item without
 * first having to tab/click into a specific top-level label. Once open,
 * menu.c's cascade already supports full keyboard navigation (arrow
 * keys, Enter, Escape) with no mouse involved at all.
 */
#include "../xispanel.h"

#include <X11/Xatom.h>
#include <X11/Xlib.h>

#include <stdio.h>
#include <string.h>

#define GLOBALMENU_MAX_TOP 16
#define GLOBALMENU_POLL_MS 300 /* active-window tracking cadence, same as winctl.c */
#define GLOBALMENU_ITEM_PAD 14 /* horizontal padding around each top-level label, both sides */
#define GLOBALMENU_ICON_PAD 8 /* padding around the hamburger icon, closed mode */

typedef struct {
    int open_mode; /* 1 = mode=open (inline bar), 0 = mode=closed (hamburger icon, default) */
    /* Off by default (same convention as tasklist's own same_desktop/
     * same_output), each config_kv=yes -- see globalmenu_passes_filters(). */
    int same_desktop_only;
    int same_output_only;
    int focused_only;

    Window tracked_win;
    char busname[128];
    char objpath[128];
    int has_menu;

    /* Top-level item labels/ids -- only fetched (dbusmenu_fetch depth=1)
     * when the tracked window or its busname/objpath actually changes,
     * not on every poll tick. Only meaningful in open_mode (closed mode
     * just needs has_menu to know whether the hamburger icon is active). */
    MenuItem top_items[GLOBALMENU_MAX_TOP];
    int top_ids[GLOBALMENU_MAX_TOP];
    int top_depth[GLOBALMENU_MAX_TOP]; /* always 0 (depth=1 fetch = only immediate children) -- dbusmenu_fetch requires the array anyway */
    int n_top;
    /* Which top_items[] slot's subtree is currently open via menu.c, or
     * -1 if none -- lets globalmenu_hover_root() tell "already open,
     * nothing to do" from "pointer moved to a different top-level label,
     * switch to it". Only meaningful in open_mode. */
    int open_top_index;

    /* Recomputed by globalmenu_layout() every paint/on_button call from
     * the widget's real allotted w->len -- same "never disagree" pattern
     * tasklist/tray/winctl all use for their own hit-testing. */
    int btn_x[GLOBALMENU_MAX_TOP];
    int btn_w[GLOBALMENU_MAX_TOP];

    /* Whatever subtree is currently open in menu.c (either one top-level
     * item's own descendants in open_mode, or -- closed mode -- the
     * entire tree): menu_items[]/menu_depth[] are handed to
     * panel_menu_open_tree() (which copies them internally, so this
     * buffer only needs to stay valid for that one call), menu_ids[] is
     * kept around so globalmenu_select() can map a clicked flat index
     * back to a DBusMenu item id -- menu.c only keeps the MenuItem
     * labels/depths, not these ids. Sized for a whole-tree fetch
     * (closed mode), not just one level. */
    MenuItem menu_items[MENU_TREE_MAX_ITEMS];
    int menu_ids[MENU_TREE_MAX_ITEMS];
    int menu_depth[MENU_TREE_MAX_ITEMS];
    int n_menu;
} GlobalmenuPriv;

static Atom g_atom_appmenu_service = None;
static Atom g_atom_appmenu_path = None;

static void ensure_atoms(void)
{
    if (g_atom_appmenu_service == None) {
        g_atom_appmenu_service = XInternAtom(g_dpy, "_KDE_NET_WM_APPMENU_SERVICE_NAME", False);
        g_atom_appmenu_path = XInternAtom(g_dpy, "_KDE_NET_WM_APPMENU_OBJECT_PATH", False);
    }
}

/* Both properties are plain STRING (not UTF8_STRING) -- confirmed against
 * the reference script (Xlib.Xatom.STRING) and real Qt/KF5 apps, which
 * only ever put ASCII bus names/object paths in them anyway. */
static void read_string_prop(Window w, Atom atom, char *buf, size_t bufsz)
{
    buf[0] = 0;
    Atom actual_type;
    int actual_format;
    unsigned long n_items, bytes_after;
    unsigned char *prop = NULL;
    if (XGetWindowProperty(g_dpy, w, atom, 0, 1024, False, XA_STRING, &actual_type, &actual_format, &n_items,
                            &bytes_after, &prop) == Success &&
        prop) {
        if (actual_type == XA_STRING && n_items > 0) {
            size_t len = n_items < bufsz - 1 ? n_items : bufsz - 1;
            memcpy(buf, prop, len);
            buf[len] = 0;
        }
        XFree(prop);
    }
}

static void globalmenu_open_menu(PanelWidget *w, int parent_id, int anchor_x, int anchor_w);

/* hotkey= callback -- see the file comment. Opens the whole tree
 * (parent_id=0, the same call `closed` mode's hamburger click makes)
 * regardless of open_mode, so it doesn't matter which top-level label
 * (if any) the keyboard user "meant". A no-op if the tracked window
 * currently has no exported menu at all. */
static void globalmenu_hotkey_open(PanelWidget *w)
{
    GlobalmenuPriv *gp = w->priv;
    if (!gp->has_menu) {
        return;
    }
    globalmenu_open_menu(w, 0, 0, w->len);
}

static int globalmenu_init(PanelWidget *w)
{
    GlobalmenuPriv *gp = w->priv;
    char buf[16];
    gp->open_mode = kv_get(w->config_kv, "mode", buf, sizeof(buf)) && !strcmp(buf, "open");
    gp->same_desktop_only = kv_get(w->config_kv, "same_desktop", buf, sizeof(buf)) && !strcmp(buf, "yes");
    gp->same_output_only = kv_get(w->config_kv, "same_output", buf, sizeof(buf)) && !strcmp(buf, "yes");
    gp->focused_only = kv_get(w->config_kv, "focused_only", buf, sizeof(buf)) && !strcmp(buf, "yes");
    gp->tracked_win = None;
    gp->open_top_index = -1;
    w->next_tick_ms = now_ms();
    char hotkey[64];
    if (kv_get(w->config_kv, "hotkey", hotkey, sizeof(hotkey)) && hotkey[0]) {
        hotkey_register(w, hotkey, globalmenu_hotkey_open);
    }
    return 0;
}

static void globalmenu_destroy(PanelWidget *w)
{
    hotkey_unregister_widget(w);
}

/* 1 if `active` passes every filter this widget instance has turned on --
 * see the GlobalmenuPriv fields' doc comment. `active == None` always
 * fails (nothing to show a menu for). Mirrors tasklist.c's own same_
 * desktop/same_output filtering (ewmh_get_current_desktop()/ewmh_window_
 * in_rect()), plus a globalmenu-specific focused_only check: _NET_ACTIVE_
 * WINDOW can lag behind real X focus (e.g. some WMs leave it pointing at
 * the last client after focus moves to the root window/desktop), so
 * focused_only cross-checks against XGetInputFocus() via ewmh_window_
 * has_input_focus() instead of trusting the EWMH hint alone. */
static int globalmenu_passes_filters(PanelWidget *w, Window active)
{
    GlobalmenuPriv *gp = w->priv;
    if (active == None) {
        return 0;
    }
    if (gp->same_desktop_only) {
        int current_desktop = ewmh_get_current_desktop();
        int desktop = ewmh_get_desktop(active);
        if (current_desktop >= 0 && desktop >= 0 && desktop != current_desktop) {
            return 0;
        }
    }
    if (gp->same_output_only &&
        !ewmh_window_in_rect(active, w->panel->out_x, w->panel->out_y, w->panel->out_w, w->panel->out_h)) {
        return 0;
    }
    if (gp->focused_only && !ewmh_window_has_input_focus(active)) {
        return 0;
    }
    return 1;
}

static void globalmenu_refetch_top(GlobalmenuPriv *gp)
{
    gp->n_top = 0;
    if (!gp->open_mode || !gp->has_menu) {
        return;
    }
    int n = dbusmenu_fetch(gp->busname, gp->objpath, 0, 1, gp->top_items, gp->top_ids, gp->top_depth,
                            GLOBALMENU_MAX_TOP);
    gp->n_top = n > 0 ? n : 0;
}

static int globalmenu_on_tick(PanelWidget *w, uint64_t now)
{
    GlobalmenuPriv *gp = w->priv;
    w->next_tick_ms = now + GLOBALMENU_POLL_MS;
    ensure_atoms();

    Window active = ewmh_get_active_window();
    /* Recomputed every tick, not just when `active` itself changes: a
     * filter's verdict can flip (desktop switch, window dragged to
     * another output, focus moving to the root window) without _NET_
     * ACTIVE_WINDOW changing at all. */
    Window effective = globalmenu_passes_filters(w, active) ? active : None;
    if (effective == gp->tracked_win) {
        return 0;
    }
    gp->tracked_win = effective;

    char busname[128] = "", objpath[128] = "";
    if (effective != None && !ewmh_skip_taskbar(effective)) {
        read_string_prop(effective, g_atom_appmenu_service, busname, sizeof(busname));
        read_string_prop(effective, g_atom_appmenu_path, objpath, sizeof(objpath));
    }
    int had_menu = gp->has_menu;
    int changed = 0;
    gp->has_menu = busname[0] && objpath[0];
    if (gp->has_menu && (strcmp(gp->busname, busname) || strcmp(gp->objpath, objpath))) {
        snprintf(gp->busname, sizeof(gp->busname), "%s", busname);
        snprintf(gp->objpath, sizeof(gp->objpath), "%s", objpath);
        globalmenu_refetch_top(gp); /* open-mode top-level labels changed */
        changed = 1;
    } else if (!gp->has_menu) {
        gp->busname[0] = 0;
        gp->objpath[0] = 0;
        gp->n_top = 0;
    }
    /* has_menu flipping changes measure() (0 vs a real width), so the
     * whole panel needs re-laying-out+repainting either way. */
    if (had_menu != gp->has_menu) {
        changed = 1;
    }
    return changed;
}

/* Recomputes each top-level button's hit-rect from the widget's real
 * allotted w->len -- see the GlobalmenuPriv comment. Closed mode has
 * nothing to lay out (the whole widget is the hamburger icon). */
static void globalmenu_layout(PanelWidget *w)
{
    GlobalmenuPriv *gp = w->priv;
    if (!gp->open_mode) {
        return;
    }
    Panel *p = w->panel;
    int x = 0;
    for (int i = 0; i < gp->n_top; i++) {
        double tw;
        pango_text_extents_ellipsized(p->cr, gp->top_items[i].label, panel_text_size(p), 0, &tw, NULL);
        int bw = (int)tw + GLOBALMENU_ITEM_PAD * 2;
        gp->btn_x[i] = x;
        gp->btn_w[i] = bw;
        x += bw;
    }
}

static void globalmenu_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    (void)cross_axis;
    GlobalmenuPriv *gp = w->priv;
    if (!gp->has_menu) {
        *out_len = 0;
        *out_min_len = 0;
        return;
    }
    if (!gp->open_mode) {
        *out_len = w->thickness;
        *out_min_len = *out_len;
        return;
    }
    globalmenu_layout(w);
    int len = gp->n_top > 0 ? gp->btn_x[gp->n_top - 1] + gp->btn_w[gp->n_top - 1] : 0;
    *out_len = len;
    *out_min_len = len;
}

static void globalmenu_paint(PanelWidget *w, cairo_t *cr)
{
    GlobalmenuPriv *gp = w->priv;
    if (!gp->has_menu) {
        return;
    }
    int ox, oy, owidth, oheight;
    widget_get_rect(w, &ox, &oy, &owidth, &oheight);

    Panel *p = w->panel;
    if (!gp->open_mode) {
        /* Hamburger icon: three horizontal bars, same visual weight as
         * tray's fallback icon glyphs. */
        int s = w->thickness - GLOBALMENU_ICON_PAD * 2;
        if (s < 6) {
            s = 6;
        }
        int cx = ox + owidth / 2;
        int cy = oy + oheight / 2;
        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.9);
        cairo_set_line_width(cr, 1.6);
        for (int i = -1; i <= 1; i++) {
            double y = cy + i * (s / 3.0);
            cairo_move_to(cr, cx - s / 2.0, y);
            cairo_line_to(cr, cx + s / 2.0, y);
            cairo_stroke(cr);
        }
        return;
    }

    globalmenu_layout(w);
    cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.95);
    for (int i = 0; i < gp->n_top; i++) {
        if (i == gp->open_top_index) {
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.12);
            cairo_rectangle(cr, ox + gp->btn_x[i], oy, gp->btn_w[i], oheight);
            cairo_fill(cr);
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.95);
        }
        double tw;
        pango_text_extents_ellipsized(cr, gp->top_items[i].label, panel_text_size(p), 0, &tw, NULL);
        double tx = ox + gp->btn_x[i] + (gp->btn_w[i] - tw) / 2.0;
        pango_show_text_boxed(cr, tx, oy, oheight, 0, panel_text_size(p), gp->top_items[i].label, NULL);
    }
}

static void globalmenu_select(Panel *panel, PanelWidget *widget, void *ctx, int index)
{
    (void)panel;
    (void)ctx;
    GlobalmenuPriv *gp = widget->priv;
    if (index < 0 || index >= gp->n_menu) {
        return;
    }
    dbusmenu_send_event(gp->busname, gp->objpath, gp->menu_ids[index]);
}

/* Called on every pointer motion while a menu opened from this widget (or
 * one of its own submenu frames) is on screen -- see MenuHoverRootFn's
 * doc comment in xispanel.h. Only acts in open_mode: if the pointer is
 * over a *different* top-level label than whichever one is currently
 * open, switches the whole cascade to that label's subtree instead,
 * without requiring a click -- the "moving the mouse across a menu bar
 * changes which menu is shown" behavior every desktop menu bar has. */
static void globalmenu_open_for_top(PanelWidget *w, int top_idx);

static void globalmenu_hover_root(void *ctx, int root_x, int root_y)
{
    PanelWidget *w = ctx;
    GlobalmenuPriv *gp = w->priv;
    if (!gp->open_mode || gp->n_top <= 0) {
        return;
    }
    Panel *p = w->panel;
    int local_main;
    if (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM) {
        if (root_y < p->y || root_y >= p->y + p->thickness) {
            return;
        }
        local_main = root_x - (p->x + w->x);
    } else {
        if (root_x < p->x || root_x >= p->x + p->thickness) {
            return;
        }
        local_main = root_y - (p->y + w->x);
    }
    if (local_main < 0 || local_main >= w->len) {
        return;
    }
    int idx = -1;
    for (int i = 0; i < gp->n_top; i++) {
        if (local_main >= gp->btn_x[i] && local_main < gp->btn_x[i] + gp->btn_w[i]) {
            idx = i;
            break;
        }
    }
    if (idx < 0 || idx == gp->open_top_index) {
        return;
    }
    globalmenu_open_for_top(w, idx);
}

/* Fetches parent_id's own subtree and opens it as a cascade anchored at
 * [anchor_x, anchor_x+anchor_w) -- shared by the click handler (both
 * modes) and globalmenu_hover_root()'s top-level switching (open_mode
 * only, so on_hover_root is only wired up there). */
static void globalmenu_on_close(void *ctx)
{
    PanelWidget *w = ctx;
    GlobalmenuPriv *gp = w->priv;
    gp->open_top_index = -1;
    w->panel->dirty = 1;
}

static void globalmenu_open_menu(PanelWidget *w, int parent_id, int anchor_x, int anchor_w)
{
    GlobalmenuPriv *gp = w->priv;
    int n = dbusmenu_fetch(gp->busname, gp->objpath, parent_id, -1, gp->menu_items, gp->menu_ids, gp->menu_depth,
                            MENU_TREE_MAX_ITEMS);
    if (n <= 0) {
        return;
    }
    gp->n_menu = n;
    panel_menu_open_tree(w->panel, w, anchor_x, anchor_w, gp->menu_items, gp->menu_depth, gp->n_menu, w,
                          globalmenu_select, gp->open_mode ? globalmenu_hover_root : NULL, globalmenu_on_close);
}

static void globalmenu_open_for_top(PanelWidget *w, int top_idx)
{
    GlobalmenuPriv *gp = w->priv;
    gp->open_top_index = top_idx;
    w->panel->dirty = 1;
    globalmenu_open_menu(w, gp->top_ids[top_idx], gp->btn_x[top_idx], gp->btn_w[top_idx]);
}

static int globalmenu_on_button(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y)
{
    (void)local_y;
    (void)root_x;
    (void)root_y;
    GlobalmenuPriv *gp = w->priv;
    if (button != Button1 || !gp->has_menu) {
        return 0;
    }

    if (!gp->open_mode) {
        /* Closed/hamburger: the entire tree as one cascade, rooted at 0. */
        globalmenu_open_menu(w, 0, 0, w->len);
        return 1;
    }

    globalmenu_layout(w);
    int idx = -1;
    for (int i = 0; i < gp->n_top; i++) {
        if (local_x >= gp->btn_x[i] && local_x < gp->btn_x[i] + gp->btn_w[i]) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        return 0;
    }
    globalmenu_open_for_top(w, idx);
    return 1;
}

const PanelWidgetOps globalmenu_ops = {
    .type_name = "globalmenu",
    .priv_size = sizeof(GlobalmenuPriv),
    .init = globalmenu_init,
    .destroy = globalmenu_destroy,
    .measure = globalmenu_measure,
    .paint = globalmenu_paint,
    .on_button = globalmenu_on_button,
    .on_tick = globalmenu_on_tick,
};
