/*
 * tasklist widget - one button per top-level window from
 * _NET_CLIENT_LIST, refreshed by polling every ~800ms (on_tick) --
 * simple and reliably correct, and at this rate cheap enough that
 * reacting to PropertyNotify instead wouldn't be a meaningful resource
 * win, just more plumbing.
 *
 * "wide" mode draws icon+title (Windows XP style); "compact" draws icon
 * only (Windows 7 style). Both share the same btn_x/btn_w geometry array,
 * computed once per measure() (called from panel_layout() right before
 * every repaint) and reused by paint() and on_button() so hit-testing and
 * drawing can never disagree about where a button actually is.
 *
 * Right-click opens a per-window context menu (minimize/maximize/move/
 * close/pin) via the generic panel_menu_open(). "Pin" is currently a
 * visual-only toggle for the running session: a pinned entry does *not*
 * yet survive its window closing and relaunch on click, since that needs
 * .desktop-file lookup by WM_CLASS -- a later (launcher) phase. What it
 * does today is exist as working context-menu-item infrastructure that
 * the launcher phase can build real pinning on top of.
 */
#include "../xispanel.h"

#include <X11/Xlib.h>

#include <stdio.h>
#include <string.h>

#define MAX_TASKS 64
#define TASKLIST_BTN_GAP 3
#define TASKLIST_WIDE_MAXW 180
#define TASKLIST_ARROW_W 14
#define TASKLIST_ARROW_GAP 4

typedef struct {
    Window win;
    char title[128];
    char wm_class[64];
    int desktop;
    int minimized;
    int maximized;
    int pinned;
    cairo_surface_t *icon;
} TaskEntry;

typedef struct {
    int compact; /* 0 = wide (icon+label), 1 = compact (icon only) */
    TaskEntry tasks[MAX_TASKS];
    int n_tasks;
    int n_desktops;
    int btn_w[MAX_TASKS]; /* natural (unclipped) width of each task's button */

    /* Visible window into `tasks`, recomputed by tasklist_layout_visible()
     * from the widget's *actual* allotted w->len (which panel_layout() may
     * have shrunk below the natural total width computed above) every
     * paint/on_button call -- cheap enough not to bother caching across
     * calls, and guarantees paint() and on_button() can never disagree
     * about where a button is. */
    int scroll_offset; /* index into tasks[] of the first visible button */
    int vis_idx[MAX_TASKS]; /* tasks[] index for each visible slot */
    int vis_x[MAX_TASKS];
    int vis_w[MAX_TASKS];
    int n_visible;
    int scrollable; /* 1 if not everything fits and the arrow pair is shown */
    int arrow_x; /* local x of the up/down arrow pair, valid iff scrollable */
} TasklistPriv;

static int tasklist_find(TasklistPriv *tp, Window win)
{
    for (int i = 0; i < tp->n_tasks; i++) {
        if (tp->tasks[i].win == win) {
            return i;
        }
    }
    return -1;
}

static int tasklist_init(PanelWidget *w)
{
    TasklistPriv *tp = w->priv;
    char buf[16];
    tp->compact = kv_get(w->config_kv, "mode", buf, sizeof(buf)) && strcmp(buf, "compact") == 0;
    tp->n_desktops = 1;
    w->next_tick_ms = now_ms();
    return 0;
}

static void tasklist_destroy(PanelWidget *w)
{
    TasklistPriv *tp = w->priv;
    for (int i = 0; i < tp->n_tasks; i++) {
        if (tp->tasks[i].icon) {
            cairo_surface_destroy(tp->tasks[i].icon);
        }
    }
}

static void tasklist_on_tick(PanelWidget *w, uint64_t now)
{
    TasklistPriv *tp = w->priv;
    w->next_tick_ms = now + 800;

    Window *list = NULL;
    int n = 0;
    if (!ewmh_get_client_list(&list, &n)) {
        return;
    }
    if (n > MAX_TASKS) {
        n = MAX_TASKS;
    }

    TaskEntry fresh[MAX_TASKS];
    int n_fresh = 0;
    int icon_px = w->thickness > 8 ? w->thickness - 8 : 16;
    for (int i = 0; i < n; i++) {
        Window win = list[i];
        if (ewmh_skip_taskbar(win)) {
            continue;
        }
        int old_idx = tasklist_find(tp, win);
        TaskEntry *e = &fresh[n_fresh++];
        memset(e, 0, sizeof(*e));
        e->win = win;
        ewmh_get_title(win, e->title, sizeof(e->title));
        ewmh_get_class(win, e->wm_class, sizeof(e->wm_class));
        e->desktop = ewmh_get_desktop(win);
        ewmh_get_state_flags(win, &e->minimized, &e->maximized);
        if (old_idx >= 0) {
            e->pinned = tp->tasks[old_idx].pinned;
            e->icon = tp->tasks[old_idx].icon; /* ownership moves to `fresh` */
            tp->tasks[old_idx].icon = NULL;
        } else {
            e->icon = ewmh_get_icon_surface(win, icon_px);
        }
    }
    XFree(list);

    /* Anything still owning an icon surface here belonged to a window
     * that's gone from _NET_CLIENT_LIST now -- free it. */
    for (int i = 0; i < tp->n_tasks; i++) {
        if (tp->tasks[i].icon) {
            cairo_surface_destroy(tp->tasks[i].icon);
        }
    }
    memcpy(tp->tasks, fresh, sizeof(TaskEntry) * (size_t)n_fresh);
    tp->n_tasks = n_fresh;
    tp->n_desktops = ewmh_get_number_of_desktops();
}

static void tasklist_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    TasklistPriv *tp = w->priv;
    Panel *p = w->panel;
    int icon_px = cross_axis > 8 ? cross_axis - 8 : 16;
    int cursor = 0;
    for (int i = 0; i < tp->n_tasks; i++) {
        int bw;
        if (tp->compact) {
            bw = icon_px + 8;
        } else {
            cairo_text_extents_t ext;
            cairo_text_extents(p->cr, tp->tasks[i].title, &ext);
            bw = icon_px + 8 + (int)ext.x_advance + 8;
            if (bw > TASKLIST_WIDE_MAXW) {
                bw = TASKLIST_WIDE_MAXW;
            }
        }
        tp->btn_w[i] = bw;
        cursor += bw + TASKLIST_BTN_GAP;
    }
    *out_len = tp->n_tasks > 0 ? cursor - TASKLIST_BTN_GAP : 0;

    /* Minimum: room for exactly one task button (compact-sized, since that's
     * the smallest a button can usefully be) plus the up/down arrow pair
     * that tasklist_layout_visible() reserves once scrolling kicks in. */
    *out_min_len = tp->n_tasks > 0 ? (icon_px + 8 + TASKLIST_ARROW_W + TASKLIST_ARROW_GAP) : 0;
}

/* Recomputes which tasks are visible (tp->vis_*) from the widget's actual
 * allotted w->len, which may be less than the natural width tasklist_measure()
 * reported if panel_layout() had to shrink it to fit the panel. Called at
 * the top of both paint() and on_button() so hit-testing and drawing can
 * never disagree about where a button (or the scroll arrows) actually is. */
static void tasklist_layout_visible(PanelWidget *w)
{
    TasklistPriv *tp = w->priv;

    int natural_total = 0;
    for (int i = 0; i < tp->n_tasks; i++) {
        natural_total += tp->btn_w[i] + (i > 0 ? TASKLIST_BTN_GAP : 0);
    }

    tp->scrollable = natural_total > w->len;
    int content_avail = tp->scrollable ? w->len - TASKLIST_ARROW_W - TASKLIST_ARROW_GAP : w->len;
    if (content_avail < 0) {
        content_avail = 0;
    }

    if (tp->scroll_offset >= tp->n_tasks) {
        tp->scroll_offset = tp->n_tasks > 0 ? tp->n_tasks - 1 : 0;
    }
    if (tp->scroll_offset < 0) {
        tp->scroll_offset = 0;
    }

    int cursor = 0;
    tp->n_visible = 0;
    for (int i = tp->scroll_offset; i < tp->n_tasks && tp->n_visible < MAX_TASKS; i++) {
        int bw = tp->btn_w[i];
        int gap = tp->n_visible > 0 ? TASKLIST_BTN_GAP : 0;
        if (tp->n_visible > 0 && cursor + gap + bw > content_avail) {
            break;
        }
        if (tp->n_visible == 0 && bw > content_avail) {
            bw = content_avail; /* clip the single button that still fits */
        }
        cursor += gap;
        tp->vis_idx[tp->n_visible] = i;
        tp->vis_x[tp->n_visible] = cursor;
        tp->vis_w[tp->n_visible] = bw;
        cursor += bw;
        tp->n_visible++;
    }

    tp->arrow_x = tp->scrollable ? w->len - TASKLIST_ARROW_W : -1;
}

/* Full (untruncated) title of whatever task button is under local_x, with
 * the anchor set to that specific button's span -- not the whole widget --
 * so the tooltip lines up with the actual task, same as on_button()'s
 * hit-testing. No tooltip over the scroll arrows. */
static int tasklist_get_tooltip(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w)
{
    TasklistPriv *tp = w->priv;
    tasklist_layout_visible(w);

    if (tp->scrollable && local_x >= tp->arrow_x) {
        return 0;
    }
    for (int vi = 0; vi < tp->n_visible; vi++) {
        if (local_x >= tp->vis_x[vi] && local_x < tp->vis_x[vi] + tp->vis_w[vi]) {
            TaskEntry *e = &tp->tasks[tp->vis_idx[vi]];
            snprintf(buf, bufsz, "%s", e->title);
            *anchor_x = tp->vis_x[vi];
            *anchor_w = tp->vis_w[vi];
            return 1;
        }
    }
    return 0;
}

static void tasklist_paint(PanelWidget *w, cairo_t *cr)
{
    TasklistPriv *tp = w->priv;
    Panel *p = w->panel;
    int ox, oy, owidth, oheight;
    widget_get_rect(w, &ox, &oy, &owidth, &oheight);
    (void)owidth;
    (void)oheight;

    tasklist_layout_visible(w);

    Window active = ewmh_get_active_window();
    int icon_px = w->thickness > 8 ? w->thickness - 8 : 16;
    int icon_y = oy + (w->thickness - icon_px) / 2;

    for (int vi = 0; vi < tp->n_visible; vi++) {
        TaskEntry *e = &tp->tasks[tp->vis_idx[vi]];
        int bx = ox + tp->vis_x[vi];
        int bw = tp->vis_w[vi];

        if (e->win == active) {
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.18);
            cairo_rectangle(cr, bx, oy, bw, w->thickness);
            cairo_fill(cr);
        }

        cairo_push_group(cr);
        if (e->icon) {
            draw_icon_scaled(cr, e->icon, bx + 4, icon_y, icon_px);
        } else {
            draw_fallback_icon(cr, bx + 4, icon_y, icon_px, e->title, p->fg_r, p->fg_g, p->fg_b);
        }
        if (!tp->compact) {
            char label[96];
            snprintf(label, sizeof(label), "%s", e->title);
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.95);
            trim_to_width(cr, label, sizeof(label), bw - icon_px - 16);
            cairo_text_extents_t ext;
            cairo_text_extents(cr, label, &ext);
            cairo_move_to(cr, bx + icon_px + 10, oy + (w->thickness - ext.height) / 2.0 - ext.y_bearing);
            cairo_show_text(cr, label);
        }
        if (e->pinned) {
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.9);
            cairo_arc(cr, bx + icon_px + 2, icon_y + 2, 2.5, 0, 2 * 3.14159265);
            cairo_fill(cr);
        }
        if (tp->n_desktops > 1 && e->desktop >= 0) {
            char badge[16];
            snprintf(badge, sizeof(badge), "%d", e->desktop + 1);
            double badge_fs = w->thickness * 0.28;
            cairo_set_font_size(cr, badge_fs);
            cairo_text_extents_t bext;
            cairo_text_extents(cr, badge, &bext);
            double bx2 = bx + icon_px + 4 - bext.width;
            double by2 = icon_y + icon_px;
            cairo_set_source_rgba(cr, 0, 0, 0, 0.55);
            cairo_rectangle(cr, bx2 - 2, by2 - bext.height - 1, bext.width + 4, bext.height + 3);
            cairo_fill(cr);
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.95);
            cairo_move_to(cr, bx2, by2);
            cairo_show_text(cr, badge);
            cairo_set_font_size(cr, w->thickness * 0.45);
        }
        cairo_pop_group_to_source(cr);
        cairo_paint_with_alpha(cr, e->minimized ? 0.55 : 1.0);
    }

    if (tp->scrollable) {
        int ax = ox + tp->arrow_x;
        int half = w->thickness / 2;
        int can_up = tp->scroll_offset > 0;
        int can_down = tp->vis_idx[tp->n_visible - 1] < tp->n_tasks - 1;
        double cx = ax + TASKLIST_ARROW_W / 2.0;

        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, can_up ? 0.85 : 0.25);
        cairo_move_to(cr, cx - 4, oy + half - 3);
        cairo_line_to(cr, cx + 4, oy + half - 3);
        cairo_line_to(cr, cx, oy + 2);
        cairo_close_path(cr);
        cairo_fill(cr);

        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, can_down ? 0.85 : 0.25);
        cairo_move_to(cr, cx - 4, oy + half + 3);
        cairo_line_to(cr, cx + 4, oy + half + 3);
        cairo_line_to(cr, cx, oy + w->thickness - 2);
        cairo_close_path(cr);
        cairo_fill(cr);
    }
}

/* Context menu item order: 0=minimize/restore, 1=maximize/restore,
 * 2=move, 3=close, [separator], 5=pin/unpin. ctx is the clicked window's
 * XID, packed directly into the void* (Window fits in a pointer-sized
 * integer on every platform this targets -- no heap allocation needed for
 * something this small and short-lived). */
static void tasklist_menu_select(Panel *panel, PanelWidget *w, void *ctx, int index)
{
    (void)panel;
    Window win = (Window)(uintptr_t)ctx;
    TasklistPriv *tp = w->priv;
    int idx = tasklist_find(tp, win);

    switch (index) {
    case 0:
        if (idx >= 0) {
            ewmh_toggle_minimize(win, tp->tasks[idx].minimized);
        }
        break;
    case 1:
        ewmh_toggle_maximize(win);
        break;
    case 2: {
        Window root_ret, child_ret;
        int rx, ry, wx, wy;
        unsigned mask;
        XQueryPointer(g_dpy, g_root, &root_ret, &child_ret, &rx, &ry, &wx, &wy, &mask);
        ewmh_move_interactive(win, rx, ry);
        break;
    }
    case 3:
        ewmh_close(win);
        break;
    case 5:
        if (idx >= 0) {
            tp->tasks[idx].pinned = !tp->tasks[idx].pinned;
        }
        break;
    default:
        break;
    }
    XFlush(g_dpy);
    w->panel->dirty = 1;
}

static int tasklist_on_button(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y)
{
    (void)root_x;
    (void)root_y;
    TasklistPriv *tp = w->priv;
    tasklist_layout_visible(w);

    if (tp->scrollable && local_x >= tp->arrow_x && button == Button1) {
        if (local_y < w->thickness / 2) {
            if (tp->scroll_offset > 0) {
                tp->scroll_offset--;
            }
        } else {
            if (tp->n_visible > 0 && tp->vis_idx[tp->n_visible - 1] < tp->n_tasks - 1) {
                tp->scroll_offset++;
            }
        }
        w->panel->dirty = 1;
        return 1;
    }

    int idx = -1;
    int anchor_x = 0, anchor_w = w->len;
    for (int vi = 0; vi < tp->n_visible; vi++) {
        if (local_x >= tp->vis_x[vi] && local_x < tp->vis_x[vi] + tp->vis_w[vi]) {
            idx = tp->vis_idx[vi];
            anchor_x = tp->vis_x[vi];
            anchor_w = tp->vis_w[vi];
            break;
        }
    }
    if (idx < 0) {
        return 0;
    }
    TaskEntry *e = &tp->tasks[idx];

    if (button == Button1) {
        Window active = ewmh_get_active_window();
        if (e->win == active && !e->minimized) {
            /* Click on the already-active window's button minimizes it,
             * same convention as the Windows taskbar -- click again to
             * restore. */
            ewmh_toggle_minimize(e->win, 0);
        } else {
            if (e->minimized) {
                ewmh_toggle_minimize(e->win, 1);
            }
            ewmh_activate(e->win);
        }
        XFlush(g_dpy);
        w->panel->dirty = 1;
        return 1;
    }

    if (button == Button3) {
        MenuItem items[6];
        int n = 0;
        snprintf(items[n].label, sizeof(items[n].label), "%s", e->minimized ? "Restaurar" : "Minimizar");
        items[n].enabled = 1;
        items[n].is_separator = 0;
        n++;
        snprintf(items[n].label, sizeof(items[n].label), "%s", e->maximized ? "Restaurar tamanho" : "Maximizar");
        items[n].enabled = 1;
        items[n].is_separator = 0;
        n++;
        snprintf(items[n].label, sizeof(items[n].label), "Mover");
        items[n].enabled = 1;
        items[n].is_separator = 0;
        n++;
        snprintf(items[n].label, sizeof(items[n].label), "Fechar");
        items[n].enabled = 1;
        items[n].is_separator = 0;
        n++;
        items[n].label[0] = 0;
        items[n].enabled = 0;
        items[n].is_separator = 1;
        n++;
        snprintf(items[n].label, sizeof(items[n].label), "%s", e->pinned ? "Desafixar" : "Fixar");
        items[n].enabled = 1;
        items[n].is_separator = 0;
        n++;
        panel_menu_open(w->panel, w, anchor_x, anchor_w, items, n, (void *)(uintptr_t)e->win, tasklist_menu_select);
        return 1;
    }

    return 0;
}

const PanelWidgetOps tasklist_ops = {
    .type_name = "tasklist",
    .priv_size = sizeof(TasklistPriv),
    .init = tasklist_init,
    .destroy = tasklist_destroy,
    .measure = tasklist_measure,
    .paint = tasklist_paint,
    .on_button = tasklist_on_button,
    .on_tick = tasklist_on_tick,
    .get_tooltip = tasklist_get_tooltip,
};
