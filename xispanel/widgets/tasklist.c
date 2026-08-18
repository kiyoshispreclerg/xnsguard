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
    /* 1 = this slot isn't a real window at all -- a pinned app with no
     * currently-running match (see PinnedApp/tasklist_pin_class() below).
     * win is None, minimized/maximized/desktop are meaningless, and icon
     * is *borrowed* from the owning PinnedApp (not freed by the normal
     * per-tick icon cleanup in tasklist_on_tick() -- see that loop's
     * is_placeholder check). */
    int is_placeholder;
    cairo_surface_t *icon;
    /* 1 once a .desktop-entry icon fallback lookup has been attempted for
     * this window (see tasklist_on_tick()'s icon fallback) -- carried
     * forward by win alongside `icon` itself, so a window whose icon
     * never resolves (no matching .desktop file) doesn't get its
     * directory scan repeated every tick/property-event forever. */
    int icon_lookup_tried;
} TaskEntry;

/* One app pinned via the tasklist's own "Fixar" context-menu item (or the
 * `pinned=` config key, for pins that should survive a restart without
 * needing the running app to have been open at boot) -- stays in this
 * list independent of whether a matching window is currently open.
 * tasklist_on_tick() shows either the real running window's own button
 * (if wm_class matches one) or, if none is running right now, a
 * launcher-style placeholder button built from this entry -- see
 * TaskEntry::is_placeholder. name/exec/icon are resolved once, at pin
 * time (tasklist_pin_class()), via desktop_entry_find_by_wm_class() --
 * not re-resolved every tick, since a directory scan of every .desktop
 * file on the system is too expensive to repeat on a timer. */
typedef struct {
    char wm_class[64];
    char name[128];
    char exec[512]; /* empty if no .desktop entry was found -- the placeholder button then shows
                      * but does nothing on click (nothing to launch), same as a plain icon-less
                      * fallback rather than silently pretending it can relaunch the app. */
    cairo_surface_t *icon; /* owned by this struct; NULL if nothing resolved (draw_fallback_icon() covers it) */
} PinnedApp;

#define MAX_PINNED 24

typedef struct {
    int compact; /* 0 = wide (icon+label), 1 = compact (icon only) */
    int same_desktop_only; /* 1 = only list tasks on the current _NET_CURRENT_DESKTOP */
    int same_output_only; /* 1 = only list tasks whose center is on this panel's own output */
    int minimized_only; /* 1 = only list minimized tasks */
    int icon_padding; /* px of empty space around the icon on every side; 0 (default) = icon fills the
                        * whole button height. See icon_size_for(). */
    int show_thumbs; /* 1 = tooltip includes a live thumbnail of the hovered task's window (see thumb.c);
                       * no-op if xispanel was built without libXcomposite or no compositor is running. */
    int show_desktop_badge; /* 1 = draw the task's virtual-desktop number on its icon; 0 (default) = don't. */
    int group_apps; /* 1 = collapse same-app windows (matched by WM_CLASS) into one button; 0 (default) = don't. */
    PinnedApp pinned[MAX_PINNED];
    int n_pinned;
    TaskEntry tasks[MAX_TASKS];
    int n_tasks;
    int n_desktops;
    int btn_w[MAX_TASKS]; /* natural (unclipped) width of each *display slot*'s button -- see display_repr[] */

    /* One display slot per taskbar button actually drawn: with group_apps
     * off, this is a 1:1 mirror of tasks[] (n_display == n_tasks,
     * display_repr[d] == d); with it on, tasks[] sharing a WM_CLASS
     * collapse into a single slot. Built fresh by tasklist_build_display()
     * every tasklist_measure() call (tasks[] itself only actually changes
     * once per ~800ms tick, same staleness tradeoff btn_w[] already makes
     * between ticks). */
    int display_repr[MAX_TASKS]; /* tasks[] index of the slot's representative window */
    int display_count[MAX_TASKS]; /* how many tasks[] windows this slot represents (>=1) */
    int n_display;

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

    /* Signature of everything tasklist_paint() draws that can change on
     * its own between ticks (the task set, the active-window highlight,
     * the desktop count) -- compared each tick so on_tick only asks for a
     * repaint when it actually differs, instead of repainting every
     * ~800ms unconditionally. Scroll offset / pinned toggles change only
     * on user interaction, which repaints through the button path, so
     * they don't need to drive this. */
    unsigned long last_sig;
} TasklistPriv;

/* FNV-1a over the drawn task state -- see TasklistPriv::last_sig. */
static unsigned long tasklist_display_sig(TasklistPriv *tp, Window active)
{
    unsigned long h = 1469598103934665603UL;
#define SIG_MIX(byte) (h = (h ^ (unsigned char)(byte)) * 1099511628211UL)
#define SIG_MIX_INT(v)                                                                                                \
    do {                                                                                                             \
        unsigned long _v = (unsigned long)(v);                                                                       \
        for (unsigned _k = 0; _k < sizeof(_v); _k++)                                                                 \
            SIG_MIX(_v >> (_k * 8));                                                                                 \
    } while (0)
    SIG_MIX_INT(tp->n_tasks);
    SIG_MIX_INT(tp->n_desktops);
    SIG_MIX_INT(active);
    for (int i = 0; i < tp->n_tasks; i++) {
        TaskEntry *e = &tp->tasks[i];
        SIG_MIX_INT(e->win);
        for (const char *s = e->title; *s; s++) {
            SIG_MIX(*s);
        }
        SIG_MIX(0xff); /* title terminator */
        SIG_MIX_INT(e->desktop);
        SIG_MIX(e->minimized);
        SIG_MIX(e->maximized);
        SIG_MIX(e->pinned);
        SIG_MIX_INT((uintptr_t)e->icon);
    }
#undef SIG_MIX
#undef SIG_MIX_INT
    return h;
}

static int tasklist_find(TasklistPriv *tp, Window win)
{
    for (int i = 0; i < tp->n_tasks; i++) {
        if (tp->tasks[i].win == win) {
            return i;
        }
    }
    return -1;
}

/* Resolves and stores a newly-pinned app's name/exec/icon via
 * desktop_entry_find_by_wm_class() + resolve_icon_theme_name() -- called
 * once per pin (from tasklist_init()'s `pinned=` parsing, or from the
 * "Fixar" context-menu item), never re-resolved per-tick. No-op if `cls`
 * is already pinned or the list is full. If no .desktop entry (or no
 * Icon=) is found, the placeholder button just falls back to
 * draw_fallback_icon() like any other icon-less entry -- same as a real
 * running window whose _NET_WM_ICON is also missing. */
static void tasklist_pin_class(TasklistPriv *tp, const char *cls)
{
    if (!cls[0] || tp->n_pinned >= MAX_PINNED) {
        return;
    }
    for (int i = 0; i < tp->n_pinned; i++) {
        if (strcmp(tp->pinned[i].wm_class, cls) == 0) {
            return; /* already pinned */
        }
    }
    PinnedApp *pa = &tp->pinned[tp->n_pinned++];
    memset(pa, 0, sizeof(*pa));
    snprintf(pa->wm_class, sizeof(pa->wm_class), "%s", cls);

    char icon_name[256] = "";
    desktop_entry_find_by_wm_class(cls, pa->name, sizeof(pa->name), pa->exec, sizeof(pa->exec), icon_name,
                                    sizeof(icon_name));
    if (!pa->name[0]) {
        snprintf(pa->name, sizeof(pa->name), "%s", cls);
    }
    if (icon_name[0]) {
        pa->icon = resolve_icon_theme_name(icon_name);
    }
}

static void tasklist_unpin_class(TasklistPriv *tp, const char *cls)
{
    for (int i = 0; i < tp->n_pinned; i++) {
        if (strcmp(tp->pinned[i].wm_class, cls) == 0) {
            if (tp->pinned[i].icon) {
                cairo_surface_destroy(tp->pinned[i].icon);
            }
            for (int j = i; j < tp->n_pinned - 1; j++) {
                tp->pinned[j] = tp->pinned[j + 1];
            }
            tp->n_pinned--;
            return;
        }
    }
}

static int tasklist_init(PanelWidget *w)
{
    TasklistPriv *tp = w->priv;
    char buf[16];
    tp->compact = kv_get(w->config_kv, "mode", buf, sizeof(buf)) && strcmp(buf, "compact") == 0;
    tp->same_desktop_only = kv_get(w->config_kv, "same_desktop", buf, sizeof(buf)) && strcmp(buf, "yes") == 0;
    tp->same_output_only = kv_get(w->config_kv, "same_output", buf, sizeof(buf)) && strcmp(buf, "yes") == 0;
    tp->minimized_only = kv_get(w->config_kv, "minimized_only", buf, sizeof(buf)) && strcmp(buf, "yes") == 0;
    tp->icon_padding = kv_get_int(w->config_kv, "icon_padding", 0);
    if (tp->icon_padding < 0) {
        tp->icon_padding = 0;
    }
    tp->show_thumbs = kv_get(w->config_kv, "show_thumbs", buf, sizeof(buf)) && strcmp(buf, "yes") == 0;
    tp->show_desktop_badge = kv_get(w->config_kv, "show_desktop_badge", buf, sizeof(buf)) && strcmp(buf, "yes") == 0;
    tp->group_apps = kv_get(w->config_kv, "group", buf, sizeof(buf)) && strcmp(buf, "yes") == 0;
    tp->n_desktops = 1;

    /* Optional `pinned=<wm_class1>,<wm_class2>,...` -- pins that should
     * already be there on startup, hand-edited into the config (xispanel
     * doesn't write its own config file -- see the file-level doc
     * comment in xispanel.c). Pins added later via the right-click
     * "Fixar" menu are session-only unless the user adds them here too. */
    char list[512];
    if (kv_get(w->config_kv, "pinned", list, sizeof(list))) {
        char *save = NULL;
        for (char *tok = strtok_r(list, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            tasklist_pin_class(tp, tok);
        }
    }

    w->next_tick_ms = now_ms();
    return 0;
}

static void tasklist_destroy(PanelWidget *w)
{
    TasklistPriv *tp = w->priv;
    for (int i = 0; i < tp->n_tasks; i++) {
        if (tp->tasks[i].icon && !tp->tasks[i].is_placeholder) {
            cairo_surface_destroy(tp->tasks[i].icon);
        }
    }
    for (int i = 0; i < tp->n_pinned; i++) {
        if (tp->pinned[i].icon) {
            cairo_surface_destroy(tp->pinned[i].icon);
        }
    }
}

static int tasklist_on_tick(PanelWidget *w, uint64_t now)
{
    TasklistPriv *tp = w->priv;
    /* Slow fallback only: window open/close/desktop-switch (root props) and
     * per-window title/max/min-state changes now arrive as PropertyNotify
     * events that re-poll this widget immediately (see ewmh_watch_init() +
     * xispanel.c's PropertyNotify handler), so this periodic tick just
     * backstops the event path. */
    w->next_tick_ms = now + 2000;

    Window *list = NULL;
    int n = 0;
    if (!ewmh_get_client_list(&list, &n)) {
        return 0;
    }
    if (n > MAX_TASKS) {
        n = MAX_TASKS;
    }

    int current_desktop = tp->same_desktop_only ? ewmh_get_current_desktop() : -1;

    TaskEntry fresh[MAX_TASKS];
    int n_fresh = 0;
    int icon_px = icon_size_for(w->thickness, tp->icon_padding);
    for (int i = 0; i < n; i++) {
        Window win = list[i];
        if (ewmh_skip_taskbar(win)) {
            continue;
        }
        int desktop = ewmh_get_desktop(win);
        int minimized, maximized;
        ewmh_get_state_flags(win, &minimized, &maximized);
        /* current_desktop == -1 means either the filter is off, or no WM
         * ever set _NET_CURRENT_DESKTOP -- either way, don't filter. */
        if (tp->same_desktop_only && current_desktop >= 0 && desktop >= 0 && desktop != current_desktop) {
            continue;
        }
        if (tp->same_output_only && !ewmh_window_in_rect(win, w->panel->out_x, w->panel->out_y, w->panel->out_w,
                                                           w->panel->out_h)) {
            continue;
        }
        if (tp->minimized_only && !minimized) {
            continue;
        }
        int old_idx = tasklist_find(tp, win);
        TaskEntry *e = &fresh[n_fresh++];
        memset(e, 0, sizeof(*e));
        e->win = win;
        ewmh_get_title(win, e->title, sizeof(e->title));
        ewmh_get_class(win, e->wm_class, sizeof(e->wm_class));
        e->desktop = desktop;
        e->minimized = minimized;
        e->maximized = maximized;
        if (old_idx >= 0) {
            e->icon = tp->tasks[old_idx].icon; /* ownership moves to `fresh` */
            tp->tasks[old_idx].icon = NULL;
            e->icon_lookup_tried = tp->tasks[old_idx].icon_lookup_tried;
        } else {
            e->icon = ewmh_get_icon_surface(win, icon_px);
        }
        if (!e->icon && !e->icon_lookup_tried && e->wm_class[0]) {
            /* _NET_WM_ICON didn't supply one (some GTK/Electron apps
             * only set an icon via the icon theme, keyed by WM_CLASS) --
             * fall back to the same .desktop-entry lookup pinned
             * placeholders use. Only ever attempted once per window (see
             * icon_lookup_tried's doc comment) -- a directory scan of
             * every .desktop file on the system every ~2s for a window
             * that will never resolve one is exactly the kind of idle
             * busywork this widget's on_tick was recently reworked to
             * avoid. */
            e->icon_lookup_tried = 1;
            char icon_name[256] = "";
            if (desktop_entry_find_by_wm_class(e->wm_class, NULL, 0, NULL, 0, icon_name, sizeof(icon_name)) &&
                icon_name[0]) {
                e->icon = resolve_icon_theme_name(icon_name);
            }
        }
    }
    XFree(list);

    /* Pinned apps (tasklist_pin_class()) with no window among `fresh`
     * matching their wm_class get a launcher-style placeholder button
     * appended, and every match gets flagged pinned (the "pin" dot and
     * the context menu's Desafixar item both read TaskEntry::pinned, not
     * PinnedApp directly, so a running window's pinned-ness is always
     * derived fresh here rather than carried forward from the previous
     * tick -- tp->pinned[] is the single source of truth for what's
     * pinned, never TaskEntry::pinned on its own). */
    for (int pi = 0; pi < tp->n_pinned && n_fresh < MAX_TASKS; pi++) {
        PinnedApp *pa = &tp->pinned[pi];
        int matched = 0;
        for (int i = 0; i < n_fresh; i++) {
            if (fresh[i].wm_class[0] && strcmp(fresh[i].wm_class, pa->wm_class) == 0) {
                fresh[i].pinned = 1;
                matched = 1;
            }
        }
        if (matched) {
            continue;
        }
        TaskEntry *e = &fresh[n_fresh++];
        memset(e, 0, sizeof(*e));
        e->win = None;
        e->is_placeholder = 1;
        e->pinned = 1;
        snprintf(e->wm_class, sizeof(e->wm_class), "%s", pa->wm_class);
        snprintf(e->title, sizeof(e->title), "%s", pa->name);
        e->icon = pa->icon; /* borrowed -- see TaskEntry::is_placeholder's doc comment */
    }

    /* Anything still owning an icon surface here belonged to a window
     * that's gone from _NET_CLIENT_LIST now -- free it. A placeholder's
     * icon is borrowed from its PinnedApp (owned/freed by
     * tasklist_unpin_class()/tasklist_destroy() instead), so skip those
     * or this would double-free/dangle the very next tick. */
    for (int i = 0; i < tp->n_tasks; i++) {
        if (tp->tasks[i].icon && !tp->tasks[i].is_placeholder) {
            cairo_surface_destroy(tp->tasks[i].icon);
        }
    }
    memcpy(tp->tasks, fresh, sizeof(TaskEntry) * (size_t)n_fresh);
    tp->n_tasks = n_fresh;
    tp->n_desktops = ewmh_get_number_of_desktops();

    /* Repaint only when the drawn task state actually changed -- the
     * active window (highlight) is fetched here purely for the signature,
     * matching what tasklist_paint() reads. */
    unsigned long sig = tasklist_display_sig(tp, ewmh_get_active_window());
    if (sig == tp->last_sig) {
        return 0;
    }
    tp->last_sig = sig;
    return 1;
}

/* Groups tasks[] entries sharing the same WM_CLASS (res_class -- the
 * general "which application" half of WM_CLASS, not the per-instance
 * name) into display slots, applied *after* same_desktop/same_output/
 * minimized_only already narrowed tasks[] down to what this panel would
 * show ungrouped -- grouping only ever collapses buttons that would
 * otherwise already be visible side by side here, never reaches across
 * that filtering. A window with no WM_CLASS at all (rare, but not
 * unheard of) never groups with anything, including other classless
 * windows, since there's no shared identity to group by. This is the
 * same signal simple non-Plasma taskbars (xfce4-panel, tint2) group by;
 * KWin itself doesn't group windows at all -- that's Plasma's Task
 * Manager applet layered on top, and it prefers a window's .desktop-file
 * match (StartupWMClass) over raw WM_CLASS when one's known, falling
 * back to WM_CLASS otherwise. xispanel has no .desktop-matching yet (that's
 * launcher-phase territory), so WM_CLASS is both the fallback and, for
 * now, the whole story.
 *
 * The group's representative (whose icon/title the collapsed button
 * shows) is the group's currently-active window if it has one, else
 * simply the first member found -- so focusing a different window of an
 * already-grouped app updates what the button displays. */
static void tasklist_build_display(TasklistPriv *tp)
{
    Window active = tp->group_apps ? ewmh_get_active_window() : None;
    int assigned[MAX_TASKS] = {0};
    tp->n_display = 0;

    for (int i = 0; i < tp->n_tasks && tp->n_display < MAX_TASKS; i++) {
        if (assigned[i]) {
            continue;
        }
        assigned[i] = 1;
        int repr = i;
        int count = 1;
        if (tp->group_apps && tp->tasks[i].wm_class[0]) {
            for (int j = i + 1; j < tp->n_tasks; j++) {
                if (!assigned[j] && strcmp(tp->tasks[i].wm_class, tp->tasks[j].wm_class) == 0) {
                    assigned[j] = 1;
                    count++;
                    if (tp->tasks[j].win == active) {
                        repr = j;
                    }
                }
            }
        }
        tp->display_repr[tp->n_display] = repr;
        tp->display_count[tp->n_display] = count;
        tp->n_display++;
    }
}

/* All tasks[] indices belonging to the same group as tasks[repr_idx] --
 * same WM_CLASS-matching rule tasklist_build_display() used to form the
 * group in the first place. Used when opening the group member-list popup
 * and when building a grouped tooltip, both of which need every member,
 * not just the representative tasklist_build_display() picked. */
static int tasklist_group_members(TasklistPriv *tp, int repr_idx, int *out_idx, int max)
{
    int n = 0;
    const char *cls = tp->tasks[repr_idx].wm_class;
    for (int i = 0; i < tp->n_tasks && n < max; i++) {
        if (i == repr_idx || (cls[0] && strcmp(tp->tasks[i].wm_class, cls) == 0)) {
            out_idx[n++] = i;
        }
    }
    return n;
}

static void tasklist_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    TasklistPriv *tp = w->priv;
    Panel *p = w->panel;
    int icon_px = icon_size_for(cross_axis, tp->icon_padding);
    tasklist_build_display(tp);
    int cursor = 0;
    for (int d = 0; d < tp->n_display; d++) {
        TaskEntry *e = &tp->tasks[tp->display_repr[d]];
        int bw;
        /* Pinned-not-running placeholders are always icon-only, even in
         * wide mode -- no title to show a title for would either draw
         * nothing in a title-sized gap or (worse) show the app name where
         * every other button shows the actual window title, so icon-only
         * keeps them visually distinct from real task buttons at a glance. */
        if (tp->compact || e->is_placeholder) {
            bw = icon_px + 8;
        } else {
            double tw;
            pango_text_extents_ellipsized(p->cr, e->title, panel_text_size(p), 0, &tw, NULL);
            bw = icon_px + 8 + (int)tw + 8;
            if (bw > TASKLIST_WIDE_MAXW) {
                bw = TASKLIST_WIDE_MAXW;
            }
        }
        tp->btn_w[d] = bw;
        cursor += bw + TASKLIST_BTN_GAP;
    }
    *out_len = tp->n_display > 0 ? cursor - TASKLIST_BTN_GAP : 0;

    /* Minimum: room for exactly one task button (compact-sized, since that's
     * the smallest a button can usefully be) plus the up/down arrow pair
     * that tasklist_layout_visible() reserves once scrolling kicks in. */
    *out_min_len = tp->n_display > 0 ? (icon_px + 8 + TASKLIST_ARROW_W + TASKLIST_ARROW_GAP) : 0;
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
    for (int i = 0; i < tp->n_display; i++) {
        natural_total += tp->btn_w[i] + (i > 0 ? TASKLIST_BTN_GAP : 0);
    }

    tp->scrollable = natural_total > w->len;
    int content_avail = tp->scrollable ? w->len - TASKLIST_ARROW_W - TASKLIST_ARROW_GAP : w->len;
    if (content_avail < 0) {
        content_avail = 0;
    }

    if (tp->scroll_offset >= tp->n_display) {
        tp->scroll_offset = tp->n_display > 0 ? tp->n_display - 1 : 0;
    }
    if (tp->scroll_offset < 0) {
        tp->scroll_offset = 0;
    }

    int cursor = 0;
    tp->n_visible = 0;
    /* tp->vis_idx[] now stores *display-slot* indices (0..n_display-1),
     * not raw tasks[] indices -- resolve via tp->display_repr[] wherever
     * the actual TaskEntry is needed. */
    for (int i = tp->scroll_offset; i < tp->n_display && tp->n_visible < MAX_TASKS; i++) {
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
 * hit-testing. No tooltip over the scroll arrows. A single (ungrouped, or
 * group of one) task is clickable exactly as before: the window's XID is
 * packed into *out_ctx for tooltip_activate()/tooltip_close_item() below.
 * A grouped button (count > 1) instead lists every member's title, one per
 * line, and isn't clickable -- which member "the click" should mean is
 * ambiguous from a tooltip; click the button itself for the selection
 * popup (see tasklist_on_button()). */
static int tasklist_get_tooltip(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w,
                                 int *out_closable, void **out_ctx)
{
    TasklistPriv *tp = w->priv;
    tasklist_layout_visible(w);

    if (tp->scrollable && local_x >= tp->arrow_x) {
        return 0;
    }
    for (int vi = 0; vi < tp->n_visible; vi++) {
        if (local_x >= tp->vis_x[vi] && local_x < tp->vis_x[vi] + tp->vis_w[vi]) {
            int d = tp->vis_idx[vi];
            int repr = tp->display_repr[d];
            if (tp->display_count[d] > 1) {
                int members[MAX_TASKS];
                int n = tasklist_group_members(tp, repr, members, MAX_TASKS);
                size_t used = 0;
                for (int m = 0; m < n && used < bufsz; m++) {
                    int wrote = snprintf(buf + used, bufsz - used, "%s%s", m > 0 ? "\n" : "", tp->tasks[members[m]].title);
                    if (wrote < 0) {
                        break;
                    }
                    used += (size_t)wrote;
                }
                /* A snprintf() above that ran out of room could have cut
                 * the last title mid-codepoint. */
                trim_to_utf8_boundary(buf);
                *out_closable = 0;
                *out_ctx = NULL;
            } else {
                copy_utf8_truncated(buf, bufsz, tp->tasks[repr].title);
                /* A placeholder (pinned, not running) has no window to
                 * close -- see tasklist_on_button()'s own placeholder
                 * branch for its actual click behavior (launch), which
                 * goes through the button itself, not this tooltip. */
                *out_closable = !tp->tasks[repr].is_placeholder;
                *out_ctx = (void *)(uintptr_t)tp->tasks[repr].win;
            }
            *anchor_x = tp->vis_x[vi];
            *anchor_w = tp->vis_w[vi];
            return 1;
        }
    }
    return 0;
}

static void tasklist_tooltip_activate(PanelWidget *w, void *ctx)
{
    (void)w;
    Window win = (Window)(uintptr_t)ctx;
    ewmh_activate(win);
    XFlush(g_dpy);
}

static void tasklist_tooltip_close_item(PanelWidget *w, void *ctx)
{
    (void)w;
    Window win = (Window)(uintptr_t)ctx;
    ewmh_close(win);
    XFlush(g_dpy);
}

/* Matches the hovered task's window to an active MPRIS player by PID
 * (mpris.c polls the bus separately; this is just a cheap lookup against
 * that cache). Re-resolves the task from local_x the same way
 * tasklist_get_tooltip() does rather than trusting it was called
 * first/last -- tooltip.c calls both independently. */
static int tasklist_get_tooltip_mpris(PanelWidget *w, int local_x, char *out_busname, size_t bufsz, int *out_playing)
{
    TasklistPriv *tp = w->priv;
    tasklist_layout_visible(w);

    if (tp->scrollable && local_x >= tp->arrow_x) {
        return 0;
    }
    for (int vi = 0; vi < tp->n_visible; vi++) {
        if (local_x >= tp->vis_x[vi] && local_x < tp->vis_x[vi] + tp->vis_w[vi]) {
            int d = tp->vis_idx[vi];
            if (tp->display_count[d] > 1) {
                return 0; /* which member's player? -- ambiguous while grouped */
            }
            Window win = tp->tasks[tp->display_repr[d]].win;
            unsigned long pid = ewmh_get_pid(win);
            return mpris_find_for_pid(pid, out_busname, bufsz, out_playing);
        }
    }
    return 0;
}

/* Same re-resolve-from-local_x pattern as tasklist_get_tooltip_mpris()
 * above -- only offers a thumbnail when show_thumbs=yes; thumb.c/
 * tooltip.c handle the "no compositor / not built with libXcomposite"
 * case themselves, so this doesn't need to check thumb_available() too. */
static int tasklist_get_tooltip_thumb(PanelWidget *w, int local_x, Window *out_win)
{
    TasklistPriv *tp = w->priv;
    if (!tp->show_thumbs) {
        return 0;
    }
    tasklist_layout_visible(w);

    if (tp->scrollable && local_x >= tp->arrow_x) {
        return 0;
    }
    for (int vi = 0; vi < tp->n_visible; vi++) {
        if (local_x >= tp->vis_x[vi] && local_x < tp->vis_x[vi] + tp->vis_w[vi]) {
            int d = tp->vis_idx[vi];
            if (tp->display_count[d] > 1) {
                return 0; /* which member's window to preview? -- ambiguous while grouped */
            }
            if (tp->tasks[tp->display_repr[d]].is_placeholder) {
                return 0; /* pinned, not running -- no window to thumbnail */
            }
            *out_win = tp->tasks[tp->display_repr[d]].win;
            return 1;
        }
    }
    return 0;
}

/* Same re-resolve-from-local_x pattern as the other get_tooltip_* callbacks
 * -- fills every member window of the hovered *grouped* button (count > 1)
 * so tooltip.c can render its multi-window layout; returns 0 for anything
 * else (no button under local_x, or an ungrouped one, which
 * tasklist_get_tooltip_thumb() above already handles on its own). */
static int tasklist_get_tooltip_group(PanelWidget *w, int local_x, TooltipGroupItem *out_items, int max_items,
                                       int *out_n)
{
    TasklistPriv *tp = w->priv;
    tasklist_layout_visible(w);

    if (tp->scrollable && local_x >= tp->arrow_x) {
        return 0;
    }
    for (int vi = 0; vi < tp->n_visible; vi++) {
        if (local_x >= tp->vis_x[vi] && local_x < tp->vis_x[vi] + tp->vis_w[vi]) {
            int d = tp->vis_idx[vi];
            if (tp->display_count[d] <= 1) {
                return 0;
            }
            int members[MAX_TASKS];
            int n = tasklist_group_members(tp, tp->display_repr[d], members, MAX_TASKS);
            int n_out = 0;
            for (int m = 0; m < n && n_out < max_items; m++) {
                out_items[n_out].win = tp->tasks[members[m]].win;
                snprintf(out_items[n_out].title, sizeof(out_items[0].title), "%s", tp->tasks[members[m]].title);
                n_out++;
            }
            *out_n = n_out;
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
    int icon_px = icon_size_for(w->thickness, tp->icon_padding);
    int icon_y = oy + (w->thickness - icon_px) / 2;
    /* Root-window-space mapping for _NET_WM_ICON_GEOMETRY below. Uses the
     * panel's un-rotated physical position (same rect panel_repaint()
     * computes before applying p->rotate) -- exact for rotate=0/180, an
     * approximation at 90/270 since the button's actual displayed spot is
     * transposed; acceptable for what's only an animation-endpoint hint. */
    int horiz = (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM);

    for (int vi = 0; vi < tp->n_visible; vi++) {
        int d = tp->vis_idx[vi];
        int group_count = tp->display_count[d];
        TaskEntry *e = &tp->tasks[tp->display_repr[d]];
        int bx = ox + tp->vis_x[vi];
        int bw = tp->vis_w[vi];

        if (!e->is_placeholder) {
            if (horiz) {
                ewmh_set_icon_geometry(e->win, p->x + w->x + tp->vis_x[vi], p->y, bw, w->thickness);
            } else {
                ewmh_set_icon_geometry(e->win, p->x, p->y + w->x + tp->vis_x[vi], w->thickness, bw);
            }
        }

        if (e->win == active) {
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.18);
            cairo_rectangle(cr, bx, oy, bw, w->thickness);
            cairo_fill(cr);
        }

        cairo_push_group(cr);
        if (e->icon) {
            draw_icon_scaled(cr, e->icon, bx + 4, icon_y, icon_px);
        } else {
            draw_fallback_icon(cr, bx + 4, icon_y, icon_px, e->title, p->fg_r, p->fg_g, p->fg_b, panel_text_size(p));
        }
        if (!tp->compact && !e->is_placeholder) {
            /* Pango draws e->title directly -- no manual truncation
             * buffer needed, it ellipsizes to fit on its own, and (unlike
             * the plain cairo_show_text() this replaced) does per-glyph
             * font fallback, so a title in a script the configured UI
             * font doesn't cover still renders instead of showing tofu
             * boxes. See pango_text.c. */
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.95);
            pango_show_text_boxed(cr, bx + icon_px + 10, oy, w->thickness, bw - icon_px - 16, panel_text_size(p),
                                   e->title, NULL);
        }
        if (e->pinned) {
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.9);
            cairo_arc(cr, bx + icon_px + 2, icon_y + 2, 2.5, 0, 2 * 3.14159265);
            cairo_fill(cr);
        }
        if (tp->show_desktop_badge && tp->n_desktops > 1 && e->desktop >= 0) {
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
            cairo_set_font_size(cr, panel_text_size(p));
        }
        if (group_count > 1) {
            /* Bottom-left of the icon -- deliberately the one corner the
             * pin dot (top-right) and desktop badge (bottom-right) never
             * use, so all three can be shown at once without overlapping. */
            char badge[16];
            snprintf(badge, sizeof(badge), "%d", group_count);
            double badge_fs = w->thickness * 0.28;
            cairo_set_font_size(cr, badge_fs);
            cairo_text_extents_t bext;
            cairo_text_extents(cr, badge, &bext);
            double bx2 = bx + 2;
            double by2 = icon_y + icon_px;
            cairo_set_source_rgba(cr, 0, 0, 0, 0.55);
            cairo_rectangle(cr, bx2 - 2, by2 - bext.height - 1, bext.width + 4, bext.height + 3);
            cairo_fill(cr);
            cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.95);
            cairo_move_to(cr, bx2, by2);
            cairo_show_text(cr, badge);
            cairo_set_font_size(cr, panel_text_size(p));
        }
        cairo_pop_group_to_source(cr);
        /* Placeholder (pinned, not running) buttons are dimmed so they
         * read as "not currently open" at a glance, same idea as the
         * existing minimized dimming -- the two never overlap (a
         * placeholder is never minimized, it isn't a real window). */
        cairo_paint_with_alpha(cr, e->is_placeholder ? 0.5 : (e->minimized ? 0.55 : 1.0));
    }

    if (tp->scrollable) {
        int ax = ox + tp->arrow_x;
        int half = w->thickness / 2;
        int can_up = tp->scroll_offset > 0;
        int can_down = tp->vis_idx[tp->n_visible - 1] < tp->n_display - 1;
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

/* Tags a placeholder's context-menu ctx (see tasklist_on_button()'s
 * Button3 handling) so tasklist_menu_select() can tell it apart from a
 * real window's XID -- a real Window is always a server-assigned CARD32
 * resource ID (< 2^32 by the X11 protocol itself), so any ctx at or
 * above 2^32 unambiguously means "not a real window". The low bits carry
 * the pinned app's index into tp->pinned[] directly (not its wm_class or
 * anything heap-allocated) -- safe because pinned[] can only ever be
 * mutated by this same menu's own "Desafixar" selection, and menu.c only
 * ever has one menu open at a time, so nothing else can reorder it while
 * this ctx is outstanding. */
#define TASKLIST_PLACEHOLDER_CTX_TAG (1ULL << 32)

/* Context menu item order for a real window: 0=minimize/restore,
 * 1=maximize/restore, 2=move, 3=close, [separator], 5=pin/unpin. ctx is
 * the clicked window's XID, packed directly into the void* (Window fits
 * in a pointer-sized integer on every platform this targets -- no heap
 * allocation needed for something this small and short-lived). For a
 * placeholder (pinned, not running), it's a much shorter menu: 0=Abrir,
 * 1=Desafixar -- see tasklist_on_button()'s Button3 handling. */
static void tasklist_menu_select(Panel *panel, PanelWidget *w, void *ctx, int index)
{
    (void)panel;
    TasklistPriv *tp = w->priv;
    uint64_t raw = (uint64_t)(uintptr_t)ctx;

    if (raw & TASKLIST_PLACEHOLDER_CTX_TAG) {
        int pi = (int)(raw & (TASKLIST_PLACEHOLDER_CTX_TAG - 1));
        if (pi < 0 || pi >= tp->n_pinned) {
            return;
        }
        switch (index) {
        case 0: /* Abrir */
            if (tp->pinned[pi].exec[0]) {
                run_detached(tp->pinned[pi].exec);
            }
            break;
        case 1: /* Desafixar */
            tasklist_unpin_class(tp, tp->pinned[pi].wm_class);
            break;
        default:
            break;
        }
        tasklist_on_tick(w, now_ms()); /* rebuild tasks[]/pinned[] state immediately, don't wait ~2s */
        w->panel->dirty = 1;
        return;
    }

    Window win = (Window)(uintptr_t)ctx;
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
            if (tp->tasks[idx].pinned) {
                tasklist_unpin_class(tp, tp->tasks[idx].wm_class);
            } else if (tp->tasks[idx].wm_class[0]) {
                tasklist_pin_class(tp, tp->tasks[idx].wm_class);
            }
        }
        break;
    default:
        break;
    }
    XFlush(g_dpy);
    tasklist_on_tick(w, now_ms()); /* re-derive TaskEntry::pinned from tp->pinned[] immediately -- see its doc comment */
    w->panel->dirty = 1;
}

static int tasklist_on_button(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y)
{
    (void)root_x;
    (void)root_y;
    TasklistPriv *tp = w->priv;
    tasklist_layout_visible(w);

    /* Mouse wheel pages the tasklist from anywhere over the widget, not
     * just over the up/down arrow pair -- same direction convention as
     * the arrows (wheel up = earlier tasks, wheel down = later). */
    if (tp->scrollable && (button == Button4 || button == Button5)) {
        if (button == Button4) {
            if (tp->scroll_offset > 0) {
                tp->scroll_offset--;
            }
        } else {
            if (tp->n_visible > 0 && tp->vis_idx[tp->n_visible - 1] < tp->n_display - 1) {
                tp->scroll_offset++;
            }
        }
        w->panel->dirty = 1;
        return 1;
    }

    if (tp->scrollable && local_x >= tp->arrow_x && button == Button1) {
        if (local_y < w->thickness / 2) {
            if (tp->scroll_offset > 0) {
                tp->scroll_offset--;
            }
        } else {
            if (tp->n_visible > 0 && tp->vis_idx[tp->n_visible - 1] < tp->n_display - 1) {
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
            idx = tp->display_repr[tp->vis_idx[vi]];
            anchor_x = tp->vis_x[vi];
            anchor_w = tp->vis_w[vi];
            break;
        }
    }
    if (idx < 0) {
        return 0;
    }
    /* Both left- and right-click always act on the group's representative
     * window (whatever the button is currently showing) -- picking a
     * *different* member of a grouped button is done by hovering for the
     * tooltip's per-window list instead (see tasklist_get_tooltip_group()),
     * not by a separate click target here. */
    TaskEntry *e = &tp->tasks[idx];

    if (e->is_placeholder) {
        /* A pinned app with no window currently open -- click launches it
         * instead of any of the real-window actions below (nothing to
         * minimize/maximize/move/close). */
        if (button == Button1) {
            for (int pi = 0; pi < tp->n_pinned; pi++) {
                if (strcmp(tp->pinned[pi].wm_class, e->wm_class) == 0) {
                    if (tp->pinned[pi].exec[0]) {
                        run_detached(tp->pinned[pi].exec);
                    }
                    break;
                }
            }
            return 1;
        }
        if (button == Button3) {
            MenuItem items[2];
            snprintf(items[0].label, sizeof(items[0].label), "Abrir");
            items[0].enabled = 1;
            items[0].is_separator = 0;
            snprintf(items[1].label, sizeof(items[1].label), "Desafixar");
            items[1].enabled = 1;
            items[1].is_separator = 0;
            int pi = -1;
            for (int i = 0; i < tp->n_pinned; i++) {
                if (strcmp(tp->pinned[i].wm_class, e->wm_class) == 0) {
                    pi = i;
                    break;
                }
            }
            if (pi < 0) {
                return 1;
            }
            void *ctx = (void *)(uintptr_t)(TASKLIST_PLACEHOLDER_CTX_TAG | (unsigned)pi);
            panel_menu_open(w->panel, w, anchor_x, anchor_w, items, 2, ctx, tasklist_menu_select);
            return 1;
        }
        return 0;
    }

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
    .get_tooltip_mpris = tasklist_get_tooltip_mpris,
    .get_tooltip_thumb = tasklist_get_tooltip_thumb,
    .get_tooltip_group = tasklist_get_tooltip_group,
    .tooltip_activate = tasklist_tooltip_activate,
    .tooltip_close_item = tasklist_tooltip_close_item,
};
