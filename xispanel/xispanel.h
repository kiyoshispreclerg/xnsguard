/*
 * xispanel.h - shared types and the API the core exposes to widgets.
 *
 * xispanel.c owns the panel/window/layout/config/IPC machinery. Each
 * widget type lives in its own file under widgets/ and only sees this
 * header: the Panel/PanelWidget struct layout, a handful of core helpers
 * (now_ms, kv_get, widget_get_rect), the EWMH/ICCCM helpers from ewmh.c,
 * and the context-menu API from menu.c. A widget file never needs to
 * touch xispanel.c's internals directly.
 */
#ifndef XISPANEL_H
#define XISPANEL_H

#include <X11/Xlib.h>
#include <cairo/cairo.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_WIDGETS 32

enum edge { EDGE_TOP, EDGE_BOTTOM, EDGE_LEFT, EDGE_RIGHT };
enum panel_mode { MODE_DOCK, MODE_OVERLAY, MODE_AUTOHIDE };
enum autohide_state { AH_HIDDEN, AH_SHOWING, AH_SHOWN, AH_HIDING };

typedef struct PanelWidget PanelWidget;
typedef struct Panel Panel;

/* One entry of a grouped-item tooltip -- see PanelWidgetOps.get_tooltip_group. */
#define TOOLTIP_GROUP_MAX_ITEMS 24
typedef struct {
    Window win;
    char title[128];
} TooltipGroupItem;

typedef struct {
    const char *type_name; /* "spacer", "clock", "tasklist", ... -- used in config */
    size_t priv_size; /* per-instance state, zeroed on creation */

    int (*init)(PanelWidget *w);
    void (*destroy)(PanelWidget *w);
    /* Reports desired size along the panel's main axis. out_len < 0 means
     * "greedy": fill whatever space is left after fixed-size widgets,
     * split evenly among every greedy widget in the same panel.
     * out_min_len is the smallest length the widget can still render
     * something useful in -- panel_layout() shrinks fixed-size widgets
     * toward their min (proportionally, never below it) when every
     * widget's desired length doesn't fit the panel. A widget that can't
     * meaningfully shrink (spacer, clock) just reports out_min_len ==
     * out_len. */
    void (*measure)(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len);
    void (*paint)(PanelWidget *w, cairo_t *cr);
    int (*on_button)(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y);
    void (*on_tick)(PanelWidget *w, uint64_t now);
    /* Optional (NULL is fine -- most widgets don't need this): fills buf
     * with tooltip text (lines separated by '\n') to show after the
     * pointer hovers over local_x (widget-local, main-axis) for a bit.
     * Returns 1 if there's something to show, 0 otherwise. Also reports
     * the specific sub-item's own local [*anchor_x, *anchor_x+*anchor_w)
     * span (e.g. one task's button within tasklist) so the popup aligns
     * with that item rather than the whole widget -- widgets without
     * sub-items just report their own full [0, w->len) span. Called
     * repeatedly (on every pointer motion, and periodically while shown,
     * so content like a ticking clock stays current) -- keep it cheap.
     *
     * If the tooltip should also be clickable (e.g. click it to activate
     * the task it describes, like plasmashell's taskbar tooltips), also
     * set *out_closable = 1 and *out_ctx to whatever tooltip_activate()/
     * tooltip_close_item() below need -- both start out 0/NULL, so a
     * widget that doesn't care just never touches them and gets a
     * read-only tooltip with no close icon. Every tooltip (closable or
     * not) uses the same hover-intent popup behavior -- see tooltip.c. */
    int (*get_tooltip)(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w,
                        int *out_closable, void **out_ctx);
    /* Only called for a tooltip that reported *out_closable = 1: click on
     * the tooltip's body (not its close icon) -- e.g. activate the window
     * it describes. The tooltip closes right after. */
    void (*tooltip_activate)(PanelWidget *w, void *ctx);
    /* Click on the tooltip's small close icon (only drawn when
     * *out_closable = 1) -- e.g. close the window it describes. The
     * tooltip closes right after. */
    void (*tooltip_close_item)(PanelWidget *w, void *ctx);
    /* Optional, called right after a successful get_tooltip(): if
     * whatever the tooltip describes has an active MPRIS player attached
     * (e.g. tasklist matching the hovered window's PID via
     * ewmh_get_pid()/mpris_find_for_pid()), fill *out_busname with its
     * DBus bus name and *out_playing with its current play state, and
     * return 1 -- the tooltip then draws play/pause/next/previous buttons
     * that call mpris_play_pause()/mpris_next()/mpris_previous() with
     * that bus name directly (see tooltip.c). Never called if MPRIS is
     * unavailable (no libdbus-1 at runtime, or no session bus) since
     * mpris_find_for_pid() itself just always reports nothing then.
     * Widgets that don't apply (clock, winctl) simply don't implement
     * this. */
    int (*get_tooltip_mpris)(PanelWidget *w, int local_x, char *out_busname, size_t bufsz, int *out_playing);
    /* Optional, called right after a successful get_tooltip(): if the
     * widget wants a live thumbnail of a window drawn into the tooltip
     * (tasklist does this when its own show_thumbs=yes and the hovered
     * task's window applies), fill *out_win and return 1 -- see
     * thumb.c's thumb_paint(). The tooltip's existing click-to-activate
     * mechanism (*out_closable/tooltip_activate from get_tooltip() above)
     * already covers clicking the thumbnail itself, no separate handling
     * needed. Never called if window thumbnails are unavailable (no
     * compositor running, or xispanel was built without libXcomposite --
     * see thumb.c/thumb_stub.c) since thumb_paint() itself just always
     * reports "nothing painted" then. */
    int (*get_tooltip_thumb)(PanelWidget *w, int local_x, Window *out_win);
    /* Optional, called right after a successful get_tooltip(): for a
     * *grouped* item representing more than one window (tasklist's
     * group=yes), fill up to max_items entries of *out_items and set
     * *out_n, return 1. tooltip.c then renders a multi-window layout
     * instead of the normal single-item text/thumb/mpris one -- a row of
     * thumbnails if a compositor is available (thumb_available()),
     * otherwise a stacked list of titles -- each entry individually
     * clickable to activate that window, with its own close icon. Return
     * 0 (e.g. the hovered item isn't actually grouped) to fall back to
     * the normal single-item tooltip. */
    int (*get_tooltip_group)(PanelWidget *w, int local_x, TooltipGroupItem *out_items, int max_items, int *out_n);
} PanelWidgetOps;

struct PanelWidget {
    const PanelWidgetOps *ops;
    Panel *panel;
    int order;
    char config_kv[256]; /* raw "key=value key2=value2 ..." from config */
    void *priv;

    /* Filled in by panel_layout(); main-axis position/length, cross-axis
     * thickness (<= panel thickness). */
    int x, len, thickness;

    /* 0 = no pending tick. Folded into the main loop's "soonest timeout"
     * computation so widgets don't need their own timerfd. */
    uint64_t next_tick_ms;
};

struct Panel {
    int in_use;
    char name[32];
    char output[64]; /* "*" or an XRandR output name */
    enum edge edge;
    int pct; /* 0-100 */
    int thickness_cfg;
    enum panel_mode mode;
    /* 0/90/180/270: rotates every widget's content as a rigid whole
     * around the center of its on-panel slot. Works on any edge (not
     * just left/right) -- e.g. 180 on a top panel just flips its content
     * upside down; 90/270 on a top panel turns its (normally wide/short)
     * content sideways to fit the same footprint. See panel_repaint(). */
    int rotate;
    /* ms of hover over a widget before its tooltip appears (0 = instant).
     * See tooltip.c. */
    int tooltip_delay_ms;
    /* ms of grace after the pointer leaves the widget/popup before an
     * open tooltip actually closes (0 = instant close). Defaults to a
     * bit less than tooltip_delay_ms -- see tooltip.c. */
    int tooltip_close_delay_ms;
    /* off by default. When set, show_popup() reuses the existing tooltip
     * window across widgets/content instead of destroying and recreating
     * it each time (XMoveResizeWindow + cairo_xlib_surface_set_size, then
     * a full repaint) -- see tooltip.c's show_popup(). Lets a compositor's
     * "geometry change" animation smooth the move/resize between tooltips
     * instead of a create/destroy flicker. */
    int tooltip_reuse_window;

    /* theme */
    double bg_r, bg_g, bg_b, bg_a;
    double fg_r, fg_g, fg_b, fg_a;
    /* 0 = not detected/configured -- callers fall back to their own
     * existing size (usually thickness-proportional for in-panel widget
     * text, or a fixed constant for tooltip/menu popups). >0 = pixel font
     * size to use for task/window/clock labels and this panel's tooltip
     * and context-menu text; defaults to the live system font size (see
     * detect_system_font_size_px()) and can be overridden by THEME's
     * own font_size=<px>. */
    double font_size_px;
    int spacing;
    /* Optional 9-slice background image, replacing the solid bg_* color
     * entirely when it loads successfully -- see THEME's bg_image/
     * bg_slice keys and panel_load_bg_image() in xispanel.c. Path fields
     * are the raw config values (kept so reload can retry); *_surface is
     * NULL whenever there's no image or it failed to load, in which case
     * panel_repaint() just falls back to bg_r/g/b/a as always. */
    char bg_image_path[PATH_MAX];
    char bg_slice_path[PATH_MAX];
    int bg_slice_l, bg_slice_t, bg_slice_r, bg_slice_b;
    cairo_surface_t *bg_image_surface;

    /* resolved output geometry */
    int out_x, out_y, out_w, out_h;
    /* resolved output refresh rate in Hz, 0 if RandR couldn't report one
     * (e.g. no matching output, or a mode with no timing info) -- see
     * resolve_output_geometry(). Used by tooltip.c to pace the live-
     * thumbnail fallback poll to roughly this output's own frame rate
     * instead of a fixed guess. */
    double out_refresh_hz;
    /* resolved panel geometry when shown */
    int x, y, w, h;
    int thickness;
    /* resolved panel geometry when fully hidden (autohide only) */
    int hidden_x, hidden_y;

    Window win;
    Window sensor_win; /* autohide only: always-mapped 1px edge sensor */
    Visual *visual;
    int depth;
    Colormap cmap;
    cairo_surface_t *surface;
    cairo_t *cr;
    /* Offscreen backing buffer: every widget paints here, then a single
     * cairo_paint() blits the whole thing onto `surface` at the end of
     * panel_repaint(). Painting each widget straight onto the on-screen
     * xlib surface sent each fill/stroke as its own X request, which a
     * compositor could pick up mid-repaint -- visible as flicker, worst on
     * tasklist since it repaints on every ~800ms poll tick. */
    cairo_surface_t *buf_surface;
    cairo_t *buf_cr;

    int mapped;
    int dirty;

    enum autohide_state ah_state;
    uint64_t ah_anim_start_ms;
    uint64_t ah_hide_deadline_ms; /* 0 = none pending */

    PanelWidget widgets[MAX_WIDGETS];
    int n_widgets;
};

/* ---- shared X connection state (defined in xispanel.c) ---- */
extern Display *g_dpy;
extern Window g_root;
extern int g_screen;
extern cairo_font_face_t *g_font_face;
/* System UI font family name, as detected once at startup (see
 * detect_system_font_family() in xispanel.c) -- "" if detection failed
 * and fontconfig's generic default is in use instead. Exposed as a plain
 * string (not just the cairo_font_face_t above) for widgets that need to
 * hand the font name to an external process, e.g. xisserve's widget
 * passing it through so the launcher popup can match. */
extern char g_font_family[128];

/* ---- Pango-backed text drawing (pango_text.c, exploratory) ----
 *
 * See pango_text.c's file comment -- xispanel-plus-pango branch only. */
void pango_text_init(const char *family); /* call once at startup, after g_font_family is resolved */
/* Measures `text` (ellipsized to max_width_px first if positive) without
 * drawing -- use ahead of a pango_show_text_boxed() call when the final
 * pixel size is needed to position the text itself (e.g. centering). */
void pango_text_extents_ellipsized(cairo_t *cr, const char *text, double size_px, double max_width_px, double *out_w,
                                    double *out_h);
void pango_show_text_boxed(cairo_t *cr, double x, double top_y, double box_h, double max_width_px, double size_px,
                            const char *text, double *out_w);

/* ---- small helpers widgets rely on (xispanel.c) ---- */
uint64_t now_ms(void);
int kv_get(const char *kvline, const char *key, char *out, size_t outsz);
int kv_get_int(const char *kvline, const char *key, int defval);
/* Real window-space rectangle for a widget, accounting for panel
 * orientation (horizontal panels lay widgets out along x, vertical panels
 * along y). */
void widget_get_rect(const PanelWidget *w, int *x, int *y, int *width, int *height);
/* Resolved text size for `p`'s own in-panel widget text (task/window/clock
 * labels): p->font_size_px if set (system-detected or THEME's font_size=),
 * else the historical thickness-proportional size. Widgets that draw their
 * *own* independently-sized text (badges, pin dots, fallback icon letters)
 * intentionally don't use this -- only the shared "ambient" label size set
 * once per repaint and any widget code that needs to restore it after a
 * temporary override (see tasklist.c's badges). */
double panel_text_size(const Panel *p);
/* Decodes any format Imlib2 understands (PNG, SVG if librsvg's loader is
 * present at runtime, etc.) into a premultiplied-alpha ARGB32 Cairo
 * surface, or NULL on any failure (missing file, decode error, larger
 * than 4096px either side). Used for the panel's own 9-slice background
 * (see panel_load_bg_image()) and available to any widget that wants to
 * load an image of its own, e.g. `launcher`'s icon= key. */
cairo_surface_t *load_png_argb(const char *path);
/* Runs `cmd` via `sh -c`, detached (double-forked via setsid()) and never
 * waited on -- SIGCHLD is set to SIG_IGN in main() so the child is
 * auto-reaped by the kernel instead of becoming a zombie, same pattern
 * xisback's run_action() uses for its own click actions. No-op if `cmd`
 * is NULL/empty. */
void run_detached(const char *cmd);

/* ---- WM-type / strut atoms widgets/menu may need (ewmh.c) ---- */
extern Atom g_atom_wm_window_type;
extern Atom g_atom_wm_window_type_dock;
extern Atom g_atom_wm_window_type_popup_menu;
extern Atom g_atom_wm_window_type_tooltip;
extern Atom g_atom_wm_strut;
extern Atom g_atom_wm_strut_partial;

/* Interns every atom this file (and menu.c/widgets) needs. Call once at
 * startup, after XOpenDisplay(). */
void ewmh_init_atoms(void);

/* ---- EWMH/ICCCM client-list + window-control helpers (ewmh.c) ---- */
int ewmh_get_client_list(Window **out_list, int *out_n); /* caller XFree()s *out_list */
void ewmh_get_title(Window w, char *buf, size_t bufsz);
void ewmh_get_class(Window w, char *buf, size_t bufsz);
int ewmh_get_desktop(Window w); /* -1 = sticky/not set */
void ewmh_get_state_flags(Window w, int *minimized, int *maximized);
Window ewmh_get_active_window(void);
int ewmh_get_number_of_desktops(void);
int ewmh_get_current_desktop(void); /* -1 if unavailable */
int ewmh_skip_taskbar(Window w); /* 1 if a taskbar should never list this window */
int ewmh_window_in_rect(Window w, int rx, int ry, int rw, int rh); /* 1 if w's center is inside the rect */
int ewmh_window_has_input_focus(Window w); /* 1 if w (or a descendant) holds real X input focus */
/* Sets _NET_WM_ICON_GEOMETRY(x,y,w,h) in root coordinates -- tells the WM/
 * compositor where this window's taskbar button is, so minimize/unminimize
 * animations target it instead of the pointer position. */
void ewmh_set_icon_geometry(Window win, int x, int y, int w, int h);
unsigned long ewmh_get_pid(Window w); /* 0 if the window never set _NET_WM_PID */
void ewmh_activate(Window w);
void ewmh_close(Window w);
void ewmh_toggle_maximize(Window w);
void ewmh_toggle_minimize(Window w, int minimized);
void ewmh_move_interactive(Window w, int root_x, int root_y);
cairo_surface_t *ewmh_get_icon_surface(Window w, int target_size); /* NULL if no icon */

/* ---- small drawing helpers built on top of the above (ewmh.c) ---- */
int icon_size_for(int thickness, int padding); /* shared by tasklist/tray's icon_padding= */
void draw_icon_scaled(cairo_t *cr, cairo_surface_t *icon, double x, double y, double size);
void draw_fallback_icon(cairo_t *cr, double x, double y, double size, const char *title, double fg_r, double fg_g,
                         double fg_b, double font_size_px);
void trim_to_width(cairo_t *cr, char *text, size_t bufsz, double max_width);
/* Trims `s` in place back to its last complete UTF-8 codepoint boundary
 * -- call after assembling a string by hand (repeated snprintf() calls
 * into a running offset) in case a write that ran out of room cut the
 * final multi-byte character in half. */
void trim_to_utf8_boundary(char *s);
/* snprintf(dst, dst_sz, "%s", src), but truncates at a UTF-8 codepoint
 * boundary instead of a raw byte offset if src doesn't fit -- use this
 * instead of a plain snprintf("%s", ...) whenever copying already-
 * sanitized UTF-8 text (e.g. a window title) into a *smaller* fixed-size
 * buffer, so cairo_show_text()/cairo_text_extents() never gets handed a
 * string cut mid-codepoint (which permanently poisons the cairo_t --
 * see trim_to_width()'s doc comment in ewmh.c for the real bug this
 * fixes). */
void copy_utf8_truncated(char *dst, size_t dst_sz, const char *src);
/* Resolves a themed icon name (e.g. "folder", or a tray item's IconName)
 * against a fixed grid of common icon-theme paths -- see ewmh.c's doc
 * comment for the tradeoffs. NULL if nothing matched. */
cairo_surface_t *resolve_icon_theme_name(const char *name);

/* ---- context menu (menu.c) ----
 *
 * Generic popup: any widget can open one with its own item list, an
 * opaque ctx pointer, and a selection callback -- the menu code itself
 * doesn't know or care what the items mean. Supports real cascading
 * submenus (separate popup frames, one beside the previous, classic-menu
 * style) via an implicit tree encoded as a flat items[]/depth[] pair --
 * see panel_menu_open_tree() below and menu.c's own header comment for
 * the dismissal (click-outside / Escape / hover-away) design notes. Any
 * frame with more items than fit the output vertically pages instead of
 * overflowing off-screen: up/down arrow rows at its top/bottom edges (dim
 * when there's no previous/next page) jump a whole page at a time, not a
 * continuous scroll -- see menu.c's paint_frame()/frame_row_to_pos(). */
/* Generous on purpose: a whole-tree DBusMenu fetch (globalmenu's
 * mode=closed, or a big app's tray menu) flattens *every* item across
 * *every* level into one array, so a handful of top-level menus with
 * dynamic contents (Recent Documents, a long Bookmarks list, ...) adds up
 * fast even though any single displayed dropdown stays small -- plain
 * ints, so the extra array size costs nothing that matters. */
#define MENU_TREE_MAX_ITEMS 512
typedef struct {
    char label[64];
    int enabled; /* 0 = greyed out, not selectable */
    int is_separator;
} MenuItem;

typedef void (*MenuSelectFn)(Panel *panel, PanelWidget *widget, void *ctx, int index);
/* Called on every pointer motion while any menu frame is grabbing input,
 * with the raw root-relative pointer position -- lets an opener notice
 * "the pointer moved over one of *my* other on-panel buttons" (e.g.
 * globalmenu's open-mode top-level bar, switching which top-level menu
 * is shown without requiring a click) despite the grab routing every
 * event to the first frame's window regardless of what's physically
 * under the pointer. Optional (NULL is fine -- most callers don't need
 * this). */
typedef void (*MenuHoverRootFn)(void *ctx, int root_x, int root_y);
/* Called once, right after the whole menu (every open frame) has closed
 * for any reason (leaf selected, Escape, click/hover-away outside) --
 * g_menu is already gone by the time this fires. Optional (NULL is fine):
 * lets an opener that tracks "which of my own buttons is this menu open
 * for" (e.g. globalmenu's open-mode top-level bar highlight) clear that
 * state instead of it going stale once the menu closes on its own. */
typedef void (*MenuCloseFn)(void *ctx);
/* Called the first time a lazily-marked item (see panel_menu_open_tree_
 * lazy()'s `lazy` array) is actually expanded (hover-delay or click) --
 * `parent_index` is that item's position in the *original* flat `items`
 * array passed to open, same index space `on_select` uses. Fills
 * out_items[]/out_lazy[] (parallel arrays, both sized max_items) with its
 * *immediate* children only (out_lazy[i] = 1 if that child is itself an
 * expand-on-demand container, e.g. a subdirectory) and returns how many,
 * or <=0 if it turns out to have none after all (its arrow disappears).
 * Only called once per item per menu session -- the result is cached in
 * the menu's own item pool for the rest of that session. */
typedef int (*MenuLazyFn)(void *ctx, int parent_index, MenuItem *out_items, int *out_lazy, int max_items);

/* anchor_x/anchor_w: the triggering item's own widget-local [anchor_x,
 * anchor_x+anchor_w) span (e.g. one task's button within tasklist -- a
 * widget with no sub-items just passes its own [0, w->len)). The menu's
 * first (root) frame is positioned glued to the panel's outer edge with
 * its leading edge aligned to the anchor, like plasmashell's taskbar
 * context menus -- *not* at the raw click coordinates. */
void panel_menu_open(Panel *owner_panel, PanelWidget *owner_widget, int anchor_x, int anchor_w, const MenuItem *items,
                      int n_items, void *ctx, MenuSelectFn on_select);
/* Same as panel_menu_open(), but `items`/`depth` together encode an
 * implicit tree instead of one flat level: `depth[i]` is item i's nesting
 * depth (0 = top level), and item i's children are whichever immediately
 * following items have depth[i]+1, up to (not including) the next item
 * at depth <= depth[i] -- the same shape dbusmenu_fetch()'s optional
 * out_depth produces. Hovering an item with children opens its own
 * subtree as a *new* popup frame beside the current one (after
 * owner_panel->tooltip_delay_ms, same open-delay as tooltips); clicking
 * it opens immediately. `on_select`'s index is always the item's position
 * in the original flat `items` array, regardless of which frame it was
 * clicked in. `on_hover_root`/`on_close` are optional, see MenuHoverRootFn/
 * MenuCloseFn above. */
void panel_menu_open_tree(Panel *owner_panel, PanelWidget *owner_widget, int anchor_x, int anchor_w,
                           const MenuItem *items, const int *depth, int n_items, void *ctx, MenuSelectFn on_select,
                           MenuHoverRootFn on_hover_root, MenuCloseFn on_close);
/* Same as panel_menu_open_tree(), plus a `lazy` array (parallel to
 * `items`/`depth`, same length): `lazy[i] = 1` marks item i as having
 * children that aren't in `items` yet and should instead be fetched via
 * `on_lazy` (see MenuLazyFn above) the first time it's actually expanded
 * -- for a tree with no natural bound the way a filesystem has (unlike a
 * DBusMenu tree, which is safely fetched whole in one GetLayout(-1) call
 * -- see dbusmenu.c), eagerly walking the *entire* thing up front is
 * both slow and unbounded. `folder` (widgets/folder.c) uses this to only
 * ever read a directory's contents when its submenu is actually opened,
 * not the whole subtree on the initial click. `on_lazy` may be NULL if
 * every `lazy[i]` is 0 (equivalent to plain panel_menu_open_tree()). */
void panel_menu_open_tree_lazy(Panel *owner_panel, PanelWidget *owner_widget, int anchor_x, int anchor_w,
                                const MenuItem *items, const int *depth, const int *lazy, int n_items, void *ctx,
                                MenuSelectFn on_select, MenuLazyFn on_lazy, MenuHoverRootFn on_hover_root,
                                MenuCloseFn on_close);
void panel_menu_close(void);
/* Returns 1 if `ev` belonged to the open menu (and was fully handled),
 * 0 otherwise -- xispanel.c's event loop dispatches to this first without
 * needing to know anything about the menu's internals. */
int panel_menu_handle_event(const XEvent *ev);
/* Call periodically from the main loop (like tooltip_tick()/
 * tooltip_next_wake_ms()) -- drives the hover-open-submenu and
 * hover-away-closes-everything delays, which are time-based and not
 * necessarily tied to an incoming X event. */
void panel_menu_tick(uint64_t now);
uint64_t panel_menu_next_wake_ms(void);

/* ---- global hotkeys (hotkey.c) ----
 *
 * Lets a widget bind one of its own config_kv options (e.g. folder's
 * `hotkey=<spec>`) to a fixed, code-defined action -- there's no generic
 * "run this shell command" binding, only "which built-in action this
 * particular hotkey triggers" is configurable. `spec` is parsed as
 * `<Mod>+<Mod>+...+<Key>` (any order, case-insensitive modifier names --
 * Ctrl/Control, Alt, Shift, Meta/Super/Win -- last token is a plain X
 * keysym name, e.g. "d", "F5", "space", passed straight to
 * XStringToKeysym()). Call from a widget's ops->init(); the underlying
 * XGrabKey() happens immediately (g_dpy/g_root are already set up by the
 * time any widget's init() runs).
 *
 * `spec` may also be a *bare* modifier name with no '+' and no trailing
 * key (e.g. "Meta") -- fires when that modifier is pressed and released
 * with no other key pressed in between (tap-to-open, like plasmashell's
 * "press Meta to open the launcher"), transparently routed to modtap.c
 * instead of a plain XGrabKey -- see modtap.c's own file comment for why
 * a bare-modifier grab can't just use XGrabKey directly. Falls back to
 * "unavailable, logged, spec ignored" if xispanel was built without the
 * X Record extension (see modtap_stub.c). */
typedef void (*HotkeyFn)(PanelWidget *w);
/* Returns 1 on success, 0 if the spec couldn't be parsed or the grab
 * table is full (logs why either way) -- callers can ignore the return
 * value if a bad hotkey= shouldn't be fatal to the rest of the widget. */
int hotkey_register(PanelWidget *w, const char *spec, HotkeyFn fn);
/* Ungrabs and forgets every hotkey registered for `w` -- call from a
 * widget's ops->destroy() so panel reloads (RELOAD IPC command, RandR
 * hotplug) don't leak grabs or leave stale PanelWidget pointers around. */
void hotkey_unregister_widget(PanelWidget *w);
/* Returns 1 if `ev` was a KeyPress matching a registered hotkey (and its
 * HotkeyFn was invoked), 0 otherwise -- xispanel.c's event loop dispatches
 * to this the same way it does panel_menu_handle_event()/tooltip_handle_
 * event(). */
int hotkey_handle_event(const XEvent *ev);

/* ---- modifier-tap-alone global hotkeys (modtap.c) ----
 *
 * Only called by hotkey.c (widgets never touch this directly -- see
 * hotkey_register()'s doc comment above for the widget-facing bare-
 * modifier hotkey= syntax). Detects "this modifier was pressed and
 * released with no other key press or mouse click in between" --
 * something plain XGrabKey has no way to express (it can only match a
 * fixed keycode+modifier-state combination on press; there's no "and
 * nothing else happened before the matching release" condition).
 * Implemented via the X Record extension: a passive, non-exclusive,
 * whole-display keyboard+button event monitor (a second, dedicated
 * Display connection, since enabling a RECORD context takes over that
 * connection's protocol stream) -- unlike XGrabKey this doesn't claim
 * the modifier's keycode exclusively, so it coexists cleanly with an
 * existing combo using the same modifier (e.g. folder's
 * hotkey=Meta+D): pressing D while the tap-candidate Meta press is
 * pending marks it interrupted, so only the Meta+D grab fires, not the
 * bare-Meta tap; a mouse click while the modifier is held interrupts it
 * the same way. Optional at build time (needs libXtst's
 * Record extension headers) -- modtap_stub.c is the always-unavailable
 * fallback. */
int modtap_init(void); /* call once at startup, right after XOpenDisplay(); returns 1 if available */
int modtap_available(void);
int modtap_register(unsigned int modmask, PanelWidget *w, HotkeyFn fn); /* modmask: Control/Mod1/Shift/Mod4Mask */
void modtap_unregister_widget(PanelWidget *w);
int modtap_fd(void); /* -1 if unavailable -- fold into the main loop's select() readset */
void modtap_process(void); /* call when modtap_fd() is readable */

/* ---- hover tooltip (tooltip.c) ----
 *
 * Purely informational, no pointer/keyboard grab: positioned just outside
 * the panel's own rectangle (below a top panel, above a bottom one, etc.,
 * same convention plasmashell's tooltips use) so it never overlaps a
 * panel widget and doesn't need to handle clicks itself -- the pointer
 * leaving the panel window is all it needs to know to hide. See tooltip.c
 * for the delay/positioning details. */
void tooltip_notice_motion(Panel *p, int axis_pos); /* call on MotionNotify over a panel window */
void tooltip_notice_leave(Panel *p); /* call on LeaveNotify from a panel window */
void tooltip_tick(uint64_t now); /* advance the show-delay timer / refresh shown content */
uint64_t tooltip_next_wake_ms(void); /* 0 = no pending timer, else fold into the main loop's timeout */
void tooltip_close(void); /* hide immediately -- call before invalidating any Panel/PanelWidget */
int tooltip_handle_event(const XEvent *ev); /* 1 if `ev` belonged to the tooltip popup */

/* ---- MPRIS2 media control client (mpris.c) ----
 *
 * Best-effort and entirely optional: libdbus-1 is dlopen()'d at runtime,
 * never linked, so every function here is always safe to call and simply
 * acts as if no player is ever found when the library (or a session bus)
 * isn't available. See mpris.c for why this polls instead of integrating
 * DBus watches into the select() loop. */
void mpris_poll(uint64_t now); /* call periodically from the main loop, e.g. alongside tooltip_tick() */
/* 1 if a player with this PID is currently known, filling *out_busname
 * and *out_playing. */
int mpris_find_for_pid(unsigned long pid, char *out_busname, size_t bufsz, int *out_playing);
void mpris_play_pause(const char *busname);
void mpris_next(const char *busname);
void mpris_previous(const char *busname);

/* ---- system tray: StatusNotifierItem/Watcher client+host (sni.c) ----
 *
 * Same optional-dlopen'd-libdbus-1 philosophy as mpris.c above -- every
 * function here is always safe to call and just reports zero items if
 * libdbus-1 (or a session bus) isn't available. Unlike mpris.c, xispanel
 * also acts as the StatusNotifierWatcher/Host service other processes'
 * tray icons register with (falling back to just reading another
 * process's watcher if one already exists) -- see sni.c for how that's
 * done without pulling DBus watch/timeout objects into the select() loop. */
void sni_poll(uint64_t now); /* call periodically from the main loop */
int sni_count(void);
const char *sni_title(int idx); /* "" if idx out of range */
cairo_surface_t *sni_icon(int idx); /* NULL if unknown/idx out of range */
void sni_activate(int idx, int x, int y); /* left click */
void sni_secondary_activate(int idx, int x, int y); /* middle click */
void sni_context_menu(int idx, int x, int y); /* right click */
/* If the item has a Menu (DBusMenu) property, fetches+flattens its layout
 * and opens it via panel_menu_open(), returning 1 -- the item's own
 * process didn't necessarily implement ContextMenu() at all (many don't,
 * once they set Menu -- see sni.c's DBusMenu client section), so the
 * caller shouldn't fall back to sni_context_menu()/sni_activate() when
 * this returns 1, only when it returns 0 (no Menu property set). */
int sni_menu_open(int idx, Panel *panel, PanelWidget *widget, int anchor_x, int anchor_w);

/* ---- generic com.canonical.dbusmenu client (dbusmenu.c) ----
 *
 * Shared by sni.c (a tray item's Menu property) and, later, the
 * globalmenu widget (_KDE_NET_WM_APPMENU_SERVICE_NAME/_OBJECT_PATH) --
 * this file only knows "a busname+objectpath pointing at a dbusmenu
 * object", not where that pair came from. Same optional-dlopen'd-
 * libdbus-1 philosophy as mpris.c/sni.c, with its own independent
 * session-bus connection (not shared with sni.c's). */
/* Same cap as MENU_TREE_MAX_ITEMS (menu.c's whole-tree fetch buffer) --
 * sni.c's own tray-Menu fetch can hit a large real menu just as easily
 * as globalmenu's whole-tree mode=closed fetch does. */
#define DBUSMENU_MAX_ITEMS MENU_TREE_MAX_ITEMS
/* Fetches GetLayout(parent_id, depth, []) and flattens the returned
 * subtree into out_items[]/out_ids[]/out_depth[] (parallel arrays, all
 * sized max_items) -- out_depth[i] is item i's nesting depth *relative to
 * parent_id* (0 = parent_id's immediate children), the same shape
 * panel_menu_open_tree() (menu.c) consumes to build real cascading
 * submenu popups; out_items[i].label is always the raw, un-indented
 * label (callers that want a single flat display with visual indentation
 * -- e.g. sni.c's tray Menu popup -- add that themselves from out_depth).
 * parent_id=0 means the menu's root; depth=-1 means unlimited (the whole
 * subtree in one call), depth=1 means only parent_id's immediate children
 * (their own children, if any, won't be included -- useful for just
 * listing a menu bar's top-level item labels without pulling in every
 * submenu up front). Returns the number of items flattened (>= 0,
 * possibly 0 for an empty menu), or -1 if libdbus-1/the session bus/the
 * call itself failed. */
int dbusmenu_fetch(const char *busname, const char *path, int32_t parent_id, int32_t depth, MenuItem *out_items,
                    int *out_ids, int *out_depth, int max_items);
/* Fire-and-forget Event(id, "clicked", ...) for one of the ids returned by
 * a prior dbusmenu_fetch() at the same busname/path. */
void dbusmenu_send_event(const char *busname, const char *path, int32_t id);

/* ---- desktop notifications: org.freedesktop.Notifications server (notifd.c) ----
 *
 * Same optional dlopen'd-libdbus-1 philosophy as mpris.c/sni.c. Unlike
 * SNI (which has a real Watcher/Host model letting xispanel attach as a
 * "second host" alongside an existing tray), only one process can ever
 * own org.freedesktop.Notifications at a time -- if something else
 * already does (checked once at startup via NameHasOwner, same check
 * sni.c does for its watcher names), xispanel just stays permanently
 * dormant rather than fighting for it; sni.c's compromise (own more than
 * one, or add together the union of watchers) has no equivalent here.
 *
 * Storage is owned here, not by the widget: a capped in-memory ring
 * buffer (NOTIFD_MAX, oldest evicted) of whatever arrived this session --
 * lost on restart, no on-disk log. A widget only ever reads through the
 * accessors below; it never stores anything of its own. */
#define NOTIFD_SUMMARY_MAX 128
#define NOTIFD_BODY_MAX 256
#define NOTIFD_APP_NAME_MAX 64
typedef struct {
    unsigned int id;
    char app_name[NOTIFD_APP_NAME_MAX];
    char summary[NOTIFD_SUMMARY_MAX];
    char body[NOTIFD_BODY_MAX];
    cairo_surface_t *icon; /* NULL if none/unresolved -- never freed by the caller, owned by notifd.c */
    int read; /* 0 = unread, counts toward notifd_unread_count() */
    uint64_t received_ms;
} NotifEntry;
void notifd_poll(uint64_t now); /* call periodically from the main loop, e.g. alongside sni_poll() */
int notifd_count(void); /* currently held, oldest first */
const NotifEntry *notifd_get(int idx); /* NULL if idx out of range */
int notifd_unread_count(void);
void notifd_mark_read(unsigned int id); /* no-op if id isn't currently held */
/* Optional: called once, right when a new Notify() call is parsed and
 * appended -- lets a toast-popup mechanism react to genuinely new
 * arrivals without polling notifd_count() for changes itself.
 * expire_timeout_ms is the sender's requested display time, already
 * resolved from the protocol's raw -1/0/N semantics (< 0 = server
 * picks a default, 0 = never auto-expire) into a concrete value. */
typedef void (*NotifArrivedFn)(const NotifEntry *e, int expire_timeout_ms);
void notifd_set_arrived_callback(NotifArrivedFn fn);
/* Overrides the ms substituted for a Notify() call that didn't request its
 * own expire_timeout (protocol's "< 0 = server picks a default" case) --
 * widgets/notif.c's timeout= config key. No-op for ms <= 0. Never affects
 * a sender's own explicit expire_timeout request. */
void notifd_set_default_expire_ms(int ms);

/* ---- notification toast popups (toast.c) ----
 *
 * Own floating override-redirect windows, one per visible toast, stacked
 * in a fixed corner of the (default-screen) desktop -- deliberately not
 * built on tooltip.c (informational, no click) or menu.c (takes a pointer
 * grab, single popup at a time): a toast needs neither hover-intent timing
 * nor an input grab, and several can be visible at once. Wired to notifd.c
 * purely via notifd_set_arrived_callback() -- toast.c never polls notifd_
 * count() itself, only ever reacts to genuinely new arrivals. Clicking a
 * toast dismisses it early and marks the underlying notification read
 * (notifd_mark_read()); otherwise it auto-dismisses after its own
 * expire_timeout_ms (0 = never auto-expire, per the Notify() spec). */
void toast_init(void); /* call once at startup, after ewmh_init_atoms() (needs g_atom_wm_window_type*) */
void toast_tick(uint64_t now); /* dismiss expired toasts -- call alongside tooltip_tick()/panel_menu_tick() */
uint64_t toast_next_wake_ms(void); /* 0 = no toast pending expiry, else fold into the main loop's timeout */
int toast_handle_event(const XEvent *ev); /* 1 if `ev` belonged to a toast popup (click-to-dismiss, Expose) */
/* Which screen corner toasts stack from -- one global setting (not
 * per-panel: there's only ever one toast stack, regardless of how many
 * `notif` widgets/panels exist), set by widgets/notif.c's corner=
 * config key from whichever panel/instance last touched it. Default is
 * TOAST_CORNER_BOTTOM_RIGHT. */
typedef enum { TOAST_CORNER_BOTTOM_RIGHT, TOAST_CORNER_BOTTOM_LEFT, TOAST_CORNER_TOP_RIGHT, TOAST_CORNER_TOP_LEFT } ToastCorner;
void toast_set_corner(ToastCorner corner);

/* ---- volume control: shells out to `pactl`, no libpulse linked (pulse.c) ----
 *
 * Unconditionally compiled (no headers/library needed to build this file
 * at all) -- pulse_available() is a runtime-only check for whether the
 * `pactl` binary exists in $PATH, cached after the first call. Every
 * other function here is a no-op / reports failure if it doesn't. */
int pulse_available(void);
/* 1 on success, filling *out_pct (0-100ish, PulseAudio allows >100 with
 * boosted volume) and *out_muted. `sink`/`source` are pactl device
 * names/indices, or the literal "@DEFAULT_SINK@"/"@DEFAULT_SOURCE@". */
int pulse_get_sink_state(const char *sink, int *out_pct, int *out_muted);
int pulse_get_source_state(const char *source, int *out_pct, int *out_muted);
void pulse_set_sink_volume_relative(const char *sink, int delta_pct); /* delta_pct may be negative */
void pulse_toggle_sink_mute(const char *sink);

/* ---- live window thumbnails: XComposite, no libpulse-style dlopen (thumb.c) ----
 *
 * Unlike mpris.c/sni.c's runtime dlopen(), there's no equivalent trick for
 * an X extension (it's used over the already-open X connection, not a
 * separate shared library) -- so this is a normal build-time-optional
 * dependency instead: if libXcomposite wasn't found via pkg-config,
 * thumb_stub.c is linked and thumb_available() always reports false. */
int thumb_available(void); /* 1 if libXcomposite was built in AND a compositor is currently running */
/* Draws win's live contents scaled to fit within [x,y,max_w,max_h]
 * (preserving aspect ratio, never upscaled past the window's real size,
 * centered in any leftover space), returns 1 if it painted anything. */
int thumb_paint(cairo_t *cr, Window win, double x, double y, double max_w, double max_h);
/* Live-thumbnail change tracking via XDamage -- see thumb.c's file
 * comment. tooltip.c calls thumb_watch() for every window a shown
 * tooltip currently displays a thumbnail of (idempotent -- a window
 * already being watched is a no-op), and thumb_unwatch_all() once that
 * set changes or the tooltip closes. */
void thumb_watch(Window win);
void thumb_unwatch_all(void);
/* Returns 1 if `ev` was an XDamage notification (for a watched window or
 * a just-unwatched one -- consumed either way, to keep the server from
 * queuing more), same dispatch-chain pattern as panel_menu_handle_event()/
 * tooltip_handle_event(). */
int thumb_handle_event(const XEvent *ev);
/* Returns 1 (and clears) if any watched window has been damaged since
 * the last call -- tooltip_tick() polls this once per main-loop
 * iteration to decide whether to repaint a shown thumbnail. */
int thumb_take_dirty(void);

/* ---- widget registry: each file under widgets/ defines one of these --- */
extern const PanelWidgetOps spacer_ops;
extern const PanelWidgetOps clock_ops;
extern const PanelWidgetOps tasklist_ops;
extern const PanelWidgetOps winctl_ops;
extern const PanelWidgetOps tray_ops;
extern const PanelWidgetOps launcher_ops;
extern const PanelWidgetOps volume_ops;
extern const PanelWidgetOps globalmenu_ops;
extern const PanelWidgetOps folder_ops;
extern const PanelWidgetOps xisserve_ops;
extern const PanelWidgetOps notif_ops;

#endif
