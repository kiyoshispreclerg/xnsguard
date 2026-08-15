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

    /* theme */
    double bg_r, bg_g, bg_b, bg_a;
    double fg_r, fg_g, fg_b, fg_a;
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

/* ---- small helpers widgets rely on (xispanel.c) ---- */
uint64_t now_ms(void);
int kv_get(const char *kvline, const char *key, char *out, size_t outsz);
int kv_get_int(const char *kvline, const char *key, int defval);
/* Real window-space rectangle for a widget, accounting for panel
 * orientation (horizontal panels lay widgets out along x, vertical panels
 * along y). */
void widget_get_rect(const PanelWidget *w, int *x, int *y, int *width, int *height);
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
                         double fg_b);
void trim_to_width(cairo_t *cr, char *text, size_t bufsz, double max_width);

/* ---- context menu (menu.c) ----
 *
 * Generic popup: any widget can open one with its own item list, an
 * opaque ctx pointer, and a selection callback -- the menu code itself
 * doesn't know or care what the items mean. See menu.c for the dismissal
 * (click-outside / Escape) design notes. */
typedef struct {
    char label[64];
    int enabled; /* 0 = greyed out, not selectable */
    int is_separator;
} MenuItem;

typedef void (*MenuSelectFn)(Panel *panel, PanelWidget *widget, void *ctx, int index);

/* anchor_x/anchor_w: the triggering item's own widget-local [anchor_x,
 * anchor_x+anchor_w) span (e.g. one task's button within tasklist -- a
 * widget with no sub-items just passes its own [0, w->len)). The menu is
 * positioned glued to the panel's outer edge with its leading edge
 * aligned to the anchor, like plasmashell's taskbar context menus --
 * *not* at the raw click coordinates. */
void panel_menu_open(Panel *owner_panel, PanelWidget *owner_widget, int anchor_x, int anchor_w, const MenuItem *items,
                      int n_items, void *ctx, MenuSelectFn on_select);
void panel_menu_close(void);
/* Returns 1 if `ev` belonged to the open menu (and was fully handled),
 * 0 otherwise -- xispanel.c's event loop dispatches to this first without
 * needing to know anything about the menu's internals. */
int panel_menu_handle_event(const XEvent *ev);

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

/* ---- widget registry: each file under widgets/ defines one of these --- */
extern const PanelWidgetOps spacer_ops;
extern const PanelWidgetOps clock_ops;
extern const PanelWidgetOps tasklist_ops;
extern const PanelWidgetOps winctl_ops;
extern const PanelWidgetOps tray_ops;
extern const PanelWidgetOps launcher_ops;
extern const PanelWidgetOps volume_ops;

#endif
