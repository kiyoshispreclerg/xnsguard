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
     * split evenly among every greedy widget in the same panel. */
    void (*measure)(PanelWidget *w, int cross_axis, int *out_len);
    void (*paint)(PanelWidget *w, cairo_t *cr);
    /* root_x/root_y: screen-absolute click position, for widgets that pop
     * up a context menu (panel_menu_open() takes screen coordinates). */
    int (*on_button)(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y);
    void (*on_tick)(PanelWidget *w, uint64_t now);
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

    /* theme */
    double bg_r, bg_g, bg_b, bg_a;
    double fg_r, fg_g, fg_b, fg_a;
    int spacing;

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

/* ---- WM-type / strut atoms widgets/menu may need (ewmh.c) ---- */
extern Atom g_atom_wm_window_type;
extern Atom g_atom_wm_window_type_dock;
extern Atom g_atom_wm_window_type_popup_menu;
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
void ewmh_activate(Window w);
void ewmh_close(Window w);
void ewmh_toggle_maximize(Window w);
void ewmh_toggle_minimize(Window w, int minimized);
void ewmh_move_interactive(Window w, int root_x, int root_y);
cairo_surface_t *ewmh_get_icon_surface(Window w, int target_size); /* NULL if no icon */

/* ---- small drawing helpers built on top of the above (ewmh.c) ---- */
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

void panel_menu_open(Panel *owner_panel, PanelWidget *owner_widget, int screen_x, int screen_y, const MenuItem *items,
                      int n_items, void *ctx, MenuSelectFn on_select);
void panel_menu_close(void);
/* Returns 1 if `ev` belonged to the open menu (and was fully handled),
 * 0 otherwise -- xispanel.c's event loop dispatches to this first without
 * needing to know anything about the menu's internals. */
int panel_menu_handle_event(const XEvent *ev);

/* ---- widget registry: each file under widgets/ defines one of these --- */
extern const PanelWidgetOps spacer_ops;
extern const PanelWidgetOps clock_ops;
extern const PanelWidgetOps tasklist_ops;

#endif
