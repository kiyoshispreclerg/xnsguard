/*
 * ewmh.c - EWMH/ICCCM client-list reading and window-control actions,
 * plus the icon-fetching/drawing helpers built on top of _NET_WM_ICON.
 *
 * Everything here is read-only queries or one-shot client messages sent
 * to the root window / target window -- no state of its own beyond the
 * interned atoms, so any widget can call into this freely.
 */
#include "xispanel.h"

#include <X11/Xatom.h>
#include <X11/Xutil.h>

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

Atom g_atom_wm_window_type;
Atom g_atom_wm_window_type_dock;
Atom g_atom_wm_window_type_popup_menu;
Atom g_atom_wm_window_type_tooltip;
Atom g_atom_wm_strut;
Atom g_atom_wm_strut_partial;

static Atom g_atom_net_client_list;
static Atom g_atom_net_wm_name;
static Atom g_atom_utf8_string;
static Atom g_atom_net_wm_desktop;
static Atom g_atom_net_wm_pid;
static Atom g_atom_net_wm_state;
static Atom g_atom_net_wm_state_hidden;
static Atom g_atom_net_wm_state_maximized_vert;
static Atom g_atom_net_wm_state_maximized_horz;
static Atom g_atom_net_active_window;
static Atom g_atom_net_close_window;
static Atom g_atom_net_wm_icon;
static Atom g_atom_net_wm_moveresize;
static Atom g_atom_net_number_of_desktops;
static Atom g_atom_net_current_desktop;
static Atom g_atom_wm_state; /* ICCCM WM_STATE, distinct from _NET_WM_STATE */
static Atom g_atom_wm_change_state;
static Atom g_atom_net_wm_state_skip_taskbar;
static Atom g_atom_net_wm_window_type_desktop;
static Atom g_atom_net_wm_icon_geometry;

#define ICON_PROP_MAX_LONGS 200000

void ewmh_init_atoms(void)
{
    g_atom_wm_window_type = XInternAtom(g_dpy, "_NET_WM_WINDOW_TYPE", False);
    g_atom_wm_window_type_dock = XInternAtom(g_dpy, "_NET_WM_WINDOW_TYPE_DOCK", False);
    g_atom_wm_window_type_popup_menu = XInternAtom(g_dpy, "_NET_WM_WINDOW_TYPE_POPUP_MENU", False);
    g_atom_wm_window_type_tooltip = XInternAtom(g_dpy, "_NET_WM_WINDOW_TYPE_TOOLTIP", False);
    g_atom_wm_strut = XInternAtom(g_dpy, "_NET_WM_STRUT", False);
    g_atom_wm_strut_partial = XInternAtom(g_dpy, "_NET_WM_STRUT_PARTIAL", False);

    g_atom_net_client_list = XInternAtom(g_dpy, "_NET_CLIENT_LIST", False);
    g_atom_net_wm_name = XInternAtom(g_dpy, "_NET_WM_NAME", False);
    g_atom_utf8_string = XInternAtom(g_dpy, "UTF8_STRING", False);
    g_atom_net_wm_desktop = XInternAtom(g_dpy, "_NET_WM_DESKTOP", False);
    g_atom_net_wm_pid = XInternAtom(g_dpy, "_NET_WM_PID", False);
    g_atom_net_wm_state = XInternAtom(g_dpy, "_NET_WM_STATE", False);
    g_atom_net_wm_state_hidden = XInternAtom(g_dpy, "_NET_WM_STATE_HIDDEN", False);
    g_atom_net_wm_state_maximized_vert = XInternAtom(g_dpy, "_NET_WM_STATE_MAXIMIZED_VERT", False);
    g_atom_net_wm_state_maximized_horz = XInternAtom(g_dpy, "_NET_WM_STATE_MAXIMIZED_HORZ", False);
    g_atom_net_active_window = XInternAtom(g_dpy, "_NET_ACTIVE_WINDOW", False);
    g_atom_net_close_window = XInternAtom(g_dpy, "_NET_CLOSE_WINDOW", False);
    g_atom_net_wm_icon = XInternAtom(g_dpy, "_NET_WM_ICON", False);
    g_atom_net_wm_moveresize = XInternAtom(g_dpy, "_NET_WM_MOVERESIZE", False);
    g_atom_net_number_of_desktops = XInternAtom(g_dpy, "_NET_NUMBER_OF_DESKTOPS", False);
    g_atom_net_current_desktop = XInternAtom(g_dpy, "_NET_CURRENT_DESKTOP", False);
    g_atom_wm_state = XInternAtom(g_dpy, "WM_STATE", False);
    g_atom_wm_change_state = XInternAtom(g_dpy, "WM_CHANGE_STATE", False);
    g_atom_net_wm_state_skip_taskbar = XInternAtom(g_dpy, "_NET_WM_STATE_SKIP_TASKBAR", False);
    g_atom_net_wm_window_type_desktop = XInternAtom(g_dpy, "_NET_WM_WINDOW_TYPE_DESKTOP", False);
    g_atom_net_wm_icon_geometry = XInternAtom(g_dpy, "_NET_WM_ICON_GEOMETRY", False);
}

/* Tells the window manager/compositor where this task's taskbar button is
 * on screen, in root coordinates -- the same property KWin/Compiz/etc.
 * already read to decide where a minimize/iconify animation should end
 * (and an unminimize animation should start from), instead of defaulting
 * to the pointer position. Cheap enough to call on every tasklist repaint
 * (~800ms tick cadence): a handful of 4-CARDINAL ChangeProperty calls. */
void ewmh_set_icon_geometry(Window win, int x, int y, int w, int h)
{
    long geom[4] = {x, y, w, h};
    XChangeProperty(g_dpy, win, g_atom_net_wm_icon_geometry, XA_CARDINAL, 32, PropModeReplace,
                     (unsigned char *)geom, 4);
}

/* Windows a taskbar should never list: desktop/dock window types (KDE's
 * own desktop containment layer and any other panel/dock, including
 * xispanel's own panel windows before they're filtered by class), or
 * anything explicitly asking to be skipped via _NET_WM_STATE_SKIP_TASKBAR. */
int ewmh_skip_taskbar(Window w)
{
    Atom actual_type;
    int actual_format;
    unsigned long n_items, bytes_after;
    unsigned char *prop = NULL;

    if (XGetWindowProperty(g_dpy, w, g_atom_wm_window_type, 0, 16, False, XA_ATOM, &actual_type, &actual_format,
                            &n_items, &bytes_after, &prop) == Success &&
        prop) {
        Atom *atoms = (Atom *)(void *)prop;
        for (unsigned long i = 0; i < n_items; i++) {
            if (atoms[i] == g_atom_net_wm_window_type_desktop || atoms[i] == g_atom_wm_window_type_dock) {
                XFree(prop);
                return 1;
            }
        }
        XFree(prop);
    }

    prop = NULL;
    if (XGetWindowProperty(g_dpy, w, g_atom_net_wm_state, 0, 32, False, XA_ATOM, &actual_type, &actual_format,
                            &n_items, &bytes_after, &prop) == Success &&
        prop) {
        Atom *atoms = (Atom *)(void *)prop;
        for (unsigned long i = 0; i < n_items; i++) {
            if (atoms[i] == g_atom_net_wm_state_skip_taskbar) {
                XFree(prop);
                return 1;
            }
        }
        XFree(prop);
    }

    return 0;
}

int ewmh_get_client_list(Window **out_list, int *out_n)
{
    Atom actual_type;
    int actual_format;
    unsigned long n_items, bytes_after;
    unsigned char *prop = NULL;
    int status = XGetWindowProperty(g_dpy, g_root, g_atom_net_client_list, 0, 4096, False, XA_WINDOW, &actual_type,
                                     &actual_format, &n_items, &bytes_after, &prop);
    if (status != Success || !prop || actual_type != XA_WINDOW) {
        if (prop) {
            XFree(prop);
        }
        *out_list = NULL;
        *out_n = 0;
        return 0;
    }
    *out_list = (Window *)(void *)prop;
    *out_n = (int)n_items;
    return 1;
}

/* Cairo's text functions hard-fail (poisoning the whole cairo_t with
 * CAIRO_STATUS_INVALID_STRING, silently no-op'ing every draw call after
 * it, including unrelated widgets painted later in the same repaint) on
 * invalid UTF-8. _NET_WM_NAME is supposed to always be UTF8_STRING, but
 * the ICCCM WM_NAME fallback (XGetWMName) is locale-encoded and commonly
 * isn't -- replace anything that doesn't decode cleanly with '?' rather
 * than trust window-supplied text to already be well-formed. */
static void sanitize_utf8(char *s)
{
    unsigned char *p = (unsigned char *)s;
    while (*p) {
        unsigned char c = *p;
        int extra;
        if (c < 0x80) {
            extra = 0;
        } else if ((c & 0xE0) == 0xC0) {
            extra = 1;
        } else if ((c & 0xF0) == 0xE0) {
            extra = 2;
        } else if ((c & 0xF8) == 0xF0) {
            extra = 3;
        } else {
            *p = '?';
            p++;
            continue;
        }
        int ok = 1;
        for (int i = 1; i <= extra; i++) {
            if ((p[i] & 0xC0) != 0x80) {
                ok = 0;
                break;
            }
        }
        if (!ok) {
            *p = '?';
            p++;
            continue;
        }
        p += extra + 1;
    }
}

void ewmh_get_title(Window w, char *buf, size_t bufsz)
{
    buf[0] = 0;
    Atom actual_type;
    int actual_format;
    unsigned long n_items, bytes_after;
    unsigned char *prop = NULL;
    if (XGetWindowProperty(g_dpy, w, g_atom_net_wm_name, 0, 1024, False, g_atom_utf8_string, &actual_type,
                            &actual_format, &n_items, &bytes_after, &prop) == Success &&
        prop) {
        if (actual_type == g_atom_utf8_string && n_items > 0) {
            size_t len = n_items < bufsz - 1 ? n_items : bufsz - 1;
            memcpy(buf, prop, len);
            buf[len] = 0;
        }
        XFree(prop);
    }
    if (!buf[0]) {
        XTextProperty tp;
        if (XGetWMName(g_dpy, w, &tp) && tp.value) {
            size_t len = strlen((char *)tp.value);
            if (len >= bufsz) {
                len = bufsz - 1;
            }
            memcpy(buf, tp.value, len);
            buf[len] = 0;
            XFree(tp.value);
        }
    }
    sanitize_utf8(buf);
}

void ewmh_get_class(Window w, char *buf, size_t bufsz)
{
    buf[0] = 0;
    XClassHint ch;
    ch.res_name = NULL;
    ch.res_class = NULL;
    if (XGetClassHint(g_dpy, w, &ch)) {
        if (ch.res_class) {
            snprintf(buf, bufsz, "%s", ch.res_class);
            XFree(ch.res_class);
        }
        if (ch.res_name) {
            XFree(ch.res_name);
        }
    }
}

int ewmh_get_desktop(Window w)
{
    Atom actual_type;
    int actual_format;
    unsigned long n_items, bytes_after;
    unsigned char *prop = NULL;
    int desktop = -1;
    if (XGetWindowProperty(g_dpy, w, g_atom_net_wm_desktop, 0, 1, False, XA_CARDINAL, &actual_type, &actual_format,
                            &n_items, &bytes_after, &prop) == Success &&
        prop) {
        if (n_items > 0) {
            long val = *(long *)(void *)prop;
            desktop = (val == 0xFFFFFFFFL) ? -1 : (int)val;
        }
        XFree(prop);
    }
    return desktop;
}

/* 0 if the window never set _NET_WM_PID (not every app does). Used to
 * match a taskbar window to an MPRIS player owning the same PID -- see
 * mpris.c. */
unsigned long ewmh_get_pid(Window w)
{
    Atom actual_type;
    int actual_format;
    unsigned long n_items, bytes_after;
    unsigned char *prop = NULL;
    unsigned long pid = 0;
    if (XGetWindowProperty(g_dpy, w, g_atom_net_wm_pid, 0, 1, False, XA_CARDINAL, &actual_type, &actual_format,
                            &n_items, &bytes_after, &prop) == Success &&
        prop) {
        if (n_items > 0) {
            pid = *(unsigned long *)(void *)prop;
        }
        XFree(prop);
    }
    return pid;
}

void ewmh_get_state_flags(Window w, int *minimized, int *maximized)
{
    *minimized = 0;
    *maximized = 0;

    /* ICCCM WM_STATE: IconicState means minimized -- more universally
     * respected than _NET_WM_STATE_HIDDEN, which not every WM sets. */
    Atom actual_type;
    int actual_format;
    unsigned long n_items, bytes_after;
    unsigned char *prop = NULL;
    if (XGetWindowProperty(g_dpy, w, g_atom_wm_state, 0, 2, False, g_atom_wm_state, &actual_type, &actual_format,
                            &n_items, &bytes_after, &prop) == Success &&
        prop) {
        if (n_items > 0 && *(long *)(void *)prop == IconicState) {
            *minimized = 1;
        }
        XFree(prop);
    }

    prop = NULL;
    if (XGetWindowProperty(g_dpy, w, g_atom_net_wm_state, 0, 32, False, XA_ATOM, &actual_type, &actual_format,
                            &n_items, &bytes_after, &prop) == Success &&
        prop) {
        Atom *atoms = (Atom *)(void *)prop;
        int has_vert = 0, has_horz = 0;
        for (unsigned long i = 0; i < n_items; i++) {
            if (atoms[i] == g_atom_net_wm_state_hidden) {
                *minimized = 1;
            }
            if (atoms[i] == g_atom_net_wm_state_maximized_vert) {
                has_vert = 1;
            }
            if (atoms[i] == g_atom_net_wm_state_maximized_horz) {
                has_horz = 1;
            }
        }
        *maximized = has_vert && has_horz;
        XFree(prop);
    }
}

/* 1 if `w` (or a descendant of it, e.g. an app's internal focus proxy
 * window -- Qt/GTK sometimes focus a child rather than the toplevel EWMH
 * clients enumerate) currently holds real X input focus, as opposed to
 * merely being _NET_ACTIVE_WINDOW -- some WMs leave the latter pointing
 * at the last active client even after focus moves to the root window
 * (e.g. after clicking the desktop), which globalmenu's focused_only
 * filter uses to tell that apart. */
int ewmh_window_has_input_focus(Window w)
{
    if (w == None) {
        return 0;
    }
    Window focused;
    int revert_to;
    XGetInputFocus(g_dpy, &focused, &revert_to);
    if (focused == None || focused == PointerRoot) {
        return 0;
    }
    while (focused != None) {
        if (focused == w) {
            return 1;
        }
        Window root_ret, parent_ret, *children = NULL;
        unsigned int n_children = 0;
        if (!XQueryTree(g_dpy, focused, &root_ret, &parent_ret, &children, &n_children)) {
            break;
        }
        if (children) {
            XFree(children);
        }
        if (parent_ret == root_ret || parent_ret == None) {
            break;
        }
        focused = parent_ret;
    }
    return 0;
}

/* 1 if `w`'s center falls within the given root-relative rectangle --
 * used to filter tasklist/winctl entries to whatever output the panel
 * itself is resolved onto (Panel::out_x/y/w/h), for multi-monitor
 * same_output filtering. Returns 1 (never filters) if the window's
 * geometry can't be queried, e.g. it closed between listing and here. */
int ewmh_window_in_rect(Window w, int rx, int ry, int rw, int rh)
{
    XWindowAttributes wa;
    if (!XGetWindowAttributes(g_dpy, w, &wa)) {
        return 1;
    }
    Window child;
    int abs_x, abs_y;
    if (!XTranslateCoordinates(g_dpy, w, g_root, 0, 0, &abs_x, &abs_y, &child)) {
        return 1;
    }
    int cx = abs_x + wa.width / 2;
    int cy = abs_y + wa.height / 2;
    return cx >= rx && cx < rx + rw && cy >= ry && cy < ry + rh;
}

Window ewmh_get_active_window(void)
{
    Atom actual_type;
    int actual_format;
    unsigned long n_items, bytes_after;
    unsigned char *prop = NULL;
    Window w = None;
    if (XGetWindowProperty(g_dpy, g_root, g_atom_net_active_window, 0, 1, False, XA_WINDOW, &actual_type,
                            &actual_format, &n_items, &bytes_after, &prop) == Success &&
        prop) {
        if (n_items > 0) {
            w = *(Window *)(void *)prop;
        }
        XFree(prop);
    }
    return w;
}

int ewmh_get_number_of_desktops(void)
{
    Atom actual_type;
    int actual_format;
    unsigned long n_items, bytes_after;
    unsigned char *prop = NULL;
    int n = 1;
    if (XGetWindowProperty(g_dpy, g_root, g_atom_net_number_of_desktops, 0, 1, False, XA_CARDINAL, &actual_type,
                            &actual_format, &n_items, &bytes_after, &prop) == Success &&
        prop) {
        if (n_items > 0) {
            n = (int)*(long *)(void *)prop;
        }
        XFree(prop);
    }
    return n;
}

/* -1 if unavailable (some very minimal WM not setting it) -- callers
 * should treat that as "don't filter by desktop", not "desktop -1". */
int ewmh_get_current_desktop(void)
{
    Atom actual_type;
    int actual_format;
    unsigned long n_items, bytes_after;
    unsigned char *prop = NULL;
    int desktop = -1;
    if (XGetWindowProperty(g_dpy, g_root, g_atom_net_current_desktop, 0, 1, False, XA_CARDINAL, &actual_type,
                            &actual_format, &n_items, &bytes_after, &prop) == Success &&
        prop) {
        if (n_items > 0) {
            desktop = (int)*(long *)(void *)prop;
        }
        XFree(prop);
    }
    return desktop;
}

/* --- event-driven property watching (see the doc comments in xispanel.h) ---
 *
 * Selects PropertyChangeMask on the root window (for _NET_ACTIVE_WINDOW/
 * _NET_CLIENT_LIST/_NET_CURRENT_DESKTOP/_NET_NUMBER_OF_DESKTOPS) and on
 * every client-list window (for _NET_WM_STATE/WM_STATE/_NET_WM_NAME/
 * WM_NAME -- title and max/min state, which live on the windows
 * themselves, not the root). Lets the main loop re-poll the polling
 * widgets (tasklist/winctl/globalmenu) the instant one of these changes
 * instead of only catching it on the slow fallback tick. */
void ewmh_watch_windows(void)
{
    Window *list = NULL;
    int n = 0;
    if (!ewmh_get_client_list(&list, &n)) {
        return;
    }
    for (int i = 0; i < n; i++) {
        /* XSelectInput *replaces* this client's whole event mask on the
         * window, it doesn't OR -- so blindly selecting PropertyChangeMask
         * would wipe any mask we already have there. That matters for our
         * own dock-mode panel windows, which are WM-managed and so appear
         * in _NET_CLIENT_LIST: clobbering their ButtonPress/Motion/Enter/
         * Leave mask down to just PropertyChangeMask killed every panel
         * click (regression fixed here). Preserve the existing mask and
         * add PropertyChangeMask to it. XGetWindowAttributes().your_event_
         * mask is exactly *this* client's current mask on the window (0
         * for another app's window we've never touched). A window
         * destroyed in between just yields a BadWindow the global error
         * handler ignores; skip it if the fetch failed. */
        XWindowAttributes wa;
        if (XGetWindowAttributes(g_dpy, list[i], &wa)) {
            XSelectInput(g_dpy, list[i], wa.your_event_mask | PropertyChangeMask);
        }
    }
    XFree(list);
}

void ewmh_watch_init(void)
{
    /* PropertyChangeMask: the root properties above. SubstructureNotifyMask:
     * ConfigureNotify for top-level windows, the only signal for a window
     * changing *output* (which has no property of its own -- it's derived
     * from geometry vs the RandR layout). SubstructureNotifyMask is freely
     * shared (unlike SubstructureRedirectMask, which only the WM holds), so
     * selecting it here doesn't disturb the window manager. See the
     * ConfigureNotify handling in xispanel.c (debounced, since a drag emits
     * a continuous stream of them). */
    XSelectInput(g_dpy, g_root, PropertyChangeMask | SubstructureNotifyMask);
    ewmh_watch_windows();
}

int ewmh_property_event_is_relevant(const XPropertyEvent *ev, int *out_client_list_changed)
{
    if (out_client_list_changed) {
        *out_client_list_changed = 0;
    }
    Atom a = ev->atom;
    if (ev->window == g_root) {
        if (a == g_atom_net_client_list) {
            if (out_client_list_changed) {
                *out_client_list_changed = 1;
            }
            return 1;
        }
        return a == g_atom_net_active_window || a == g_atom_net_current_desktop ||
               a == g_atom_net_number_of_desktops;
    }
    /* A watched client window: title, max/min-state, or which virtual
     * desktop it's on (_NET_WM_DESKTOP -- tasklist's same_desktop filter
     * and desktop badge, winctl/globalmenu's same_desktop filter). Which
     * *output* a window is on has no property to watch -- it's derived
     * from the window's geometry against the RandR layout, so an output
     * change arrives as a ConfigureNotify, not a PropertyNotify; see the
     * SubstructureNotify handling in xispanel.c. */
    return a == g_atom_net_wm_state || a == g_atom_wm_state || a == g_atom_net_wm_name || a == XA_WM_NAME ||
           a == g_atom_net_wm_desktop;
}

static void ewmh_send_client_message(Window w, Atom message_type, long l0, long l1, long l2, long l3, long l4)
{
    XEvent ev;
    memset(&ev, 0, sizeof(ev));
    ev.xclient.type = ClientMessage;
    ev.xclient.window = w;
    ev.xclient.message_type = message_type;
    ev.xclient.format = 32;
    ev.xclient.data.l[0] = l0;
    ev.xclient.data.l[1] = l1;
    ev.xclient.data.l[2] = l2;
    ev.xclient.data.l[3] = l3;
    ev.xclient.data.l[4] = l4;
    XSendEvent(g_dpy, g_root, False, SubstructureRedirectMask | SubstructureNotifyMask, &ev);
}

/* source indication 2 = "pager or other tool", per the EWMH spec. */
void ewmh_activate(Window w)
{
    ewmh_send_client_message(w, g_atom_net_active_window, 2, CurrentTime, 0, 0, 0);
}

void ewmh_close(Window w)
{
    ewmh_send_client_message(w, g_atom_net_close_window, CurrentTime, 2, 0, 0, 0);
}

/* action: 0=remove, 1=add, 2=toggle (_NET_WM_STATE_TOGGLE). */
static void ewmh_set_state(Window w, Atom prop1, Atom prop2, int action)
{
    ewmh_send_client_message(w, g_atom_net_wm_state, action, (long)prop1, (long)prop2, 1, 0);
}

void ewmh_toggle_maximize(Window w)
{
    ewmh_set_state(w, g_atom_net_wm_state_maximized_vert, g_atom_net_wm_state_maximized_horz, 2);
}

void ewmh_toggle_minimize(Window w, int minimized)
{
    if (minimized) {
        /* No EWMH client message un-minimizes a window directly; every WM
         * treats "activate" as "show + focus", which implicitly restores
         * an iconified window too -- that's the portable way panels/
         * taskbars do this. */
        ewmh_activate(w);
    } else {
        /* ICCCM WM_CHANGE_STATE(IconicState): minimize request. */
        ewmh_send_client_message(w, g_atom_wm_change_state, IconicState, 0, 0, 0, 0);
    }
}

/* Hands off to the window manager's own interactive move (mouse-driven,
 * exactly like dragging a titlebar) via _NET_WM_MOVERESIZE -- xispanel has
 * no drag/resize logic of its own, nor does it need any. */
void ewmh_move_interactive(Window w, int root_x, int root_y)
{
    ewmh_send_client_message(w, g_atom_net_wm_moveresize, root_x, root_y, 8 /* _NET_WM_MOVERESIZE_MOVE */, Button1, 2);
}

/* _NET_WM_ICON is a CARDINAL array of concatenated [w,h,pixels...]
 * entries, each pixel a packed 32-bit non-premultiplied ARGB value.
 * Picks the smallest available icon that's still >= target_size (avoids
 * upscaling a tiny icon when a bigger one exists), falling back to the
 * largest available if none is big enough. Returns NULL if the window has
 * no icon property at all -- callers should fall back to a drawn
 * placeholder, not treat that as an error. */
cairo_surface_t *ewmh_get_icon_surface(Window w, int target_size)
{
    Atom actual_type;
    int actual_format;
    unsigned long n_items, bytes_after;
    unsigned char *prop = NULL;
    if (XGetWindowProperty(g_dpy, w, g_atom_net_wm_icon, 0, ICON_PROP_MAX_LONGS, False, XA_CARDINAL, &actual_type,
                            &actual_format, &n_items, &bytes_after, &prop) != Success ||
        !prop) {
        if (prop) {
            XFree(prop);
        }
        return NULL;
    }
    /* Xlib packs format-32 properties as an array of `long` regardless of
     * the platform's actual CARDINAL width -- but only if the property
     * really *is* format 32. A buggy client publishing _NET_WM_ICON with
     * some other format would make every offset below meaningless (and,
     * left unchecked, could produce a bogus width/height large enough to
     * push cairo_image_surface_create() into an error surface that then
     * poisons every cairo_t it's later used as a source on). */
    if (actual_format != 32 || actual_type != XA_CARDINAL) {
        XFree(prop);
        return NULL;
    }

    long *data = (long *)(void *)prop;
    unsigned long offset = 0;
    long best_w = 0, best_h = 0;
    unsigned long best_offset = 0;
    while (offset + 2 <= n_items) {
        long iw = data[offset], ih = data[offset + 1];
        /* Sanity cap: no real desktop icon is anywhere near this large --
         * reject anything that big rather than risk an oversized/invalid
         * cairo image surface from a malformed property. */
        if (iw <= 0 || ih <= 0 || iw > 1024 || ih > 1024 || offset + 2 + (unsigned long)(iw * ih) > n_items) {
            break;
        }
        int is_better;
        if (best_w == 0) {
            is_better = 1;
        } else if (best_w < target_size) {
            is_better = (iw > best_w);
        } else {
            is_better = (iw >= target_size && iw < best_w);
        }
        if (is_better) {
            best_w = iw;
            best_h = ih;
            best_offset = offset;
        }
        offset += 2 + (unsigned long)(iw * ih);
    }
    if (best_w <= 0) {
        XFree(prop);
        return NULL;
    }

    cairo_surface_t *surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, (int)best_w, (int)best_h);
    if (cairo_surface_status(surf) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(surf);
        XFree(prop);
        return NULL;
    }
    unsigned char *dst = cairo_image_surface_get_data(surf);
    int stride = cairo_image_surface_get_stride(surf);
    for (long y = 0; y < best_h; y++) {
        uint32_t *row = (uint32_t *)(void *)(dst + y * stride);
        for (long x = 0; x < best_w; x++) {
            uint32_t argb = (uint32_t)data[best_offset + 2 + (unsigned long)(y * best_w + x)];
            uint8_t a = (uint8_t)((argb >> 24) & 0xff);
            uint8_t r = (uint8_t)((argb >> 16) & 0xff);
            uint8_t g = (uint8_t)((argb >> 8) & 0xff);
            uint8_t b = (uint8_t)(argb & 0xff);
            /* Cairo's ARGB32 image format requires premultiplied alpha;
             * _NET_WM_ICON is straight (non-premultiplied). */
            r = (uint8_t)((r * a) / 255);
            g = (uint8_t)((g * a) / 255);
            b = (uint8_t)((b * a) / 255);
            row[x] = ((uint32_t)a << 24) | ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
        }
    }
    cairo_surface_mark_dirty(surf);
    XFree(prop);
    return surf;
}

/* icon_padding=0 (default, for whichever widget's config exposes this)
 * fills the whole available thickness, matching every widget's original
 * hardcoded icon sizing; a positive value shrinks the icon by that many
 * pixels on every side instead, for users who want a smaller icon with
 * visible breathing room around it. Floors at 4px so a very large
 * padding relative to a thin panel can't produce a zero/negative icon.
 * Shared by tasklist and tray rather than duplicated per widget. */
int icon_size_for(int thickness, int padding)
{
    int size = thickness - 2 * padding;
    return size > 4 ? size : 4;
}

void draw_icon_scaled(cairo_t *cr, cairo_surface_t *icon, double x, double y, double size)
{
    if (!icon || cairo_surface_status(icon) != CAIRO_STATUS_SUCCESS) {
        return;
    }
    int iw = cairo_image_surface_get_width(icon);
    int ih = cairo_image_surface_get_height(icon);
    if (iw <= 0 || ih <= 0) {
        return;
    }
    double scale = size / (double)(iw > ih ? iw : ih);
    cairo_save(cr);
    cairo_translate(cr, x + (size - iw * scale) / 2.0, y + (size - ih * scale) / 2.0);
    cairo_scale(cr, scale, scale);
    cairo_set_source_surface(cr, icon, 0, 0);
    cairo_paint(cr);
    cairo_restore(cr);
}

/* Cheap placeholder for windows with no _NET_WM_ICON: a translucent
 * square with the title's first letter. Avoids leaving a blank gap in
 * the taskbar rather than trying to source a real icon (freedesktop
 * icon-theme resolution by WM_CLASS is future launcher-phase territory). */
/* Copies the first UTF-8 *codepoint* of `s` (not just its first byte,
 * which for anything outside ASCII is only a fragment of one and would
 * itself be invalid UTF-8 -- title is already sanitize_utf8()'d by the
 * time it gets here, but a leading multi-byte character is still valid
 * UTF-8 that a naive single-byte copy would break). Falls back to '?' if
 * `s` is empty or the leading byte doesn't look like a valid UTF-8 start. */
static void first_utf8_char(const char *s, char *out, size_t outsz)
{
    out[0] = '?';
    out[1] = 0;
    if (!s || !s[0] || outsz < 2) {
        return;
    }
    unsigned char c = (unsigned char)s[0];
    int len = 1;
    if ((c & 0xE0) == 0xC0) {
        len = 2;
    } else if ((c & 0xF0) == 0xE0) {
        len = 3;
    } else if ((c & 0xF8) == 0xF0) {
        len = 4;
    }
    if ((size_t)len >= outsz) {
        return;
    }
    for (int i = 0; i < len; i++) {
        if (!s[i]) {
            return; /* string shorter than the sequence claimed -- keep '?' */
        }
    }
    memcpy(out, s, (size_t)len);
    out[len] = 0;
}

void draw_fallback_icon(cairo_t *cr, double x, double y, double size, const char *title, double fg_r, double fg_g,
                         double fg_b, double font_size_px)
{
    cairo_save(cr);
    cairo_set_source_rgba(cr, fg_r, fg_g, fg_b, 0.22);
    cairo_rectangle(cr, x, y, size, size);
    cairo_fill(cr);
    char letter[8];
    first_utf8_char(title, letter, sizeof(letter));
    cairo_set_source_rgba(cr, fg_r, fg_g, fg_b, 0.9);
    double tw;
    pango_text_extents_ellipsized(cr, letter, font_size_px, 0, &tw, NULL);
    pango_show_text_boxed(cr, x + (size - tw) / 2.0, y, size, 0, font_size_px, letter, NULL);
    cairo_restore(cr);
}

/* Backs `len` up to the start of the UTF-8 codepoint it's currently
 * inside of (or already at the start of), by skipping past continuation
 * bytes (10xxxxxx) -- shared by trim_to_width() below and by
 * trim_to_utf8_boundary()/copy_utf8_truncated(). */
static size_t back_up_to_codepoint(const char *text, size_t len)
{
    while (len > 0 && ((unsigned char)text[len] & 0xC0) == 0x80) {
        len--;
    }
    return len;
}

/* Trims `s` in place back to its last complete UTF-8 codepoint boundary
 * -- for a buffer assembled by hand (e.g. repeated snprintf() calls into
 * a running offset, or a plain "%s" snprintf into a smaller buffer) where
 * a write that ran out of room could have cut the final multi-byte
 * character in half, silently leaving invalid UTF-8 that would poison a
 * cairo_t the next time it's drawn.
 *
 * Deliberately not built on back_up_to_codepoint() above: that helper
 * always drops the *entire* codepoint straddling a given cut position
 * (the right behavior for trim_to_width(), which is intentionally
 * shortening the string one whole character at a time). Here we only
 * want to drop a *trailing* codepoint if it's actually incomplete --
 * dropping a perfectly valid last character just because the buffer
 * happened to end exactly there would be wrong. So this walks back to
 * the last codepoint's own lead byte, works out how many bytes that
 * lead byte says the codepoint should be, and only truncates if fewer
 * than that many bytes actually made it into the buffer. */
void trim_to_utf8_boundary(char *s)
{
    size_t len = strlen(s);
    if (len == 0) {
        return;
    }
    size_t lead = len - 1;
    while (lead > 0 && ((unsigned char)s[lead] & 0xC0) == 0x80) {
        lead--;
    }
    unsigned char c = (unsigned char)s[lead];
    size_t expected;
    if (c < 0x80) {
        expected = 1;
    } else if ((c & 0xE0) == 0xC0) {
        expected = 2;
    } else if ((c & 0xF0) == 0xE0) {
        expected = 3;
    } else if ((c & 0xF8) == 0xF0) {
        expected = 4;
    } else {
        expected = 1; /* not a valid lead byte at all -- drop it too */
    }
    if (len - lead < expected) {
        s[lead] = 0;
    }
}

/* Same as snprintf(dst, dst_sz, "%s", src), but if src has to be cut to
 * fit, cuts at a UTF-8 codepoint boundary instead of a raw byte offset --
 * a plain "%s" snprintf can slice a multi-byte character in half. This is
 * the fix for a real bug: window titles are already sanitized to valid
 * UTF-8 by the time they reach a widget (see sanitize_utf8() above), but
 * copying one into a *smaller* fixed-size stack buffer with a plain
 * snprintf (e.g. tasklist's per-button label, copied from a 128-byte
 * title into a smaller on-stack scratch buffer) can still truncate mid-
 * codepoint -- easy to hit with dense multi-byte text (a long CJK window
 * title was the real-world trigger) even though pure-ASCII titles never
 * come close to it. */
void copy_utf8_truncated(char *dst, size_t dst_sz, const char *src)
{
    if (dst_sz == 0) {
        return;
    }
    snprintf(dst, dst_sz, "%s", src);
    trim_to_utf8_boundary(dst);
}

/* Trims `text` in place (respecting `bufsz`) and appends an ellipsis
 * until it fits within max_width at cr's current font. */
void trim_to_width(cairo_t *cr, char *text, size_t bufsz, double max_width)
{
    cairo_text_extents_t ext;
    cairo_text_extents(cr, text, &ext);
    if (max_width <= 0 || ext.x_advance <= max_width) {
        return;
    }
    /* Reserve room for the 3-byte ellipsis (U+2026 is \xe2\x80\xa6) plus
     * its NUL inside `bufsz` up front, so neither snprintf below can ever
     * need to truncate -- previously the ellipsis was appended into a
     * fixed-size local scratch buffer and then copied back with a plain
     * "%s" snprintf, both byte-oriented cuts with no UTF-8 awareness: a
     * `text` long enough to land within 3 bytes of the buffer's end (easy
     * with dense multi-byte text -- a long Japanese window title was the
     * real-world trigger) could have the ellipsis itself sliced in half,
     * handing cairo_text_extents()/cairo_show_text() invalid UTF-8 and
     * poisoning the whole cairo_t for every draw call after it. */
    size_t len = strlen(text);
    size_t max_len = bufsz > 4 ? bufsz - 4 : 0;
    if (len > max_len) {
        len = back_up_to_codepoint(text, max_len);
        text[len] = 0;
    }
    while (len > 0) {
        len--;
        /* Don't stop mid-codepoint: back up past any UTF-8 continuation
         * bytes too, so we never truncate to an incomplete multi-byte
         * sequence -- cairo_text_extents() below would reject that as
         * invalid UTF-8 and poison `cr` for every draw after it, not
         * just this one. */
        len = back_up_to_codepoint(text, len);
        text[len] = 0;
        char trimmed[256];
        snprintf(trimmed, sizeof(trimmed), "%s\xe2\x80\xa6", text); /* U+2026 HORIZONTAL ELLIPSIS */
        cairo_text_extents(cr, trimmed, &ext);
        if (ext.x_advance <= max_width) {
            /* Always fits: len <= bufsz-4, plus the 3-byte ellipsis and a
             * NUL is at most bufsz bytes. */
            snprintf(text, bufsz, "%s", trimmed);
            return;
        }
    }
    text[0] = 0;
}

/* Some icon sources give only a themed name (e.g. a tray item's IconName,
 * or a well-known name like "folder") meant to be resolved via the
 * freedesktop icon theme spec (index.theme parsing, per-size subdirs,
 * theme inheritance...). Full spec compliance is deliberately out of
 * scope (see the original project plan's icon_theme.c note), so this is
 * an intentionally unsophisticated stand-in: generate a fixed grid of
 * candidate paths (theme base x category x size-or-"symbolic"/"scalable"
 * x extension) and load the first hit via load_png_argb() (Imlib2,
 * already linked -- no new dependency), rather than a real recursive/
 * spec-aware search (which risks a synchronous multi-thousand-file
 * directory walk on the main thread the first time an icon needs
 * resolving -- a real stall risk on a theme with a large icon set,
 * unacceptable for what only saves a fallback letter icon from showing).
 * Themes disagree on directory order -- breeze nests size *under*
 * category (".../devices/symbolic/name.svg"), Adwaita/hicolor nest
 * category *under* size (".../scalable/devices/name.svg", confirmed
 * against both live) -- so both orderings are tried. Good enough to turn
 * a blank/fallback icon into a real one for the common case; finds
 * nothing for an icon this grid doesn't happen to cover, degrading back
 * to the fallback icon exactly like an absent pixmap already does. Also
 * handles the (seen in the wild) case of a caller passing an absolute
 * path as `name` directly. */
/* Reads the desktop's configured icon theme name the same live-off-config
 * way xispanel.c's detect_system_font_family()/detect_system_colors()
 * read font/color -- KDE's ~/.config/kdeglobals ([Icons] Theme=) checked
 * first, then GTK3's ~/.config/gtk-3.0/settings.ini
 * (gtk-icon-theme-name=). Without this, resolve_icon_theme_name() below
 * only ever finds icons on the handful of hardcoded theme names it
 * happens to list -- a user on Papirus/Yaru/Numix/elementary/... would
 * never get a resolved icon at all. Leaves `out` empty (caller just
 * skips the extra search root) if neither config file has the key. */
static void detect_icon_theme(char *out, size_t outsz)
{
    out[0] = 0;
    const char *home = getenv("HOME");
    if (!home) {
        return;
    }
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/.config/kdeglobals", home);
    FILE *f = fopen(path, "r");
    if (f) {
        char line[256];
        int in_icons = 0;
        while (fgets(line, sizeof(line), f)) {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = 0;
            }
            if (line[0] == '[') {
                in_icons = strcmp(line, "[Icons]") == 0;
                continue;
            }
            if (in_icons && !strncmp(line, "Theme=", 6)) {
                snprintf(out, outsz, "%s", line + 6);
                break;
            }
        }
        fclose(f);
        if (out[0]) {
            return;
        }
    }
    snprintf(path, sizeof(path), "%s/.config/gtk-3.0/settings.ini", home);
    f = fopen(path, "r");
    if (!f) {
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = 0;
        }
        if (!strncmp(line, "gtk-icon-theme-name=", 20)) {
            snprintf(out, outsz, "%s", line + 20);
            break;
        }
    }
    fclose(f);
}

cairo_surface_t *resolve_icon_theme_name(const char *name)
{
    if (!name || !name[0]) {
        return NULL;
    }
    if (name[0] == '/') {
        return load_png_argb(name);
    }

    /* The user's actual icon theme (if detected) is searched first, ahead
     * of the hardcoded breeze/Adwaita/hicolor fallback list -- built at
     * runtime instead of a compile-time array since the theme name/home
     * dir aren't known until now. Deliberately capped/deduped rather than
     * walking a theme's full index.theme Inherits= chain -- see this
     * function's original doc comment on why full spec compliance is out
     * of scope. */
    char theme[128];
    detect_icon_theme(theme, sizeof(theme));
    const char *home = getenv("HOME");

    char base_buf[7][PATH_MAX];
    const char *bases[7];
    int n_bases = 0;
    if (theme[0]) {
        snprintf(base_buf[n_bases], PATH_MAX, "/usr/share/icons/%s", theme);
        bases[n_bases] = base_buf[n_bases];
        n_bases++;
        if (home) {
            snprintf(base_buf[n_bases], PATH_MAX, "%s/.local/share/icons/%s", home, theme);
            bases[n_bases] = base_buf[n_bases];
            n_bases++;
            snprintf(base_buf[n_bases], PATH_MAX, "%s/.icons/%s", home, theme);
            bases[n_bases] = base_buf[n_bases];
            n_bases++;
        }
    }
    static const char *hardcoded[] = {
        "/usr/share/icons/breeze",
        "/usr/share/icons/breeze-dark",
        "/usr/share/icons/Adwaita",
        "/usr/share/icons/hicolor",
    };
    for (size_t i = 0; i < sizeof(hardcoded) / sizeof(hardcoded[0]) && n_bases < 7; i++) {
        int dup = 0;
        for (int j = 0; j < n_bases; j++) {
            if (strcmp(bases[j], hardcoded[i]) == 0) {
                dup = 1;
                break;
            }
        }
        if (!dup) {
            bases[n_bases++] = hardcoded[i];
        }
    }

    /* "legacy" matters: some icon names from the freedesktop spec's
     * legacy list (e.g. konsole's Icon=utilities-terminal) only exist
     * there in Adwaita/hicolor, not under "apps" -- confirmed against a
     * live install (Adwaita/48x48/legacy/utilities-terminal.png exists,
     * .../apps/utilities-terminal.png doesn't; only a *-symbolic variant
     * does, a different filename that wouldn't match `name` anyway). */
    static const char *categories[] = {"status",     "apps",  "devices", "actions",
                                        "categories", "mimetypes", "places",  "legacy"};
    /* Both naming conventions are real: Adwaita/hicolor use "48x48" per
     * the icon-theme spec, but breeze/KDE themes use a bare "48" (plus
     * "@2x"/"@3x" HiDPI variants this doesn't bother with) -- confirmed
     * against a live breeze install (.../apps/48/kcolorchooser.svg, not
     * .../apps/48x48/...). Trying both forms for every theme is cheap
     * (just extra access() misses) and avoids needing to know which
     * convention a given theme uses ahead of time. 128/256/512 cover
     * hicolor-only apps that never ship a "scalable" SVG (confirmed:
     * OBS Studio's hicolor entry is 128x128/256x256/512x512 PNGs plus a
     * scalable SVG, no smaller sizes at all). */
    static const char *sizedirs[] = {"symbolic", "scalable", "48x48",   "48",  "32x32",   "32",     "24x24",
                                      "24",       "22x22",    "22",      "16x16", "16",   "64x64",  "64",
                                      "128x128",  "128",      "256x256", "256", "512x512", "512"};
    /* .png before .svg: Imlib2's SVG support depends on an optional
     * loader plugin (librsvg-backed) that isn't guaranteed to be
     * installed -- confirmed on a live system where imlib_load_image()
     * silently fails on every .svg (breeze ships nothing else, so this
     * alone made konsole/kate unresolvable before the "legacy" fix
     * above gave Adwaita's PNG a chance to be tried at all). Trying .png
     * first costs nothing when only one extension exists in a given
     * directory, and wins outright when both do. */
    static const char *exts[] = {".png", ".svg"};
    char path[PATH_MAX];
    for (int b = 0; b < n_bases; b++) {
        for (size_t c = 0; c < sizeof(categories) / sizeof(categories[0]); c++) {
            for (size_t s = 0; s < sizeof(sizedirs) / sizeof(sizedirs[0]); s++) {
                for (size_t e = 0; e < sizeof(exts) / sizeof(exts[0]); e++) {
                    /* breeze order: <category>/<sizedir>/<name> */
                    snprintf(path, sizeof(path), "%s/%s/%s/%s%s", bases[b], categories[c], sizedirs[s], name,
                             exts[e]);
                    cairo_surface_t *surf = access(path, R_OK) == 0 ? load_png_argb(path) : NULL;
                    if (surf) {
                        return surf;
                    }
                    /* Adwaita/hicolor order: <sizedir>/<category>/<name> */
                    snprintf(path, sizeof(path), "%s/%s/%s/%s%s", bases[b], sizedirs[s], categories[c], name,
                             exts[e]);
                    surf = access(path, R_OK) == 0 ? load_png_argb(path) : NULL;
                    if (surf) {
                        return surf;
                    }
                }
            }
        }
    }
    /* Flat fallback, no theme structure at all -- /usr/local/share/pixmaps
     * matters for anything installed outside the distro package manager
     * (confirmed: a manually-installed Anki only ships
     * /usr/local/share/pixmaps/anki.png, nothing under /usr/share at
     * all). */
    static const char *pixmap_dirs[] = {"/usr/share/pixmaps", "/usr/local/share/pixmaps"};
    static const char *exts2[] = {".png", ".svg", ".xpm"};
    for (size_t d = 0; d < sizeof(pixmap_dirs) / sizeof(pixmap_dirs[0]); d++) {
        for (size_t e = 0; e < sizeof(exts2) / sizeof(exts2[0]); e++) {
            snprintf(path, sizeof(path), "%s/%s%s", pixmap_dirs[d], name, exts2[e]);
            cairo_surface_t *surf = access(path, R_OK) == 0 ? load_png_argb(path) : NULL;
            if (surf) {
                return surf;
            }
        }
    }
    return NULL;
}

/* Removes freedesktop Exec= field codes (%f/%F/%u/%U/%d/%D/%n/%N/%i/%c/%k/
 * %v/%m) in place -- xispanel never hands a launched app a file/URL/icon-
 * name argument, so every one of these is just deleted rather than
 * substituted. "%%" (a literal percent) collapses to "%". Any other
 * %<char> (not part of the spec) is left alone rather than guessed at. */
static void strip_desktop_field_codes(char *s)
{
    char out[512];
    size_t oi = 0;
    for (size_t i = 0; s[i] && oi + 1 < sizeof(out); i++) {
        if (s[i] == '%' && s[i + 1]) {
            char c = s[i + 1];
            if (c == '%') {
                out[oi++] = '%';
                i++;
                continue;
            }
            if (strchr("fFuUdDnNickvm", c)) {
                i++; /* drop both the '%' and the code letter */
                continue;
            }
        }
        out[oi++] = s[i];
    }
    out[oi] = 0;
    snprintf(s, 512, "%s", out);
}

/* Parses one .desktop file at `path`, filling out_name/out_exec/out_icon
 * (Exec= with field codes already stripped) if it looks usable (has an
 * Exec=, isn't Hidden=true) and matches `wm_class` -- see
 * desktop_entry_find_by_wm_class()'s doc comment for the match rules.
 * Returns 0 (no match/unusable), 1 (fallback match: basename or Exec
 * basename), or 2 (best match: exact StartupWMClass=). Only reads the
 * [Desktop Entry] section, stopping at the first following [...] header
 * so a file's [Desktop Action ...] subsections never leak into the
 * result. */
static int parse_desktop_file(const char *path, const char *wm_class, char *out_name, size_t name_sz,
                               char *out_exec, size_t exec_sz, char *out_icon, size_t icon_sz)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        return 0;
    }
    char line[1024];
    int in_entry = 0, seen_entry = 0, hidden = 0;
    char name[256] = "", exec[512] = "", icon[256] = "", startup_class[128] = "";
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = 0;
        }
        if (line[0] == '[') {
            in_entry = strcmp(line, "[Desktop Entry]") == 0;
            if (in_entry) {
                seen_entry = 1;
            } else if (seen_entry) {
                break; /* left the main section after having read it */
            }
            continue;
        }
        if (!in_entry) {
            continue;
        }
        if (!strncmp(line, "Name=", 5) && !name[0]) {
            snprintf(name, sizeof(name), "%s", line + 5);
        } else if (!strncmp(line, "Exec=", 5)) {
            snprintf(exec, sizeof(exec), "%s", line + 5);
        } else if (!strncmp(line, "Icon=", 5)) {
            snprintf(icon, sizeof(icon), "%s", line + 5);
        } else if (!strncmp(line, "StartupWMClass=", 15)) {
            snprintf(startup_class, sizeof(startup_class), "%s", line + 15);
        } else if (!strcmp(line, "Hidden=true")) {
            hidden = 1;
        }
    }
    fclose(f);
    if (hidden || !exec[0]) {
        return 0;
    }

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    char basenoext[256];
    snprintf(basenoext, sizeof(basenoext), "%s", base);
    char *dot = strrchr(basenoext, '.');
    if (dot) {
        *dot = 0;
    }

    int match = 0;
    if (startup_class[0] && strcmp(startup_class, wm_class) == 0) {
        match = 2;
    } else {
        char exec_base[256];
        snprintf(exec_base, sizeof(exec_base), "%s", exec);
        char *sp = strchr(exec_base, ' ');
        if (sp) {
            *sp = 0;
        }
        const char *exec_bin = strrchr(exec_base, '/');
        exec_bin = exec_bin ? exec_bin + 1 : exec_base;
        if (strcasecmp(basenoext, wm_class) == 0 || strcasecmp(exec_bin, wm_class) == 0) {
            match = 1;
        }
    }
    if (!match) {
        return 0;
    }

    strip_desktop_field_codes(exec);
    if (out_name && name_sz) {
        snprintf(out_name, name_sz, "%s", name[0] ? name : basenoext);
    }
    if (out_exec && exec_sz) {
        snprintf(out_exec, exec_sz, "%s", exec);
    }
    if (out_icon && icon_sz) {
        snprintf(out_icon, icon_sz, "%s", icon);
    }
    return match;
}

/* Appends "<base>/applications" to dirs[*n] (silently capped at `max` --
 * a caller passing more search roots than that just loses the excess,
 * fine for what's already a generous fixed list). */
static void add_desktop_search_dir(char dirs[][PATH_MAX], int *n, int max, const char *base)
{
    if (*n >= max || !base || !base[0]) {
        return;
    }
    snprintf(dirs[*n], PATH_MAX, "%s/applications", base);
    (*n)++;
}

/* Searches .desktop files under XDG_DATA_HOME (or ~/.local/share) and
 * every XDG_DATA_DIRS entry (falling back to /usr/local/share:/usr/share
 * if unset, per the freedesktop base-dir spec defaults) for the entry
 * that best matches `wm_class` (a window's WM_CLASS res_class, as
 * returned by ewmh_get_class()). An exact StartupWMClass= match wins
 * outright and stops the search; otherwise the first file whose own
 * basename (sans .desktop) or Exec='s first-token basename matches
 * case-insensitively is kept as a fallback candidate, same heuristic
 * KDE's own Task Manager applet falls back to when no StartupWMClass is
 * known (see tasklist.c's tasklist_build_display() doc comment) -- used
 * only if no exact match turns up anywhere.
 *
 * Deliberately not a full .desktop/icon-theme implementation (no
 * NoDisplay/OnlyShowIn filtering, no localized Name[xx]= keys, non-
 * recursive directory scan) -- just enough to name/launch/icon a pinned
 * app (tasklist.c's "Fixar") or fill in a real running window's icon
 * when _NET_WM_ICON didn't supply one (some GTK/Electron apps only set
 * an icon via WM_CLASS + the icon theme, never _NET_WM_ICON pixel data).
 * out_name/out_exec/out_icon_name are each optional (pass NULL/0 to skip);
 * out_exec has field codes already stripped (see
 * strip_desktop_field_codes()). Returns 1 on any match, 0 if nothing
 * matched anywhere. */
int desktop_entry_find_by_wm_class(const char *wm_class, char *out_name, size_t name_sz, char *out_exec,
                                    size_t exec_sz, char *out_icon_name, size_t icon_sz)
{
    if (!wm_class || !wm_class[0]) {
        return 0;
    }

    char dirs[16][PATH_MAX];
    int n_dirs = 0;
    const char *xdg_data_home = getenv("XDG_DATA_HOME");
    if (xdg_data_home && xdg_data_home[0]) {
        add_desktop_search_dir(dirs, &n_dirs, 16, xdg_data_home);
    } else {
        const char *home = getenv("HOME");
        if (home && home[0]) {
            char buf[PATH_MAX];
            snprintf(buf, sizeof(buf), "%s/.local/share", home);
            add_desktop_search_dir(dirs, &n_dirs, 16, buf);
        }
    }
    const char *xdg_data_dirs = getenv("XDG_DATA_DIRS");
    if (!xdg_data_dirs || !xdg_data_dirs[0]) {
        xdg_data_dirs = "/usr/local/share:/usr/share";
    }
    char ddbuf[1024];
    snprintf(ddbuf, sizeof(ddbuf), "%s", xdg_data_dirs);
    char *save = NULL;
    for (char *tok = strtok_r(ddbuf, ":", &save); tok; tok = strtok_r(NULL, ":", &save)) {
        add_desktop_search_dir(dirs, &n_dirs, 16, tok);
    }

    char fb_name[256] = "", fb_exec[512] = "", fb_icon[256] = "";
    int have_fallback = 0;

    for (int d = 0; d < n_dirs; d++) {
        DIR *dh = opendir(dirs[d]);
        if (!dh) {
            continue;
        }
        struct dirent *de;
        while ((de = readdir(dh)) != NULL) {
            size_t nlen = strlen(de->d_name);
            if (nlen < 9 || strcmp(de->d_name + nlen - 8, ".desktop") != 0) {
                continue;
            }
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", dirs[d], de->d_name);
            char name[256], exec[512], icon[256];
            int m = parse_desktop_file(path, wm_class, name, sizeof(name), exec, sizeof(exec), icon, sizeof(icon));
            if (m == 2) {
                closedir(dh);
                if (out_name && name_sz) {
                    snprintf(out_name, name_sz, "%s", name);
                }
                if (out_exec && exec_sz) {
                    snprintf(out_exec, exec_sz, "%s", exec);
                }
                if (out_icon_name && icon_sz) {
                    snprintf(out_icon_name, icon_sz, "%s", icon);
                }
                return 1;
            }
            if (m == 1 && !have_fallback) {
                have_fallback = 1;
                snprintf(fb_name, sizeof(fb_name), "%s", name);
                snprintf(fb_exec, sizeof(fb_exec), "%s", exec);
                snprintf(fb_icon, sizeof(fb_icon), "%s", icon);
            }
        }
        closedir(dh);
    }

    if (!have_fallback) {
        return 0;
    }
    if (out_name && name_sz) {
        snprintf(out_name, name_sz, "%s", fb_name);
    }
    if (out_exec && exec_sz) {
        snprintf(out_exec, exec_sz, "%s", fb_exec);
    }
    if (out_icon_name && icon_sz) {
        snprintf(out_icon_name, icon_sz, "%s", fb_icon);
    }
    return 1;
}
