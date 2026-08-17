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

#include <limits.h>
#include <stdio.h>
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
cairo_surface_t *resolve_icon_theme_name(const char *name)
{
    if (!name || !name[0]) {
        return NULL;
    }
    if (name[0] == '/') {
        return load_png_argb(name);
    }
    static const char *bases[] = {
        "/usr/share/icons/breeze",
        "/usr/share/icons/breeze-dark",
        "/usr/share/icons/Adwaita",
        "/usr/share/icons/hicolor",
    };
    static const char *categories[] = {"status", "apps", "devices", "actions", "categories", "mimetypes", "places"};
    static const char *sizedirs[] = {"symbolic", "scalable", "48x48", "32x32", "24x24", "22x22", "16x16"};
    static const char *exts[] = {".svg", ".png"};
    char path[PATH_MAX];
    for (size_t b = 0; b < sizeof(bases) / sizeof(bases[0]); b++) {
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
    /* Flat fallback, no theme structure at all. */
    static const char *exts2[] = {".png", ".svg", ".xpm"};
    for (size_t e = 0; e < sizeof(exts2) / sizeof(exts2[0]); e++) {
        snprintf(path, sizeof(path), "/usr/share/pixmaps/%s%s", name, exts2[e]);
        cairo_surface_t *surf = access(path, R_OK) == 0 ? load_png_argb(path) : NULL;
        if (surf) {
            return surf;
        }
    }
    return NULL;
}
