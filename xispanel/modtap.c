/*
 * modtap.c - "tap this modifier alone" global hotkey detection, via the
 * X Record extension. See the doc comment on modtap_register() in
 * xispanel.h for why plain XGrabKey can't express this and how this
 * avoids conflicting with a real Mod+key combo bound elsewhere (e.g.
 * folder's hotkey=Meta+D).
 *
 * X Record is a passive, non-exclusive monitor of the *entire* display's
 * protocol stream (every client's key/button/etc events, not just this
 * process's own window) -- enabling a context takes over its Display
 * connection's protocol stream, so it needs a second, dedicated
 * connection separate from g_dpy (opened here, never touched by any
 * other file). XRecordEnableContextAsync + XRecordProcessReplies is the
 * non-blocking pairing meant for exactly this kind of external event
 * loop (as opposed to XRecordEnableContext, which blocks the calling
 * thread until XRecordDisableContext is called from yet another
 * connection) -- xispanel.c folds modtap_fd() into its own select() call
 * and calls modtap_process() when it's readable, the same shape as the
 * main X connection itself.
 *
 * The intercepted data is raw core X11 protocol bytes (not Xlib XEvent
 * structs) -- decoded here via <X11/Xproto.h>'s xEvent, the same wire
 * struct Xlib itself unpacks XEvent from. client_swapped (the recording
 * client and the event's originating client disagreeing on byte order)
 * is vanishingly unlikely on a local single-arch X session and is simply
 * skipped rather than handled, consistent with this codebase's general
 * "best-effort, not a fatal condition" approach to X edge cases.
 */
#include "xispanel.h"

#include <X11/Xlib.h>
#include <X11/Xproto.h>
#include <X11/extensions/record.h>

#include <stdio.h>
#include <string.h>

#define MODTAP_MAX 16

typedef struct {
    unsigned int modmask;
    PanelWidget *w;
    HotkeyFn fn;
} ModTapEntry;

static ModTapEntry g_taps[MODTAP_MAX];
static int g_n_taps = 0;

static Display *g_rec_dpy;
static XRecordContext g_rec_ctx;
static int g_available = 0;

/* Which modifier (if any) is the current tap candidate -- i.e. its own
 * key went down while no other key was held -- and whether anything has
 * interrupted it (any other key press) since. 0 = no candidate. */
static unsigned int g_candidate_mask = 0;
static int g_interrupted = 0;

/* Same technique hotkey.c's numlock_mask() uses (query the modifier
 * map), generalized to any modifier instead of just Num_Lock. */
static unsigned int keycode_to_modmask(KeyCode kc)
{
    XModifierKeymap *map = XGetModifierMapping(g_dpy);
    if (!map) {
        return 0;
    }
    unsigned int result = 0;
    for (int mod = 0; mod < 8; mod++) {
        for (int k = 0; k < map->max_keypermod; k++) {
            if (map->modifiermap[mod * map->max_keypermod + k] == kc) {
                result = 1u << mod;
            }
        }
    }
    XFreeModifiermap(map);
    return result;
}

static void fire_taps(unsigned int modmask)
{
    for (int i = 0; i < g_n_taps; i++) {
        if (g_taps[i].modmask == modmask && g_taps[i].fn) {
            g_taps[i].fn(g_taps[i].w);
        }
    }
}

static void record_callback(XPointer closure, XRecordInterceptData *data)
{
    (void)closure;
    if (data->category != XRecordFromServer || data->client_swapped) {
        XRecordFreeData(data);
        return;
    }
    xEvent *ev = (xEvent *)data->data;
    int type = ev->u.u.type & 0x7f; /* strip the "sent from another client" bit */
    if (type == KeyPress || type == KeyRelease) {
        KeyCode kc = (KeyCode)ev->u.u.detail;
        unsigned int mm = keycode_to_modmask(kc);
        if (type == KeyPress) {
            if (mm && g_candidate_mask == 0) {
                g_candidate_mask = mm;
                g_interrupted = 0;
            } else {
                /* Any other key press -- including a second, different
                 * modifier -- while a candidate is pending interrupts
                 * it. This is what keeps a bare-Meta tap from also
                 * firing when the user actually presses Meta+D. */
                g_interrupted = 1;
            }
        } else if (mm && mm == g_candidate_mask) {
            if (!g_interrupted) {
                fire_taps(mm);
            }
            g_candidate_mask = 0;
            g_interrupted = 0;
        }
    }
    XRecordFreeData(data);
}

int modtap_init(void)
{
    int major, minor;
    if (!XRecordQueryVersion(g_dpy, &major, &minor)) {
        fprintf(stderr, "xispanel: modtap: X server has no Record extension, bare-modifier hotkeys disabled\n");
        return 0;
    }
    g_rec_dpy = XOpenDisplay(NULL);
    if (!g_rec_dpy) {
        return 0;
    }
    XRecordRange *range = XRecordAllocRange();
    if (!range) {
        XCloseDisplay(g_rec_dpy);
        g_rec_dpy = NULL;
        return 0;
    }
    memset(range, 0, sizeof(*range));
    range->device_events.first = KeyPress;
    range->device_events.last = KeyRelease;
    XRecordClientSpec spec = XRecordAllClients;
    XRecordRange *ranges[1] = {range};
    /* Both the context and its enable call must happen on the *same*
     * connection (g_rec_dpy, not g_dpy) -- a RECORD context's resource ID
     * isn't valid when referenced from a different client connection, so
     * creating it on g_dpy and enabling it on g_rec_dpy fails with
     * XRecordBadContext. g_rec_dpy is dedicated to this alone; every
     * other X call in the process still goes through g_dpy as usual. */
    g_rec_ctx = XRecordCreateContext(g_rec_dpy, 0, &spec, 1, ranges, 1);
    XFree(range);
    if (!g_rec_ctx) {
        XCloseDisplay(g_rec_dpy);
        g_rec_dpy = NULL;
        return 0;
    }
    if (!XRecordEnableContextAsync(g_rec_dpy, g_rec_ctx, record_callback, NULL)) {
        XRecordFreeContext(g_rec_dpy, g_rec_ctx);
        XCloseDisplay(g_rec_dpy);
        g_rec_dpy = NULL;
        return 0;
    }
    XFlush(g_rec_dpy);
    g_available = 1;
    return 1;
}

int modtap_available(void)
{
    return g_available;
}

int modtap_register(unsigned int modmask, PanelWidget *w, HotkeyFn fn)
{
    if (!g_available) {
        fprintf(stderr, "xispanel: hotkey: bare-modifier hotkey needs the X Record extension, which isn't "
                        "available -- ignoring\n");
        return 0;
    }
    if (g_n_taps >= MODTAP_MAX) {
        fprintf(stderr, "xispanel: hotkey: too many modifier-tap hotkeys registered, ignoring one\n");
        return 0;
    }
    ModTapEntry *e = &g_taps[g_n_taps++];
    e->modmask = modmask;
    e->w = w;
    e->fn = fn;
    return 1;
}

void modtap_unregister_widget(PanelWidget *w)
{
    for (int i = 0; i < g_n_taps;) {
        if (g_taps[i].w == w) {
            g_taps[i] = g_taps[g_n_taps - 1];
            g_n_taps--;
        } else {
            i++;
        }
    }
}

int modtap_fd(void)
{
    return g_available ? ConnectionNumber(g_rec_dpy) : -1;
}

void modtap_process(void)
{
    if (g_available) {
        XRecordProcessReplies(g_rec_dpy);
    }
}
