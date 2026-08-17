/*
 * hotkey.c - global keyboard shortcuts, grabbed on the root window via
 * XGrabKey, dispatched to a fixed code-defined action per widget.
 *
 * There is no user-programmable action here on purpose (see the doc
 * comment on HotkeyFn in xispanel.h): a widget offers a hotkey=<spec>
 * config option that triggers whatever that widget's own code already
 * does for a click, nothing more general. This file only owns
 * spec-string parsing, the grab table, and dispatching KeyPress events
 * from the main loop to the right widget's callback.
 */
#include "xispanel.h"

#include <X11/Xlib.h>
#include <X11/keysym.h>

#include <stdio.h>
#include <string.h>

#define HOTKEY_MAX 64

typedef struct {
    PanelWidget *w;
    HotkeyFn fn;
    KeyCode keycode;
    unsigned int modifiers; /* only Control/Mod1/Shift/Mod4 bits -- Lock/NumLock are stripped both here and when matching an incoming event, see numlock_mask() */
} HotkeyEntry;

static HotkeyEntry g_hotkeys[HOTKEY_MAX];
static int g_n_hotkeys = 0;

/* NumLock isn't always Mod2Mask -- it's whatever modifier slot the
 * server's current modifier map happens to put the Num_Lock keysym's
 * keycode in (in practice almost always Mod2, but querying is cheap and
 * correct instead of assuming). Computed once and cached: the modifier
 * map essentially never changes at runtime. */
static unsigned int numlock_mask(void)
{
    static unsigned int mask = 0;
    static int computed = 0;
    if (computed) {
        return mask;
    }
    computed = 1;
    KeyCode numlock_kc = XKeysymToKeycode(g_dpy, XK_Num_Lock);
    if (!numlock_kc) {
        return mask;
    }
    XModifierKeymap *map = XGetModifierMapping(g_dpy);
    if (!map) {
        return mask;
    }
    for (int mod = 0; mod < 8; mod++) {
        for (int k = 0; k < map->max_keypermod; k++) {
            if (map->modifiermap[mod * map->max_keypermod + k] == numlock_kc) {
                mask = 1u << mod;
            }
        }
    }
    XFreeModifiermap(map);
    return mask;
}

/* Recognizes a *bare* modifier name (no '+', nothing else) -- routed to
 * modtap.c instead of a plain XGrabKey, see hotkey_register()'s doc
 * comment in xispanel.h. */
static int parse_bare_modifier(const char *spec, unsigned int *out_mask)
{
    if (strchr(spec, '+')) {
        return 0;
    }
    if (!strcasecmp(spec, "Ctrl") || !strcasecmp(spec, "Control")) {
        *out_mask = ControlMask;
    } else if (!strcasecmp(spec, "Alt")) {
        *out_mask = Mod1Mask;
    } else if (!strcasecmp(spec, "Shift")) {
        *out_mask = ShiftMask;
    } else if (!strcasecmp(spec, "Meta") || !strcasecmp(spec, "Super") || !strcasecmp(spec, "Win")) {
        *out_mask = Mod4Mask;
    } else {
        return 0;
    }
    return 1;
}

/* Parses "<Mod>+<Mod>+...+<Key>" -- see the doc comment on hotkey_
 * register() in xispanel.h for the accepted modifier names/key format. */
static int parse_hotkey_spec(const char *spec, unsigned int *out_mods, KeyCode *out_keycode)
{
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", spec);

    unsigned int mods = 0;
    char keyname[64] = "";
    char *save = NULL;
    char *tok = strtok_r(buf, "+", &save);
    while (tok) {
        char *next = strtok_r(NULL, "+", &save);
        if (!next) {
            /* last '+'-separated token is the key itself */
            snprintf(keyname, sizeof(keyname), "%s", tok);
            break;
        }
        if (!strcasecmp(tok, "Ctrl") || !strcasecmp(tok, "Control")) {
            mods |= ControlMask;
        } else if (!strcasecmp(tok, "Alt")) {
            mods |= Mod1Mask;
        } else if (!strcasecmp(tok, "Shift")) {
            mods |= ShiftMask;
        } else if (!strcasecmp(tok, "Meta") || !strcasecmp(tok, "Super") || !strcasecmp(tok, "Win")) {
            mods |= Mod4Mask;
        } else {
            fprintf(stderr, "xispanel: hotkey: unknown modifier '%s' in '%s', ignoring it\n", tok, spec);
        }
        tok = next;
    }
    if (!keyname[0]) {
        fprintf(stderr, "xispanel: hotkey: spec '%s' has no key, only modifiers\n", spec);
        return 0;
    }
    KeySym ks = XStringToKeysym(keyname);
    if (ks == NoSymbol) {
        fprintf(stderr, "xispanel: hotkey: unknown key name '%s' in spec '%s'\n", keyname, spec);
        return 0;
    }
    KeyCode kc = XKeysymToKeycode(g_dpy, ks);
    if (!kc) {
        fprintf(stderr, "xispanel: hotkey: key '%s' (spec '%s') has no keycode on this keyboard\n", keyname, spec);
        return 0;
    }
    *out_mods = mods;
    *out_keycode = kc;
    return 1;
}

/* Grabs all four Lock/NumLock combinations of `mods` so the hotkey still
 * fires regardless of either lock's current state -- the same thing any
 * well-behaved WM/hotkey-daemon does, since XGrabKey() matches modifier
 * state exactly. */
static void grab_variants(KeyCode kc, unsigned int mods)
{
    unsigned int nl = numlock_mask();
    unsigned int variants[4] = {0, LockMask, nl, nl | LockMask};
    for (int i = 0; i < 4; i++) {
        XGrabKey(g_dpy, kc, mods | variants[i], g_root, True, GrabModeAsync, GrabModeAsync);
    }
}

static void ungrab_variants(KeyCode kc, unsigned int mods)
{
    unsigned int nl = numlock_mask();
    unsigned int variants[4] = {0, LockMask, nl, nl | LockMask};
    for (int i = 0; i < 4; i++) {
        XUngrabKey(g_dpy, kc, mods | variants[i], g_root);
    }
}

int hotkey_register(PanelWidget *w, const char *spec, HotkeyFn fn)
{
    unsigned int bare_mask;
    if (parse_bare_modifier(spec, &bare_mask)) {
        return modtap_register(bare_mask, w, fn);
    }
    if (g_n_hotkeys >= HOTKEY_MAX) {
        fprintf(stderr, "xispanel: hotkey: too many hotkeys registered, ignoring '%s'\n", spec);
        return 0;
    }
    unsigned int mods;
    KeyCode kc;
    if (!parse_hotkey_spec(spec, &mods, &kc)) {
        return 0;
    }
    /* A grab that's already held by another client (WM, another app)
     * fails with BadAccess -- xispanel.c's global X error handler logs
     * and ignores it rather than crashing, same as every other X call
     * that can race against something else on the display. */
    grab_variants(kc, mods);
    HotkeyEntry *e = &g_hotkeys[g_n_hotkeys++];
    e->w = w;
    e->fn = fn;
    e->keycode = kc;
    e->modifiers = mods;
    return 1;
}

void hotkey_unregister_widget(PanelWidget *w)
{
    for (int i = 0; i < g_n_hotkeys;) {
        if (g_hotkeys[i].w == w) {
            ungrab_variants(g_hotkeys[i].keycode, g_hotkeys[i].modifiers);
            g_hotkeys[i] = g_hotkeys[g_n_hotkeys - 1];
            g_n_hotkeys--;
        } else {
            i++;
        }
    }
    modtap_unregister_widget(w);
}

int hotkey_handle_event(const XEvent *ev)
{
    if (ev->type != KeyPress) {
        return 0;
    }
    unsigned int state = ev->xkey.state & ~(LockMask | numlock_mask());
    for (int i = 0; i < g_n_hotkeys; i++) {
        if (g_hotkeys[i].keycode == ev->xkey.keycode && g_hotkeys[i].modifiers == state) {
            if (g_hotkeys[i].fn) {
                g_hotkeys[i].fn(g_hotkeys[i].w);
            }
            return 1;
        }
    }
    return 0;
}
