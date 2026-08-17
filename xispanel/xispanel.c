/*
 * xispanel - minimal desktop panel/taskbar daemon.
 *
 * One process per session (guarded by an flock'd lock file under
 * XDG_RUNTIME_DIR, same pattern as xisback/xisguard). Any further
 * invocation talks to the already running instance over a Unix socket
 * (see PROTOCOL.md) instead of spawning a second process.
 *
 * A "panel" is a bar anchored to one edge (top/bottom/left/right) of one
 * XRandR output, sized by a percentage of that edge plus a fixed
 * thickness, holding an ordered list of "widgets" (spacer, clock,
 * tasklist, ...). Multiple panels (e.g. one per output, or two on the
 * same output) are multiple entries in one config file served by one
 * daemon process -- same relationship xisback has between its process
 * and its per-(output, desktop) wallpaper layers.
 *
 * Panel windows are override-redirect: this keeps xispanel independent of
 * whatever window manager happens to be running (no reparenting, no
 * negotiating "always on top" state with the WM) while still reserving
 * screen space via _NET_WM_STRUT_PARTIAL in "dock" mode -- every WM that
 * matters here reads that property from any top-level window, managed or
 * not. The tradeoff is that xispanel itself is fully responsible for
 * raising/positioning/clipping its own windows, which is why the autohide
 * state machine below does its own slide animation instead of asking the
 * WM for one.
 *
 * This file owns the panel/window/layout/config/IPC machinery. Widget
 * types live in their own widgets/ directory (see xispanel.h for the
 * PanelWidgetOps vtable + core API they're built against) and are wired
 * in as a compile-time registry below -- no dlopen, in the same "flat
 * files, no abstraction beyond what's needed" spirit as the rest of this
 * kit. EWMH/ICCCM helpers live in ewmh.c, the context-menu popup in
 * menu.c. Widget add/remove/reorder is done by editing the config file
 * and sending RELOAD (or restarting) -- there is no live IPC mutation of
 * a panel's widget list yet, see PROTOCOL.md.
 *
 * Rendering: one ARGB32 (if available) cairo_xlib_surface per panel
 * window. Imlib2 is pulled in for future bitmap-theme decoding (nothing
 * uses it yet); window icons come from _NET_WM_ICON via Xlib directly
 * (ewmh.c), not Imlib2 -- it's already raw ARGB pixel data, no
 * image-format decoding needed. Text goes through
 * cairo_ft_font_face_create_for_ft_face with a Fontconfig-resolved font
 * -- no Pango, no GLib.
 *
 * Config lives at $XDG_CONFIG_HOME/xispanel.conf and is *not* written by
 * this program yet: PANEL/WIDGET/THEME lines are hand-edited (or written
 * by a future xisconf tab) and picked up on startup or via the IPC RELOAD
 * command. Persisting live-mutated state (SET_WIDGET etc. over the IPC
 * socket) is a later phase once there is any IPC command that actually
 * mutates a panel. See PROTOCOL.md.
 */

#include "xispanel.h"

#include <Imlib2.h>
#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/Xrandr.h>

#include <cairo/cairo-ft.h>
#include <cairo/cairo-xlib.h>
#include <fontconfig/fontconfig.h>
#include <ft2build.h>
#include FT_FREETYPE_H

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define XISPANEL_VERSION "0.4.1"
#define MAX_PANELS 8
#define LINE_MAX_LEN 2048
#define IPC_MAX_LEN 4096
#define AUTOHIDE_ANIM_MS 150
#define AUTOHIDE_DELAY_MS 400

/* ------------------------------------------------------------------ */
/* globals                                                              */
/* ------------------------------------------------------------------ */

Display *g_dpy;
Window g_root;
int g_screen;
cairo_font_face_t *g_font_face;
char g_font_family[128]; /* filled once at startup, see detect_system_font_family() in main() */

static int g_rr_event_base;
static volatile sig_atomic_t g_quit = 0;
static Panel g_panels[MAX_PANELS];
static char g_configpath[PATH_MAX];

static FT_Library g_ft_lib;
static FT_Face g_ft_face;

/* Only needed for dock-mode windows, which (unlike overlay/autohide) are
 * managed rather than override-redirect -- see panel_create_window(). */
static Atom g_atom_net_wm_state;
static Atom g_atom_net_wm_state_skip_taskbar;
static Atom g_atom_net_wm_state_skip_pager;
static Atom g_atom_net_wm_desktop;

/* ------------------------------------------------------------------ */
/* small helpers exposed to widgets                                     */
/* ------------------------------------------------------------------ */

uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

/* Looks up "key=value" inside a whitespace-separated token line (the tail
 * of a PANEL/WIDGET/THEME config record, or a widget's own config_kv). A
 * value may be wrapped in double quotes to embed spaces (e.g. launcher's
 * `cmd="xterm -e htop"`) -- everything between the quotes, unparsed, is
 * treated as one token, and the surrounding quotes themselves are
 * stripped from the returned value. No escaping inside quotes (a value
 * can't contain a literal `"`); not needed by anything so far. Returns 1
 * if found. */
int kv_get(const char *kvline, const char *key, char *out, size_t outsz)
{
    if (!kvline) {
        return 0;
    }
    size_t keylen = strlen(key);
    const char *p = kvline;
    while (*p) {
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (!*p) {
            break;
        }
        const char *tok_start = p;
        int in_quotes = 0;
        while (*p && (in_quotes || (*p != ' ' && *p != '\t'))) {
            if (*p == '"') {
                in_quotes = !in_quotes;
            }
            p++;
        }
        size_t tok_len = (size_t)(p - tok_start);
        if (tok_len > keylen && tok_start[keylen] == '=' && strncmp(tok_start, key, keylen) == 0) {
            const char *val_start = tok_start + keylen + 1;
            size_t vlen = tok_len - keylen - 1;
            if (vlen >= 2 && val_start[0] == '"' && val_start[vlen - 1] == '"') {
                val_start++;
                vlen -= 2;
            }
            if (vlen >= outsz) {
                vlen = outsz - 1;
            }
            memcpy(out, val_start, vlen);
            out[vlen] = 0;
            return 1;
        }
    }
    return 0;
}

int kv_get_int(const char *kvline, const char *key, int defval)
{
    char buf[32];
    if (kv_get(kvline, key, buf, sizeof(buf))) {
        return atoi(buf);
    }
    return defval;
}

/* Local-frame rectangle for a widget to paint into: origin always at
 * (0,0), since panel_repaint() already translates+rotates the cairo_t
 * before calling paint() -- a widget never needs to know its own on-panel
 * position, the panel's edge, or its rotate angle.
 *
 * The *shape* reported still depends on both: at rotate 0/180 a widget
 * gets its panel's natural physical shape (wide/short for top/bottom,
 * narrow/tall for left/right); at 90/270 that shape is transposed, since
 * panel_repaint() rotates a quarter turn to fit the *same* physical
 * footprint with width and height swapped. Every widget (text, icons,
 * buttons, everything) therefore renders "rotated" for free with zero
 * orientation-specific code -- see the comment above panel_repaint(). */
void widget_get_rect(const PanelWidget *w, int *x, int *y, int *width, int *height)
{
    Panel *p = w->panel;
    int natural_horizontal = (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM);
    int transposed = (p->rotate == 90 || p->rotate == 270);
    *x = 0;
    *y = 0;
    if (natural_horizontal != transposed) {
        *width = w->len;
        *height = w->thickness;
    } else {
        *width = w->thickness;
        *height = w->len;
    }
}

double panel_text_size(const Panel *p)
{
    return p->font_size_px > 0 ? p->font_size_px : p->thickness * 0.45;
}

/* ------------------------------------------------------------------ */
/* config-only string helpers (not part of the widget-facing API)       */
/* ------------------------------------------------------------------ */

static void join_fields(char **fields, int start, int nf, char *out, size_t outsz)
{
    out[0] = 0;
    size_t used = 0;
    for (int i = start; i < nf; i++) {
        size_t len = strlen(fields[i]);
        if (used + len + 2 >= outsz) {
            break;
        }
        if (used > 0) {
            out[used++] = ' ';
        }
        memcpy(out + used, fields[i], len);
        used += len;
        out[used] = 0;
    }
}

/* "#RRGGBB" or "#RRGGBBAA" -> 0..1 components. Leaves *r/g/b/a untouched
 * (caller should pre-seed with a default) if hex is empty or malformed. */
static void parse_hex_color(const char *hex, double *r, double *g, double *b, double *a)
{
    if (!hex || hex[0] != '#') {
        return;
    }
    size_t len = strlen(hex);
    if (len != 7 && len != 9) {
        return;
    }
    unsigned int ri, gi, bi, ai = 255;
    if (sscanf(hex + 1, "%2x%2x%2x", &ri, &gi, &bi) != 3) {
        return;
    }
    if (len == 9) {
        sscanf(hex + 7, "%2x", &ai);
    }
    *r = ri / 255.0;
    *g = gi / 255.0;
    *b = bi / 255.0;
    *a = ai / 255.0;
}

/* ------------------------------------------------------------------ */
/* widget registry                                                      */
/* ------------------------------------------------------------------ */

static const PanelWidgetOps *g_widget_registry[] = {
    &spacer_ops,
    &clock_ops,
    &tasklist_ops,
    &winctl_ops,
    &tray_ops,
    &launcher_ops,
    &volume_ops,
    &globalmenu_ops,
    &folder_ops,
    &xisserve_ops,
    NULL,
};

static const PanelWidgetOps *find_widget_ops(const char *type_name)
{
    for (int i = 0; g_widget_registry[i]; i++) {
        if (strcmp(g_widget_registry[i]->type_name, type_name) == 0) {
            return g_widget_registry[i];
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* font setup                                                           */
/* ------------------------------------------------------------------ */

/* Reads whichever desktop's own "default UI font" setting is present, so
 * xispanel's text matches the rest of the session instead of whatever
 * fontconfig's generic "sans-serif" alias happens to resolve to (often a
 * different font than what the user picked in System Settings, since
 * that alias is a distro-wide default, not a per-user one). No Qt/GTK
 * linked -- just the same two plain config files those toolkits
 * themselves read, checked in order:
 *
 *   - KDE/Plasma: ~/.config/kdeglobals, [General] font=Family,size,...
 *   - GTK3:       ~/.config/gtk-3.0/settings.ini, [Settings]
 *                 gtk-font-name=Family size
 *
 * Falls back to fontconfig's "sans-serif" default (via init_font()'s own
 * fallback) if neither file exists or has the key -- most likely a
 * minimal/non-desktop X session, where there's nothing more specific to
 * honor anyway. */
static void detect_system_font_family(char *out, size_t outsz)
{
    out[0] = 0;
    const char *home = getenv("HOME");
    if (!home) {
        return;
    }
    char path[PATH_MAX];
    char line[512];

    snprintf(path, sizeof(path), "%s/.config/kdeglobals", home);
    FILE *f = fopen(path, "r");
    if (f) {
        int in_general = 0;
        while (fgets(line, sizeof(line), f)) {
            size_t len = strlen(line);
            while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = 0;
            }
            if (line[0] == '[') {
                in_general = (strcmp(line, "[General]") == 0);
                continue;
            }
            if (in_general && strncmp(line, "font=", 5) == 0) {
                const char *val = line + 5;
                const char *comma = strchr(val, ',');
                size_t flen = comma ? (size_t)(comma - val) : strlen(val);
                if (flen >= outsz) {
                    flen = outsz - 1;
                }
                memcpy(out, val, flen);
                out[flen] = 0;
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
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            size_t len = strlen(line);
            while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = 0;
            }
            if (strncmp(line, "gtk-font-name=", 14) == 0) {
                char buf[256];
                snprintf(buf, sizeof(buf), "%s", line + 14);
                /* gtk-font-name is "Family [Style] size" -- drop the
                 * trailing numeric size token, Fontconfig only needs the
                 * family here (panel text is sized off panel thickness,
                 * not a fixed point size -- see the callers of
                 * init_font()). */
                char *sp = strrchr(buf, ' ');
                if (sp && isdigit((unsigned char)sp[1])) {
                    *sp = 0;
                }
                snprintf(out, outsz, "%s", buf);
                break;
            }
        }
        fclose(f);
    }
}

/* Companion to detect_system_font_family() -- same two sources, same
 * live-read-every-time philosophy (see detect_system_colors()'s doc
 * comment), but for the *point size* instead of the family name:
 *   - KDE/Plasma: kdeglobals's "font=Family,POINTSIZE,weight,..." --
 *     the second comma-separated field.
 *   - GTK3: gtk-3.0/settings.ini's "gtk-font-name=Family [Style] SIZE" --
 *     the same trailing numeric token detect_system_font_family() already
 *     strips off (there for Fontconfig's family-only lookup) is the
 *     point size here.
 * Returns 0 (not a valid pixel size) if neither file has a parseable
 * size -- callers keep whatever size they'd otherwise use (thickness-
 * proportional for in-panel widget text, fixed constants for tooltip/
 * menu popups). Converts pt to px at a flat 96 DPI (`* 96.0/72.0`) --
 * no attempt at real per-monitor DPI, consistent with the rest of
 * xispanel treating all size units as plain pixels. */
static double detect_system_font_size_px(void)
{
    const char *home = getenv("HOME");
    if (!home) {
        return 0;
    }
    char path[PATH_MAX];
    char line[512];

    snprintf(path, sizeof(path), "%s/.config/kdeglobals", home);
    FILE *f = fopen(path, "r");
    if (f) {
        int in_general = 0;
        while (fgets(line, sizeof(line), f)) {
            size_t len = strlen(line);
            while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = 0;
            }
            if (line[0] == '[') {
                in_general = (strcmp(line, "[General]") == 0);
                continue;
            }
            if (in_general && strncmp(line, "font=", 5) == 0) {
                const char *comma = strchr(line + 5, ',');
                fclose(f);
                if (comma && isdigit((unsigned char)comma[1])) {
                    return atoi(comma + 1) * 96.0 / 72.0;
                }
                return 0;
            }
        }
        fclose(f);
    }

    snprintf(path, sizeof(path), "%s/.config/gtk-3.0/settings.ini", home);
    f = fopen(path, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            size_t len = strlen(line);
            while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = 0;
            }
            if (strncmp(line, "gtk-font-name=", 14) == 0) {
                char *sp = strrchr(line + 14, ' ');
                fclose(f);
                if (sp && isdigit((unsigned char)sp[1])) {
                    return atoi(sp + 1) * 96.0 / 72.0;
                }
                return 0;
            }
        }
        fclose(f);
    }
    return 0;
}

/* Reads a "R,G,B" (each 0-255) KDE color-scheme value into 0.0-1.0 doubles.
 * Returns 0 (leaving *r/*g/*b untouched) if `val` isn't exactly that shape
 * -- callers treat that as "key present but unparseable", same as "key
 * absent" (fall through to the next source). */
static int parse_kde_rgb(const char *val, double *r, double *g, double *b)
{
    int ri, gi, bi;
    if (sscanf(val, "%d,%d,%d", &ri, &gi, &bi) != 3) {
        return 0;
    }
    *r = ri / 255.0;
    *g = gi / 255.0;
    *b = bi / 255.0;
    return 1;
}

/* Live counterpart to detect_system_font_family(): reads the desktop's
 * *actual current* panel-background/foreground colors, for whenever a
 * THEME line doesn't set bg=/fg= itself (explicit config always wins --
 * see apply_theme_kv(), called after this). Deliberately not cached/copied
 * into xispanel.conf at config-generation time (see
 * write_default_config_if_missing()'s doc comment) -- reads the files
 * fresh every time a panel's colors need a default, so a later system
 * theme change or RELOAD picks it up automatically.
 *
 *   - KDE/Plasma: ~/.config/kdeglobals, [Colors:Window]
 *                 BackgroundNormal=R,G,B / ForegroundNormal=R,G,B
 *   - GTK3: no equivalent simple key -- GTK themes are CSS, not a flat
 *     key=value color list, so there's no cheap file to read here the way
 *     gtk-font-name works for fonts. Left as a known gap rather than
 *     something worth a CSS parser for.
 *
 * Returns 1 if at least one of bg/fg was found and written, 0 if nothing
 * was (caller keeps its own hardcoded default in that case). */
static int detect_system_colors(double *bg_r, double *bg_g, double *bg_b, double *fg_r, double *fg_g, double *fg_b)
{
    const char *home = getenv("HOME");
    if (!home) {
        return 0;
    }
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/.config/kdeglobals", home);
    FILE *f = fopen(path, "r");
    if (!f) {
        return 0;
    }
    int in_window = 0, found = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = 0;
        }
        if (line[0] == '[') {
            in_window = (strcmp(line, "[Colors:Window]") == 0);
            continue;
        }
        if (!in_window) {
            continue;
        }
        if (!strncmp(line, "BackgroundNormal=", 17) && parse_kde_rgb(line + 17, bg_r, bg_g, bg_b)) {
            found = 1;
        } else if (!strncmp(line, "ForegroundNormal=", 17) && parse_kde_rgb(line + 17, fg_r, fg_g, fg_b)) {
            found = 1;
        }
    }
    fclose(f);
    return found;
}

static int init_font(const char *family_hint)
{
    if (FT_Init_FreeType(&g_ft_lib) != 0) {
        return -1;
    }
    if (!FcInit()) {
        return -1;
    }
    FcPattern *pat = FcNameParse((const FcChar8 *)(family_hint && *family_hint ? family_hint : "sans-serif"));
    FcConfigSubstitute(NULL, pat, FcMatchPattern);
    FcDefaultSubstitute(pat);
    FcResult result;
    FcPattern *match = FcFontMatch(NULL, pat, &result);
    FcPatternDestroy(pat);
    if (!match) {
        return -1;
    }
    FcChar8 *file = NULL;
    if (FcPatternGetString(match, FC_FILE, 0, &file) != FcResultMatch) {
        FcPatternDestroy(match);
        return -1;
    }
    if (FT_New_Face(g_ft_lib, (const char *)file, 0, &g_ft_face) != 0) {
        FcPatternDestroy(match);
        return -1;
    }
    FcPatternDestroy(match);
    g_font_face = cairo_ft_font_face_create_for_ft_face(g_ft_face, 0);
    return 0;
}

/* ------------------------------------------------------------------ */
/* RandR output geometry (same pattern as xisback's resolve_output_geometry)*/
/* ------------------------------------------------------------------ */

/* *out_hz is left at 0 if the CRTC's current mode has no usable timing
 * info to compute one from -- callers should treat that as "unknown",
 * not "the output truly refreshes at 0Hz". */
static int resolve_output_geometry(const char *name, int *ox, int *oy, int *ow, int *oh, double *out_hz)
{
    XRRScreenResources *res = XRRGetScreenResourcesCurrent(g_dpy, g_root);
    if (!res) {
        return 0;
    }
    int found = 0;
    for (int i = 0; i < res->noutput && !found; i++) {
        XRROutputInfo *oi = XRRGetOutputInfo(g_dpy, res, res->outputs[i]);
        if (oi && oi->connection == RR_Connected && oi->crtc && strcmp(oi->name, name) == 0) {
            XRRCrtcInfo *ci = XRRGetCrtcInfo(g_dpy, res, oi->crtc);
            if (ci) {
                *ox = ci->x;
                *oy = ci->y;
                *ow = (int)ci->width;
                *oh = (int)ci->height;
                *out_hz = 0;
                for (int m = 0; m < res->nmode; m++) {
                    if (res->modes[m].id != ci->mode) {
                        continue;
                    }
                    XRRModeInfo *mi = &res->modes[m];
                    if (mi->hTotal == 0 || mi->vTotal == 0) {
                        break;
                    }
                    /* Same formula xrandr itself uses to print "60.00*" etc. */
                    double vtotal = mi->vTotal;
                    if (mi->modeFlags & RR_DoubleScan) {
                        vtotal *= 2;
                    }
                    if (mi->modeFlags & RR_Interlace) {
                        vtotal /= 2;
                    }
                    *out_hz = (double)mi->dotClock / ((double)mi->hTotal * vtotal);
                    break;
                }
                found = 1;
                XRRFreeCrtcInfo(ci);
            }
        }
        if (oi) {
            XRRFreeOutputInfo(oi);
        }
    }
    XRRFreeScreenResources(res);
    return found;
}

/* Name of the RandR-designated primary output (xrandr --output X --primary),
 * or 0 if none is set/RandR is unavailable -- used only when writing a
 * first-run default config (see write_default_config_if_missing()), so a
 * multi-monitor session's default panel lands on the right screen instead
 * of spanning every monitor combined ("*"). */
static int get_primary_output_name(char *out, size_t outsz)
{
    RROutput primary = XRRGetOutputPrimary(g_dpy, g_root);
    if (!primary) {
        return 0;
    }
    XRRScreenResources *res = XRRGetScreenResourcesCurrent(g_dpy, g_root);
    if (!res) {
        return 0;
    }
    int found = 0;
    XRROutputInfo *oi = XRRGetOutputInfo(g_dpy, res, primary);
    if (oi && oi->connection == RR_Connected) {
        snprintf(out, outsz, "%s", oi->name);
        found = 1;
    }
    if (oi) {
        XRRFreeOutputInfo(oi);
    }
    XRRFreeScreenResources(res);
    return found;
}

/* First run (no $XDG_CONFIG_HOME/xispanel.conf yet): rather than the
 * daemon silently running with zero panels -- which looks exactly like
 * xispanel isn't working at all -- write a minimal but usable default:
 * one panel at the bottom edge of the primary output (or "*", the whole
 * virtual screen, if RandR has no primary set -- equivalent on a
 * single-monitor session anyway), with launcher+tasklist on the left and
 * tray+clock pushed to the right edge by a spacer in between.
 * Deliberately no THEME line and no font here: colors/font are meant to
 * be read live from the user's Qt/GTK config whenever they're *not*
 * explicitly set in xispanel.conf (see detect_system_colors() and
 * detect_system_font_family()) rather than baked into a copy at
 * generation time, which would just go stale the next time the user
 * changes their system theme. */
static void write_default_config_if_missing(void)
{
    if (access(g_configpath, F_OK) == 0) {
        return;
    }
    char output[64];
    if (!get_primary_output_name(output, sizeof(output))) {
        snprintf(output, sizeof(output), "*");
    }
    FILE *f = fopen(g_configpath, "w");
    if (!f) {
        fprintf(stderr, "xispanel: could not write default config to %s: %s\n", g_configpath, strerror(errno));
        return;
    }
    fprintf(f,
            "PANEL\tmain\t%s\tedge=bottom\tpct=100\tthickness=32\tmode=dock\n"
            "WIDGET\tmain\t0\tlauncher\n"
            "WIDGET\tmain\t1\ttasklist\tmode=wide\n"
            "WIDGET\tmain\t2\tspacer\n"
            "WIDGET\tmain\t3\ttray\n"
            "WIDGET\tmain\t4\tclock\n",
            output);
    fclose(f);
    fprintf(stderr, "xispanel: no config found, wrote a default panel to %s\n", g_configpath);
}

static void panel_resolve_geometry(Panel *p)
{
    if (strcmp(p->output, "*") != 0 &&
        resolve_output_geometry(p->output, &p->out_x, &p->out_y, &p->out_w, &p->out_h, &p->out_refresh_hz)) {
        /* matched */
    } else {
        if (strcmp(p->output, "*") != 0) {
            fprintf(stderr, "xispanel: panel '%s': output '%s' not found, falling back to full screen\n", p->name, p->output);
        }
        p->out_x = 0;
        p->out_y = 0;
        p->out_w = DisplayWidth(g_dpy, g_screen);
        p->out_h = DisplayHeight(g_dpy, g_screen);
        p->out_refresh_hz = 0; /* spans every output ("*") or none matched -- no single rate applies */
    }

    p->thickness = p->thickness_cfg;

    if (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM) {
        p->w = p->out_w * p->pct / 100;
        p->h = p->thickness;
        p->x = p->out_x + (p->out_w - p->w) / 2;
        p->y = (p->edge == EDGE_TOP) ? p->out_y : (p->out_y + p->out_h - p->thickness);
        p->hidden_x = p->x;
        p->hidden_y = (p->edge == EDGE_TOP) ? (p->out_y - p->thickness) : (p->out_y + p->out_h);
    } else {
        p->h = p->out_h * p->pct / 100;
        p->w = p->thickness;
        p->y = p->out_y + (p->out_h - p->h) / 2;
        p->x = (p->edge == EDGE_LEFT) ? p->out_x : (p->out_x + p->out_w - p->thickness);
        p->hidden_y = p->y;
        p->hidden_x = (p->edge == EDGE_LEFT) ? (p->out_x - p->thickness) : (p->out_x + p->out_w);
    }
}

/* ------------------------------------------------------------------ */
/* strut (dock mode)                                                    */
/* ------------------------------------------------------------------ */

static void panel_apply_strut(Panel *p)
{
    if (p->mode != MODE_DOCK) {
        return;
    }
    /* _NET_WM_STRUT_PARTIAL: left, right, top, bottom, left_start_y,
     * left_end_y, right_start_y, right_end_y, top_start_x, top_end_x,
     * bottom_start_x, bottom_end_x */
    long strut[12] = {0};
    long strut4[4] = {0};
    switch (p->edge) {
    case EDGE_TOP:
        strut[2] = p->y + p->h; /* distance from top of screen */
        strut[8] = p->x;
        strut[9] = p->x + p->w - 1;
        strut4[2] = strut[2];
        break;
    case EDGE_BOTTOM:
        strut[3] = DisplayHeight(g_dpy, g_screen) - p->y;
        strut[10] = p->x;
        strut[11] = p->x + p->w - 1;
        strut4[3] = strut[3];
        break;
    case EDGE_LEFT:
        strut[0] = p->x + p->w;
        strut[4] = p->y;
        strut[5] = p->y + p->h - 1;
        strut4[0] = strut[0];
        break;
    case EDGE_RIGHT:
        strut[1] = DisplayWidth(g_dpy, g_screen) - p->x;
        strut[6] = p->y;
        strut[7] = p->y + p->h - 1;
        strut4[1] = strut[1];
        break;
    }
    XChangeProperty(g_dpy, p->win, g_atom_wm_strut_partial, XA_CARDINAL, 32, PropModeReplace, (unsigned char *)strut, 12);
    XChangeProperty(g_dpy, p->win, g_atom_wm_strut, XA_CARDINAL, 32, PropModeReplace, (unsigned char *)strut4, 4);
}

/* ------------------------------------------------------------------ */
/* window / cairo surface creation                                      */
/* ------------------------------------------------------------------ */

static void panel_pick_visual(Panel *p)
{
    XVisualInfo vinfo;
    if (XMatchVisualInfo(g_dpy, g_screen, 32, TrueColor, &vinfo)) {
        p->visual = vinfo.visual;
        p->depth = vinfo.depth;
        p->cmap = XCreateColormap(g_dpy, g_root, p->visual, AllocNone);
    } else {
        /* No ARGB visual available (no compositor advertising one): fall
         * back to the default visual. Backgrounds configured with alpha
         * < 1 will just render fully opaque. */
        p->visual = DefaultVisual(g_dpy, g_screen);
        p->depth = DefaultDepth(g_dpy, g_screen);
        p->cmap = DefaultColormap(g_dpy, g_screen);
    }
}

static Window panel_create_window(Panel *p, int x, int y, int w, int h)
{
    /* dock mode needs to be a WM-managed window: this KWin fork's strut
     * handling (workspace.cpp's updateClientArea()) only walks its list of
     * managed clients, never the separate unmanaged/override-redirect list
     * -- so an override-redirect panel can set _NET_WM_STRUT_PARTIAL all it
     * wants and no screen space will ever actually be reserved. overlay/
     * autohide don't need struts at all, so they stay override-redirect to
     * avoid the WM ever touching their position (matters for the autohide
     * slide animation). */
    int managed = (p->mode == MODE_DOCK);

    XSetWindowAttributes attrs;
    memset(&attrs, 0, sizeof(attrs));
    attrs.override_redirect = managed ? False : True;
    attrs.colormap = p->cmap;
    attrs.border_pixel = 0;
    attrs.background_pixel = 0;
    attrs.event_mask = ButtonPressMask | EnterWindowMask | LeaveWindowMask | PointerMotionMask | ExposureMask;

    Window win = XCreateWindow(g_dpy, g_root, x, y, (unsigned)w, (unsigned)h, 0, p->depth, InputOutput, p->visual,
                                CWOverrideRedirect | CWColormap | CWBorderPixel | CWBackPixel | CWEventMask, &attrs);

    char title[64];
    snprintf(title, sizeof(title), "xispanel:%s", p->name);
    XStoreName(g_dpy, win, title);
    XClassHint ch = {(char *)"xispanel", (char *)"xispanel"};
    XSetClassHint(g_dpy, win, &ch);

    XChangeProperty(g_dpy, win, g_atom_wm_window_type, XA_ATOM, 32, PropModeReplace, (unsigned char *)&g_atom_wm_window_type_dock, 1);

    if (managed) {
        /* ICCCM input=False: never wants keyboard focus, so click-to-focus
         * policies must never give it focus (mouse clicks still work --
         * ButtonPress delivery doesn't require focus). */
        XWMHints hints;
        memset(&hints, 0, sizeof(hints));
        hints.flags = InputHint;
        hints.input = False;
        XSetWMHints(g_dpy, win, &hints);

        /* ICCCM PPosition: tells the WM the position was chosen by the
         * application, not left to the placement policy -- otherwise a
         * managed window's initial x/y is only a hint some WMs ignore. */
        XSizeHints sh;
        memset(&sh, 0, sizeof(sh));
        sh.flags = PPosition | PSize;
        sh.x = x;
        sh.y = y;
        sh.width = w;
        sh.height = h;
        XSetWMNormalHints(g_dpy, win, &sh);

        /* Initial _NET_WM_STATE: read by the WM at manage() time, same as
         * if these had been requested via a _NET_WM_STATE client message
         * after mapping. Keeps the panel out of the taskbar/pager despite
         * now being a real managed window. */
        Atom states[2] = {g_atom_net_wm_state_skip_taskbar, g_atom_net_wm_state_skip_pager};
        XChangeProperty(g_dpy, win, g_atom_net_wm_state, XA_ATOM, 32, PropModeReplace, (unsigned char *)states, 2);

        /* All desktops. */
        long all_desktops = -1;
        XChangeProperty(g_dpy, win, g_atom_net_wm_desktop, XA_CARDINAL, 32, PropModeReplace,
                         (unsigned char *)&all_desktops, 1);
    }

    return win;
}

static Window panel_create_sensor(Panel *p)
{
    XSetWindowAttributes attrs;
    memset(&attrs, 0, sizeof(attrs));
    attrs.override_redirect = True;
    attrs.background_pixel = BlackPixel(g_dpy, g_screen);
    attrs.event_mask = EnterWindowMask;

    int sx, sy, sw, sh;
    if (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM) {
        sx = p->x;
        sy = (p->edge == EDGE_TOP) ? p->out_y : (p->out_y + p->out_h - 1);
        sw = p->w;
        sh = 1;
    } else {
        sx = (p->edge == EDGE_LEFT) ? p->out_x : (p->out_x + p->out_w - 1);
        sy = p->y;
        sw = 1;
        sh = p->h;
    }

    Window win = XCreateWindow(g_dpy, g_root, sx, sy, (unsigned)sw, (unsigned)sh, 0, CopyFromParent, InputOutput,
                                DefaultVisual(g_dpy, g_screen), CWOverrideRedirect | CWBackPixel | CWEventMask, &attrs);
    XMapWindow(g_dpy, win);
    /* Must stay on top (not lowered) or it would sit behind whatever else
     * occupies that screen edge and never receive the EnterNotify that
     * triggers the show animation -- X only delivers pointer-crossing
     * events to the topmost window under the pointer. */
    XRaiseWindow(g_dpy, win);
    return win;
}

/* ------------------------------------------------------------------ */
/* 9-slice PNG background theme                                        */
/* ------------------------------------------------------------------ */

/* Decodes `path` via Imlib2 into a premultiplied-alpha cairo ARGB32
 * surface (Imlib2's DATA32 pixels are straight, not premultiplied --same
 * conversion ewmh_get_icon_surface() does for _NET_WM_ICON). NULL on any
 * failure (missing file, unreadable, decode error) -- callers treat that
 * as "no image", not a fatal error: THEME's bg_image is meant to
 * gracefully fall back to the plain bg_r/g/b/a color whenever it can't be
 * loaded. */
void run_detached(const char *cmd)
{
    if (!cmd || !cmd[0]) {
        return;
    }
    pid_t pid = fork();
    if (pid < 0) {
        perror("xispanel: fork");
        return;
    }
    if (pid == 0) {
        setsid();
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
}

cairo_surface_t *load_png_argb(const char *path)
{
    Imlib_Image img = imlib_load_image(path);
    if (!img) {
        return NULL;
    }
    imlib_context_set_image(img);
    int iw = imlib_image_get_width();
    int ih = imlib_image_get_height();
    if (iw <= 0 || ih <= 0 || iw > 4096 || ih > 4096) {
        imlib_free_image();
        return NULL;
    }
    DATA32 *src = imlib_image_get_data_for_reading_only();
    if (!src) {
        imlib_free_image();
        return NULL;
    }

    cairo_surface_t *surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, iw, ih);
    if (cairo_surface_status(surf) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(surf);
        imlib_free_image();
        return NULL;
    }
    unsigned char *dst = cairo_image_surface_get_data(surf);
    int stride = cairo_image_surface_get_stride(surf);
    for (int y = 0; y < ih; y++) {
        uint32_t *row = (uint32_t *)(void *)(dst + y * stride);
        for (int x = 0; x < iw; x++) {
            uint32_t argb = src[y * iw + x];
            uint8_t a = (uint8_t)((argb >> 24) & 0xff);
            uint8_t r = (uint8_t)((argb >> 16) & 0xff);
            uint8_t g = (uint8_t)((argb >> 8) & 0xff);
            uint8_t b = (uint8_t)(argb & 0xff);
            r = (uint8_t)((r * a) / 255);
            g = (uint8_t)((g * a) / 255);
            b = (uint8_t)((b * a) / 255);
            row[x] = ((uint32_t)a << 24) | ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
        }
    }
    cairo_surface_mark_dirty(surf);
    imlib_free_image();
    return surf;
}

/* Sidecar "measurements" file for a 9-slice bg_image: plain key=value
 * lines (left/top/right/bottom, pixels in the *source image*), same
 * spirit as the rest of this program's config format. Missing file or
 * missing keys just default that inset to 0 -- a 0-everywhere slice
 * degrades to a plain full-image stretch, not an error, so a theme author
 * can start simple. */
static void load_slice_file(const char *path, int *l, int *t, int *r, int *b)
{
    *l = *t = *r = *b = 0;
    if (!path[0]) {
        return;
    }
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "xispanel: could not open bg_slice file '%s', using 0-inset (full stretch)\n", path);
        return;
    }
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        int v;
        if (sscanf(line, "left=%d", &v) == 1) {
            *l = v;
        } else if (sscanf(line, "top=%d", &v) == 1) {
            *t = v;
        } else if (sscanf(line, "right=%d", &v) == 1) {
            *r = v;
        } else if (sscanf(line, "bottom=%d", &v) == 1) {
            *b = v;
        }
    }
    fclose(f);
}

/* Loads (or reloads) p's bg_image_surface + slice insets from its
 * currently configured bg_image_path/bg_slice_path. Called once from
 * panel_activate() -- config paths don't change without a full RELOAD,
 * which tears down and re-activates every panel anyway. */
static void panel_load_bg_image(Panel *p)
{
    if (p->bg_image_surface) {
        cairo_surface_destroy(p->bg_image_surface);
        p->bg_image_surface = NULL;
    }
    if (!p->bg_image_path[0]) {
        return;
    }
    p->bg_image_surface = load_png_argb(p->bg_image_path);
    if (!p->bg_image_surface) {
        fprintf(stderr, "xispanel: panel '%s': could not load bg_image '%s', falling back to bg color\n", p->name,
                p->bg_image_path);
        return;
    }
    load_slice_file(p->bg_slice_path, &p->bg_slice_l, &p->bg_slice_t, &p->bg_slice_r, &p->bg_slice_b);
}

/* Paints one source sub-rectangle [sx,sy,sw,sh] of `src` into one
 * destination rectangle [dx,dy,dw,dh] of `cr`, scaling to fit -- the one
 * building block every corner/edge/center region of a 9-slice draw
 * reduces to (corners just happen to have dw==sw, dh==sh, i.e. no
 * scaling). */
static void draw_slice_region(cairo_t *cr, cairo_surface_t *src, int sx, int sy, int sw, int sh, double dx, double dy,
                               double dw, double dh)
{
    if (sw <= 0 || sh <= 0 || dw <= 0 || dh <= 0) {
        return;
    }
    cairo_save(cr);
    cairo_translate(cr, dx, dy);
    cairo_scale(cr, dw / (double)sw, dh / (double)sh);
    cairo_set_source_surface(cr, src, -sx, -sy);
    cairo_pattern_set_filter(cairo_get_source(cr), CAIRO_FILTER_BILINEAR);
    cairo_rectangle(cr, 0, 0, sw, sh);
    cairo_clip(cr);
    cairo_paint(cr);
    cairo_restore(cr);
}

/* Draws `src` (sw x sh) into `cr`'s current (0,0)-(dw,dh) rect as a
 * 9-slice: the l/t/r/b-pixel corners are copied unscaled, the four edge
 * strips stretch along one axis, and the center stretches on both --
 * standard border-image technique, letting one theme image cover any
 * panel thickness/length instead of looking stretched-blurry at the
 * corners. Insets are silently clamped if they don't fit inside the
 * source image (a theme author's slice file shouldn't be able to corrupt
 * rendering, just look wrong). */
static void draw_9slice(cairo_t *cr, cairo_surface_t *src, int sw, int sh, int l, int t, int r, int b, double dw,
                         double dh)
{
    if (l + r > sw) {
        l = r = 0;
    }
    if (t + b > sh) {
        t = b = 0;
    }
    int cw = sw - l - r; /* source center width/height */
    int ch = sh - t - b;
    double dcw = dw - l - r; /* dest center width/height (may go negative on a tiny panel) */
    double dch = dh - t - b;
    if (dcw < 0) {
        dcw = 0;
    }
    if (dch < 0) {
        dch = 0;
    }

    /* corners: unscaled */
    draw_slice_region(cr, src, 0, 0, l, t, 0, 0, l, t);
    draw_slice_region(cr, src, sw - r, 0, r, t, dw - r, 0, r, t);
    draw_slice_region(cr, src, 0, sh - b, l, b, 0, dh - b, l, b);
    draw_slice_region(cr, src, sw - r, sh - b, r, b, dw - r, dh - b, r, b);
    /* edges: stretched along one axis */
    draw_slice_region(cr, src, l, 0, cw, t, l, 0, dcw, t);
    draw_slice_region(cr, src, l, sh - b, cw, b, l, dh - b, dcw, b);
    draw_slice_region(cr, src, 0, t, l, ch, 0, t, l, dch);
    draw_slice_region(cr, src, sw - r, t, r, ch, dw - r, t, r, dch);
    /* center: stretched on both axes */
    draw_slice_region(cr, src, l, t, cw, ch, l, t, dcw, dch);
}

static void panel_create_surface(Panel *p)
{
    p->surface = cairo_xlib_surface_create(g_dpy, p->win, p->visual, p->w, p->h);
    p->cr = cairo_create(p->surface);

    p->buf_surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, p->w, p->h);
    p->buf_cr = cairo_create(p->buf_surface);
    if (g_font_face) {
        cairo_set_font_face(p->cr, g_font_face);
        cairo_set_font_face(p->buf_cr, g_font_face);
    }
    cairo_set_font_size(p->cr, panel_text_size(p));
    cairo_set_font_size(p->buf_cr, panel_text_size(p));
}

/* ------------------------------------------------------------------ */
/* layout + paint                                                       */
/* ------------------------------------------------------------------ */

static void panel_layout(Panel *p)
{
    int axis_len = (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM) ? p->w : p->h;
    int lens[MAX_WIDGETS];
    int mins[MAX_WIDGETS];
    int n_greedy = 0;
    int fixed_total = 0;
    int min_total = 0;

    for (int i = 0; i < p->n_widgets; i++) {
        PanelWidget *w = &p->widgets[i];
        int out_len = 0;
        int out_min = 0;
        if (w->ops->measure) {
            w->ops->measure(w, p->thickness, &out_len, &out_min);
        }
        lens[i] = out_len;
        if (out_len < 0) {
            n_greedy++;
            mins[i] = 0;
        } else {
            fixed_total += out_len;
            mins[i] = out_min < 0 ? 0 : (out_min > out_len ? out_len : out_min);
            min_total += mins[i];
        }
    }

    int spacing_total = p->spacing * (p->n_widgets > 0 ? p->n_widgets - 1 : 0);
    int available = axis_len - spacing_total;
    if (available < 0) {
        available = 0;
    }

    int final_lens[MAX_WIDGETS];

    if (fixed_total <= available) {
        /* Everyone gets their desired size; greedy widgets split whatever
         * is left over. */
        int remaining = available - fixed_total;
        int greedy_each = (n_greedy > 0 && remaining > 0) ? remaining / n_greedy : 0;
        for (int i = 0; i < p->n_widgets; i++) {
            final_lens[i] = lens[i] < 0 ? greedy_each : lens[i];
        }
    } else {
        /* Doesn't fit even with every greedy widget at 0: shrink fixed
         * widgets toward their reported minimum, proportionally to how
         * much slack each one has, so no single widget eats the whole
         * squeeze. If even every widget's minimum doesn't fit, this is a
         * panel too small for its content -- everyone just gets their
         * minimum and the last one(s) get slightly clipped, which is the
         * best any layout can do here. */
        int shrinkable = fixed_total - min_total;
        int deficit = fixed_total - available;
        if (deficit > shrinkable) {
            deficit = shrinkable;
        }
        for (int i = 0; i < p->n_widgets; i++) {
            if (lens[i] < 0) {
                final_lens[i] = 0;
                continue;
            }
            int slack = lens[i] - mins[i];
            int shrink = (shrinkable > 0) ? (int)((int64_t)deficit * slack / shrinkable) : 0;
            final_lens[i] = lens[i] - shrink;
        }
    }

    int cursor = 0;
    for (int i = 0; i < p->n_widgets; i++) {
        PanelWidget *w = &p->widgets[i];
        int len = final_lens[i] < 0 ? 0 : final_lens[i];
        w->x = cursor;
        w->len = len;
        w->thickness = p->thickness;
        cursor += len + p->spacing;
    }
}

static void panel_repaint(Panel *p)
{
    if (!p->cr || !p->buf_cr) {
        return;
    }

    /* Once a cairo_t enters an error state (e.g. CAIRO_STATUS_INVALID_STRING
     * from passing malformed UTF-8 to cairo_show_text -- window titles are
     * supposed to be UTF-8 but not every client is well-behaved), every
     * subsequent call on it becomes a silent no-op *permanently*, even
     * cairo_save()/cairo_restore(). Since these cairo_t's are reused across
     * every repaint rather than recreated each time, one bad frame would
     * otherwise blank the panel forever. Recreate here instead of trusting
     * every current and future widget to never make this mistake. */
    if (cairo_status(p->buf_cr) != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "xispanel: panel '%s': cairo error (%s), recreating drawing context\n", p->name,
                cairo_status_to_string(cairo_status(p->buf_cr)));
        cairo_destroy(p->buf_cr);
        p->buf_cr = cairo_create(p->buf_surface);
        if (g_font_face) {
            cairo_set_font_face(p->buf_cr, g_font_face);
        }
        cairo_set_font_size(p->buf_cr, panel_text_size(p));
    }

    /* Every widget paints into the offscreen buf_cr/buf_surface first. Only
     * the single cairo_paint() below (blitting the finished buffer onto the
     * real, on-screen p->cr/surface) touches the window itself -- painting
     * straight onto the xlib surface instead sent each widget's fills/
     * strokes as its own X request, which a compositor could pick up
     * mid-repaint and show as flicker (worst on tasklist, which repaints on
     * every ~800ms poll tick even with nothing visibly different). */
    cairo_save(p->buf_cr);
    cairo_set_operator(p->buf_cr, CAIRO_OPERATOR_SOURCE);
    if (p->bg_image_surface) {
        /* Clear first: the 9-slice draw below is itself CAIRO_OPERATOR_SOURCE
         * per region, but only actually covers the panel rect once (no
         * overlap/gaps by construction), so no separate clear is needed --
         * kept anyway for a defined background on any 1px seam from
         * floating-point scaling error. */
        cairo_set_source_rgba(p->buf_cr, 0, 0, 0, 0);
        cairo_paint(p->buf_cr);
        int sw = cairo_image_surface_get_width(p->bg_image_surface);
        int sh = cairo_image_surface_get_height(p->bg_image_surface);
        draw_9slice(p->buf_cr, p->bg_image_surface, sw, sh, p->bg_slice_l, p->bg_slice_t, p->bg_slice_r,
                    p->bg_slice_b, p->w, p->h);
    } else {
        cairo_set_source_rgba(p->buf_cr, p->bg_r, p->bg_g, p->bg_b, p->bg_a);
        cairo_paint(p->buf_cr);
    }
    cairo_restore(p->buf_cr);

    cairo_set_operator(p->buf_cr, CAIRO_OPERATOR_OVER);
    for (int i = 0; i < p->n_widgets; i++) {
        PanelWidget *w = &p->widgets[i];
        if (w->ops->paint) {
            cairo_save(p->buf_cr);
            /* This widget's real, physical, un-rotated on-panel rectangle
             * -- same shape widget_get_rect() always used to report
             * before rotation existed. Rotating *about its center* by any
             * multiple of 90 degrees is what lets one formula handle
             * every edge/angle combination: at 0/180 the content shape
             * equals this rect; at 90/270 it's this rect transposed (see
             * widget_get_rect()), and rotating that transposed shape
             * about the same center lands it back on exactly this
             * footprint. Click/tooltip/menu hit-testing never sees any of
             * this -- it works from the panel's real physical layout the
             * whole time, so it's completely unaffected by rotation. */
            int px, py, pw, ph;
            if (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM) {
                px = w->x;
                py = 0;
                pw = w->len;
                ph = w->thickness;
            } else {
                px = 0;
                py = w->x;
                pw = w->thickness;
                ph = w->len;
            }
            double cx = px + pw / 2.0;
            double cy = py + ph / 2.0;
            int transposed = (p->rotate == 90 || p->rotate == 270);
            double content_w = transposed ? ph : pw;
            double content_h = transposed ? pw : ph;
            cairo_translate(p->buf_cr, cx, cy);
            if (p->rotate) {
                cairo_rotate(p->buf_cr, p->rotate * M_PI / 180.0);
            }
            cairo_translate(p->buf_cr, -content_w / 2.0, -content_h / 2.0);
            w->ops->paint(w, p->buf_cr);
            cairo_restore(p->buf_cr);
        }
    }
    cairo_surface_flush(p->buf_surface);

    /* p->cr is also used directly by widgets' measure() (cairo_text_extents
     * needs *some* cairo_t with the right font set, and measure() doesn't
     * get one passed in) -- so it can be poisoned by bad UTF-8 same as
     * buf_cr, even though it's mostly just the final blit target here. */
    if (cairo_status(p->cr) != CAIRO_STATUS_SUCCESS) {
        fprintf(stderr, "xispanel: panel '%s': cairo error (%s), recreating drawing context\n", p->name,
                cairo_status_to_string(cairo_status(p->cr)));
        cairo_destroy(p->cr);
        p->cr = cairo_create(p->surface);
        if (g_font_face) {
            cairo_set_font_face(p->cr, g_font_face);
        }
        cairo_set_font_size(p->cr, panel_text_size(p));
    }

    cairo_save(p->cr);
    cairo_set_operator(p->cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_surface(p->cr, p->buf_surface, 0, 0);
    cairo_paint(p->cr);
    cairo_restore(p->cr);
    cairo_surface_flush(p->surface);
    XFlush(g_dpy);
    p->dirty = 0;
}

/* ------------------------------------------------------------------ */
/* autohide state machine                                               */
/* ------------------------------------------------------------------ */

static void panel_autohide_enter(Panel *p)
{
    if (p->mode != MODE_AUTOHIDE) {
        return;
    }
    p->ah_hide_deadline_ms = 0;
    if (p->ah_state == AH_SHOWN || p->ah_state == AH_SHOWING) {
        return;
    }
    p->ah_state = AH_SHOWING;
    p->ah_anim_start_ms = now_ms();
    if (!p->mapped) {
        XMoveWindow(g_dpy, p->win, p->hidden_x, p->hidden_y);
        XMapWindow(g_dpy, p->win);
        XRaiseWindow(g_dpy, p->win);
        p->mapped = 1;
    }
}

static void panel_autohide_leave(Panel *p)
{
    if (p->mode != MODE_AUTOHIDE) {
        return;
    }
    if (p->ah_state == AH_SHOWN || p->ah_state == AH_SHOWING) {
        p->ah_hide_deadline_ms = now_ms() + AUTOHIDE_DELAY_MS;
    }
}

static int lerp_int(int from, int to, double t)
{
    return from + (int)((to - from) * t + 0.5);
}

/* Advances one autohide animation step for `p`. Returns 1 if `p` needs to
 * be woken again soon (mid-animation or waiting out the hide delay). */
static int panel_autohide_tick(Panel *p, uint64_t now)
{
    if (p->mode != MODE_AUTOHIDE) {
        return 0;
    }

    if (p->ah_hide_deadline_ms && now >= p->ah_hide_deadline_ms) {
        p->ah_hide_deadline_ms = 0;
        p->ah_state = AH_HIDING;
        p->ah_anim_start_ms = now;
    }

    if (p->ah_state == AH_SHOWING || p->ah_state == AH_HIDING) {
        double t = (double)(now - p->ah_anim_start_ms) / AUTOHIDE_ANIM_MS;
        if (t >= 1.0) {
            t = 1.0;
        }
        int from_x = (p->ah_state == AH_SHOWING) ? p->hidden_x : p->x;
        int from_y = (p->ah_state == AH_SHOWING) ? p->hidden_y : p->y;
        int to_x = (p->ah_state == AH_SHOWING) ? p->x : p->hidden_x;
        int to_y = (p->ah_state == AH_SHOWING) ? p->y : p->hidden_y;
        XMoveWindow(g_dpy, p->win, lerp_int(from_x, to_x, t), lerp_int(from_y, to_y, t));
        if (t >= 1.0) {
            if (p->ah_state == AH_SHOWING) {
                p->ah_state = AH_SHOWN;
            } else {
                p->ah_state = AH_HIDDEN;
                XUnmapWindow(g_dpy, p->win);
                p->mapped = 0;
            }
            return p->ah_hide_deadline_ms != 0;
        }
        return 1;
    }

    return p->ah_hide_deadline_ms != 0;
}

/* ------------------------------------------------------------------ */
/* panel lifecycle                                                      */
/* ------------------------------------------------------------------ */

static void panel_destroy_widgets(Panel *p)
{
    for (int i = 0; i < p->n_widgets; i++) {
        PanelWidget *w = &p->widgets[i];
        if (w->ops->destroy) {
            w->ops->destroy(w);
        }
        free(w->priv);
    }
    p->n_widgets = 0;
}

static void panel_deactivate(Panel *p)
{
    panel_destroy_widgets(p);
    if (p->bg_image_surface) {
        cairo_surface_destroy(p->bg_image_surface);
        p->bg_image_surface = NULL;
    }
    if (p->buf_cr) {
        cairo_destroy(p->buf_cr);
        p->buf_cr = NULL;
    }
    if (p->buf_surface) {
        cairo_surface_destroy(p->buf_surface);
        p->buf_surface = NULL;
    }
    if (p->cr) {
        cairo_destroy(p->cr);
        p->cr = NULL;
    }
    if (p->surface) {
        cairo_surface_destroy(p->surface);
        p->surface = NULL;
    }
    if (p->sensor_win != None) {
        XDestroyWindow(g_dpy, p->sensor_win);
        p->sensor_win = None;
    }
    if (p->win != None) {
        XDestroyWindow(g_dpy, p->win);
        p->win = None;
    }
    if (p->cmap != None && p->cmap != DefaultColormap(g_dpy, g_screen)) {
        XFreeColormap(g_dpy, p->cmap);
        p->cmap = None;
    }
}

static void panel_activate(Panel *p)
{
    panel_resolve_geometry(p);
    panel_pick_visual(p);
    panel_load_bg_image(p);

    int start_x = p->x, start_y = p->y;
    p->ah_state = AH_HIDDEN;
    p->ah_hide_deadline_ms = 0;
    if (p->mode == MODE_AUTOHIDE) {
        start_x = p->hidden_x;
        start_y = p->hidden_y;
    }

    p->win = panel_create_window(p, start_x, start_y, p->w, p->h);
    panel_apply_strut(p);
    panel_create_surface(p);

    for (int i = 0; i < p->n_widgets; i++) {
        p->widgets[i].panel = p;
    }
    panel_layout(p);

    if (p->mode == MODE_AUTOHIDE) {
        p->sensor_win = panel_create_sensor(p);
        p->mapped = 0;
    } else {
        XMapWindow(g_dpy, p->win);
        XRaiseWindow(g_dpy, p->win);
        p->mapped = 1;
    }
    p->dirty = 1;
}

static Panel *find_panel(const char *name)
{
    for (int i = 0; i < MAX_PANELS; i++) {
        if (g_panels[i].in_use && strcmp(g_panels[i].name, name) == 0) {
            return &g_panels[i];
        }
    }
    return NULL;
}

static Panel *alloc_panel(const char *name, const char *output)
{
    for (int i = 0; i < MAX_PANELS; i++) {
        if (!g_panels[i].in_use) {
            Panel *p = &g_panels[i];
            memset(p, 0, sizeof(*p));
            p->in_use = 1;
            snprintf(p->name, sizeof(p->name), "%s", name);
            snprintf(p->output, sizeof(p->output), "%s", output);
            p->edge = EDGE_TOP;
            p->pct = 100;
            p->thickness_cfg = 32;
            p->mode = MODE_DOCK;
            p->tooltip_delay_ms = 500;
            p->tooltip_close_delay_ms = 300;
            p->bg_r = 0.12;
            p->bg_g = 0.12;
            p->bg_b = 0.12;
            p->bg_a = 0.85;
            p->fg_r = p->fg_g = p->fg_b = 0.93;
            p->fg_a = 1.0;
            /* Live system-theme colors, if any -- overwrites just the
             * channels detect_system_colors() actually found (bg and/or
             * fg independently), leaving the hardcoded fallback above for
             * whichever it didn't. A THEME line's own bg=/fg= (applied
             * later, from load_config()) always wins over either. */
            detect_system_colors(&p->bg_r, &p->bg_g, &p->bg_b, &p->fg_r, &p->fg_g, &p->fg_b);
            /* Same THEME-overrides-detected-overrides-hardcoded layering
             * as colors above -- 0 here means "undetected", every user of
             * font_size_px already treats that as "fall back to my own
             * existing size" (see the field's doc comment in xispanel.h). */
            p->font_size_px = detect_system_font_size_px();
            p->spacing = 4;
            return p;
        }
    }
    return NULL;
}

static void panel_add_widget(Panel *p, int order, const char *type, const char *kvline)
{
    (void)order; /* config lines are already emitted in the desired order */
    if (p->n_widgets >= MAX_WIDGETS) {
        fprintf(stderr, "xispanel: panel '%s': too many widgets, ignoring '%s'\n", p->name, type);
        return;
    }
    const PanelWidgetOps *ops = find_widget_ops(type);
    if (!ops) {
        fprintf(stderr, "xispanel: panel '%s': unknown widget type '%s'\n", p->name, type);
        return;
    }
    PanelWidget *w = &p->widgets[p->n_widgets++];
    memset(w, 0, sizeof(*w));
    w->ops = ops;
    w->panel = p;
    snprintf(w->config_kv, sizeof(w->config_kv), "%s", kvline ? kvline : "");
    if (ops->priv_size > 0) {
        w->priv = calloc(1, ops->priv_size);
    }
    if (ops->init) {
        ops->init(w);
    }
}

/* ------------------------------------------------------------------ */
/* config ($XDG_CONFIG_HOME/xispanel.conf)                              */
/* ------------------------------------------------------------------ */

static enum edge parse_edge(const char *s)
{
    if (!strcmp(s, "bottom")) {
        return EDGE_BOTTOM;
    }
    if (!strcmp(s, "left")) {
        return EDGE_LEFT;
    }
    if (!strcmp(s, "right")) {
        return EDGE_RIGHT;
    }
    return EDGE_TOP;
}

static enum panel_mode parse_mode(const char *s)
{
    if (!strcmp(s, "overlay")) {
        return MODE_OVERLAY;
    }
    if (!strcmp(s, "autohide")) {
        return MODE_AUTOHIDE;
    }
    return MODE_DOCK;
}

static void apply_panel_kv(Panel *p, const char *kvline)
{
    char buf[64];
    if (kv_get(kvline, "edge", buf, sizeof(buf))) {
        p->edge = parse_edge(buf);
    }
    p->pct = kv_get_int(kvline, "pct", p->pct);
    if (p->pct < 1) {
        p->pct = 1;
    }
    if (p->pct > 100) {
        p->pct = 100;
    }
    p->thickness_cfg = kv_get_int(kvline, "thickness", p->thickness_cfg);
    if (kv_get(kvline, "mode", buf, sizeof(buf))) {
        p->mode = parse_mode(buf);
    }
    if (kv_get(kvline, "rotate", buf, sizeof(buf))) {
        int r = atoi(buf);
        if (r == 0 || r == 90 || r == 180 || r == 270) {
            p->rotate = r;
        } else {
            fprintf(stderr, "xispanel: panel '%s': invalid rotate=%s (must be 0, 90, 180, or 270), ignoring\n",
                    p->name, buf);
        }
    }
    p->tooltip_delay_ms = kv_get_int(kvline, "tooltip_delay", p->tooltip_delay_ms);
    if (p->tooltip_delay_ms < 0) {
        p->tooltip_delay_ms = 0;
    }
    p->tooltip_close_delay_ms = kv_get_int(kvline, "tooltip_close_delay", p->tooltip_close_delay_ms);
    if (p->tooltip_close_delay_ms < 0) {
        p->tooltip_close_delay_ms = 0;
    }
    p->tooltip_reuse_window = kv_get_int(kvline, "tooltip_reuse", p->tooltip_reuse_window) != 0;
}

static void apply_theme_kv(Panel *p, const char *kvline)
{
    char buf[32];
    if (kv_get(kvline, "bg", buf, sizeof(buf))) {
        parse_hex_color(buf, &p->bg_r, &p->bg_g, &p->bg_b, &p->bg_a);
    }
    if (kv_get(kvline, "fg", buf, sizeof(buf))) {
        parse_hex_color(buf, &p->fg_r, &p->fg_g, &p->fg_b, &p->fg_a);
    }
    p->spacing = kv_get_int(kvline, "spacing", p->spacing);
    if (kv_get(kvline, "font_size", buf, sizeof(buf))) {
        p->font_size_px = atof(buf);
    }
    /* Optional 9-slice background image, replacing the bg_r/g/b/a color
     * above entirely once it loads (panel_load_bg_image(), called from
     * panel_activate() -- not here, since that needs Imlib2/an open X
     * display that may not exist yet while just parsing config text).
     * bg_slice is the (also optional) sidecar measurements file; missing
     * it just means a plain full-image stretch, not an error. */
    kv_get(kvline, "bg_image", p->bg_image_path, sizeof(p->bg_image_path));
    kv_get(kvline, "bg_slice", p->bg_slice_path, sizeof(p->bg_slice_path));
}

static void load_config(void)
{
    FILE *f = fopen(g_configpath, "r");
    if (!f) {
        return;
    }
    char line[LINE_MAX_LEN];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = 0;
        }
        if (len == 0 || line[0] == '#') {
            continue;
        }

        /* Splits on any run of spaces/tabs (not just tab) -- join_fields()
         * below always reassembles the kv-value tail with single spaces
         * between tokens regardless of how many pieces it was split into,
         * so this is a lossless normalization, not a behavior change: a
         * config line can now be hand-edited with plain spaces instead of
         * requiring literal tabs between fields. */
        char *fields[48];
        int nf = 0;
        char *p = line;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p) {
            fields[nf++] = p;
        }
        while (nf < 48) {
            while (*p && *p != ' ' && *p != '\t') {
                p++;
            }
            if (!*p) {
                break;
            }
            *p = 0;
            p++;
            while (*p == ' ' || *p == '\t') {
                p++;
            }
            if (!*p) {
                break;
            }
            fields[nf++] = p;
        }
        if (nf == 0) {
            continue; /* line was whitespace-only after trimming */
        }

        if (strcmp(fields[0], "PANEL") == 0 && nf >= 3) {
            Panel *pan = alloc_panel(fields[1], fields[2]);
            if (!pan) {
                fprintf(stderr, "xispanel: config: too many panels, ignoring '%s'\n", fields[1]);
                continue;
            }
            char kvline[LINE_MAX_LEN];
            join_fields(fields, 3, nf, kvline, sizeof(kvline));
            apply_panel_kv(pan, kvline);
        } else if (strcmp(fields[0], "WIDGET") == 0 && nf >= 4) {
            Panel *pan = find_panel(fields[1]);
            if (!pan) {
                fprintf(stderr, "xispanel: config: WIDGET references unknown panel '%s'\n", fields[1]);
                continue;
            }
            char kvline[LINE_MAX_LEN];
            join_fields(fields, 4, nf, kvline, sizeof(kvline));
            panel_add_widget(pan, atoi(fields[2]), fields[3], kvline);
        } else if (strcmp(fields[0], "THEME") == 0 && nf >= 2) {
            Panel *pan = find_panel(fields[1]);
            if (!pan) {
                fprintf(stderr, "xispanel: config: THEME references unknown panel '%s'\n", fields[1]);
                continue;
            }
            char kvline[LINE_MAX_LEN];
            join_fields(fields, 2, nf, kvline, sizeof(kvline));
            apply_theme_kv(pan, kvline);
        } else {
            fprintf(stderr, "xispanel: config: skipping unknown line: '%s'\n", line);
        }
    }
    fclose(f);
}

static void reload_all_panels(void)
{
    panel_menu_close(); /* about to invalidate every Panel/PanelWidget it could reference */
    tooltip_close();
    for (int i = 0; i < MAX_PANELS; i++) {
        if (g_panels[i].in_use) {
            panel_deactivate(&g_panels[i]);
        }
    }
    memset(g_panels, 0, sizeof(g_panels));
    load_config();
    for (int i = 0; i < MAX_PANELS; i++) {
        if (g_panels[i].in_use) {
            panel_activate(&g_panels[i]);
        }
    }
}

/* ------------------------------------------------------------------ */
/* IPC (line-JSON over $XDG_RUNTIME_DIR/xispanel-ctl.sock)              */
/* ------------------------------------------------------------------ */

/* sockaddr_un.sun_path is only 108 bytes on Linux, well short of PATH_MAX
 * -- an unusually long $XDG_RUNTIME_DIR would otherwise get silently
 * truncated by snprintf, and two differently-long paths could then
 * collide on the same truncated socket name. Fail loudly instead. */
static int build_sockaddr_un(struct sockaddr_un *addr, const char *path)
{
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr->sun_path)) {
        fprintf(stderr, "xispanel: socket path too long (>%zu bytes): %s\n", sizeof(addr->sun_path) - 1, path);
        return -1;
    }
    memcpy(addr->sun_path, path, strlen(path) + 1);
    return 0;
}

/* Same minimal flat-JSON helpers as xisguard-ctl -- good enough for the
 * request shapes this protocol actually needs, no parser dependency. */
static int json_get_str(const char *msg, const char *key, char *dst, size_t dst_sz)
{
    dst[0] = 0;
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(msg, needle);
    if (!p) {
        return 0;
    }
    p += strlen(needle);
    while (*p == ' ') {
        p++;
    }
    if (*p != '"') {
        return 0;
    }
    p++;
    const char *end = strchr(p, '"');
    if (!end) {
        return 0;
    }
    size_t len = (size_t)(end - p);
    if (len >= dst_sz) {
        len = dst_sz - 1;
    }
    memcpy(dst, p, len);
    dst[len] = 0;
    return 1;
}

static void handle_ipc_message(const char *req, char *resp, size_t resp_sz)
{
    char cmd[32];
    json_get_str(req, "cmd", cmd, sizeof(cmd));

    if (strcmp(cmd, "PING") == 0) {
        snprintf(resp, resp_sz, "{\"ok\":true,\"pong\":true}\n");
    } else if (strcmp(cmd, "GET_STATUS") == 0) {
        int n_panels = 0;
        for (int i = 0; i < MAX_PANELS; i++) {
            if (g_panels[i].in_use) {
                n_panels++;
            }
        }
        snprintf(resp, resp_sz, "{\"ok\":true,\"version\":\"%s\",\"panels\":%d}\n", XISPANEL_VERSION, n_panels);
    } else if (strcmp(cmd, "RELOAD") == 0) {
        reload_all_panels();
        snprintf(resp, resp_sz, "{\"ok\":true}\n");
    } else if (strcmp(cmd, "QUIT") == 0) {
        g_quit = 1;
        snprintf(resp, resp_sz, "{\"ok\":true}\n");
    } else {
        snprintf(resp, resp_sz, "{\"ok\":false,\"error\":\"unknown command\"}\n");
    }
}

static int ipc_client_request(const char *sockpath, const char *req)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("xispanel: socket");
        return 1;
    }
    struct sockaddr_un addr;
    if (build_sockaddr_un(&addr, sockpath) != 0) {
        close(fd);
        return 1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "xispanel: could not connect to daemon (%s)\n", sockpath);
        close(fd);
        return 1;
    }
    if (write(fd, req, strlen(req)) < 0) {
        perror("xispanel: write");
    }
    shutdown(fd, SHUT_WR);

    char buf[IPC_MAX_LEN];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = 0;
        fputs(buf, stdout);
    }
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main loop                                                            */
/* ------------------------------------------------------------------ */

static void handle_signal(int sig)
{
    (void)sig;
    g_quit = 1;
}

/* xispanel constantly queries properties/attributes of *other*
 * processes' windows (tasklist/winctl polling every open window's
 * title/icon/state, thumb.c's live captures, ...), any of which can
 * close between being listed and being queried -- Xlib's default error
 * handler calls exit() on any X protocol error, which would take down
 * the whole panel daemon over what's actually a routine, expected race,
 * not a bug. Every well-behaved WM/panel/taskbar installs a permissive
 * handler for exactly this reason; this just logs and continues. thumb.c
 * additionally swaps in its own temporary handler around composite calls
 * (to detect *its own* failures without logging noise for the common
 * "window isn't redirected" case), but always restores this one
 * afterward -- this is the actual default for the rest of the process. */
static int x_error_handler(Display *dpy, XErrorEvent *ev)
{
    char text[64];
    XGetErrorText(dpy, ev->error_code, text, sizeof(text));
    fprintf(stderr, "xispanel: ignoring X error: %s (request %d.%d, resource 0x%lx)\n", text, ev->request_code,
            ev->minor_code, ev->resourceid);
    return 0;
}

static Panel *find_panel_by_window(Window win, int *is_sensor)
{
    for (int i = 0; i < MAX_PANELS; i++) {
        if (!g_panels[i].in_use) {
            continue;
        }
        if (g_panels[i].win == win) {
            *is_sensor = 0;
            return &g_panels[i];
        }
        if (g_panels[i].sensor_win == win) {
            *is_sensor = 1;
            return &g_panels[i];
        }
    }
    return NULL;
}

static void dispatch_button(Panel *p, int button, int x, int y, int root_x, int root_y)
{
    int axis_pos = (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM) ? x : y;
    int cross_pos = (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM) ? y : x;
    for (int i = 0; i < p->n_widgets; i++) {
        PanelWidget *w = &p->widgets[i];
        if (axis_pos >= w->x && axis_pos < w->x + w->len) {
            if (w->ops->on_button) {
                int local = axis_pos - w->x;
                w->ops->on_button(w, button, local, cross_pos, root_x, root_y);
            }
            return;
        }
    }
}

static int run_as_daemon(const char *sockpath)
{
    g_dpy = XOpenDisplay(NULL);
    if (!g_dpy) {
        fprintf(stderr, "xispanel: could not open the X display\n");
        return 1;
    }
    XSetErrorHandler(x_error_handler);
    g_screen = DefaultScreen(g_dpy);
    g_root = RootWindow(g_dpy, g_screen);

    imlib_context_set_display(g_dpy);
    imlib_context_set_visual(DefaultVisual(g_dpy, g_screen));
    imlib_context_set_colormap(DefaultColormap(g_dpy, g_screen));
    imlib_context_set_anti_alias(1);
    imlib_context_set_dither(1);

    detect_system_font_family(g_font_family, sizeof(g_font_family));
    if (init_font(g_font_family) != 0) {
        fprintf(stderr, "xispanel: could not resolve a default font via fontconfig\n");
    } else if (g_font_family[0]) {
        fprintf(stderr, "xispanel: using system font '%s'\n", g_font_family);
    }

    ewmh_init_atoms();
    modtap_init(); /* bare-modifier ("tap Meta alone") hotkeys, see hotkey.c/modtap.c */
    g_atom_net_wm_state = XInternAtom(g_dpy, "_NET_WM_STATE", False);
    g_atom_net_wm_state_skip_taskbar = XInternAtom(g_dpy, "_NET_WM_STATE_SKIP_TASKBAR", False);
    g_atom_net_wm_state_skip_pager = XInternAtom(g_dpy, "_NET_WM_STATE_SKIP_PAGER", False);
    g_atom_net_wm_desktop = XInternAtom(g_dpy, "_NET_WM_DESKTOP", False);

    int rr_error_base;
    if (!XRRQueryExtension(g_dpy, &g_rr_event_base, &rr_error_base)) {
        fprintf(stderr, "xispanel: RandR extension unavailable, named outputs won't work\n");
        g_rr_event_base = -1;
    } else {
        XRRSelectInput(g_dpy, g_root, RRScreenChangeNotifyMask);
    }

    unlink(sockpath);
    int listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    if (build_sockaddr_un(&addr, sockpath) != 0) {
        return 1;
    }
    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(listenfd, 16) != 0) {
        perror("xispanel: bind/listen");
        return 1;
    }
    chmod(sockpath, 0600);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);
    /* run_detached()'s children (launcher widget clicks) are never
     * waitpid()'d -- ignoring SIGCHLD makes the kernel reap them itself
     * instead of leaving zombies, same pattern xisback uses. */
    signal(SIGCHLD, SIG_IGN);
    fcntl(listenfd, F_SETFD, FD_CLOEXEC);
    fcntl(ConnectionNumber(g_dpy), F_SETFD, FD_CLOEXEC);

    write_default_config_if_missing();
    reload_all_panels();
    XFlush(g_dpy);

    int xfd = ConnectionNumber(g_dpy);
    int modtapfd = modtap_fd();
    while (!g_quit) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listenfd, &rfds);
        FD_SET(xfd, &rfds);
        int maxfd = listenfd > xfd ? listenfd : xfd;
        if (modtapfd >= 0) {
            FD_SET(modtapfd, &rfds);
            if (modtapfd > maxfd) {
                maxfd = modtapfd;
            }
        }

        uint64_t now = now_ms();
        long timeout_ms = -1;
        int any_animating = 0;
        uint64_t soonest_tick = 0;

        for (int i = 0; i < MAX_PANELS; i++) {
            Panel *p = &g_panels[i];
            if (!p->in_use) {
                continue;
            }
            if (p->mode == MODE_AUTOHIDE && (p->ah_state == AH_SHOWING || p->ah_state == AH_HIDING || p->ah_hide_deadline_ms)) {
                any_animating = 1;
            }
            for (int j = 0; j < p->n_widgets; j++) {
                uint64_t t = p->widgets[j].next_tick_ms;
                if (t != 0 && (soonest_tick == 0 || t < soonest_tick)) {
                    soonest_tick = t;
                }
            }
        }
        if (any_animating) {
            timeout_ms = 33;
        }
        if (soonest_tick != 0) {
            long delta = (long)(soonest_tick > now ? soonest_tick - now : 0);
            if (timeout_ms < 0 || delta < timeout_ms) {
                timeout_ms = delta;
            }
        }
        uint64_t tooltip_wake = tooltip_next_wake_ms();
        if (tooltip_wake != 0) {
            long delta = (long)(tooltip_wake > now ? tooltip_wake - now : 0);
            if (timeout_ms < 0 || delta < timeout_ms) {
                timeout_ms = delta;
            }
        }
        uint64_t menu_wake = panel_menu_next_wake_ms();
        if (menu_wake != 0) {
            long delta = (long)(menu_wake > now ? menu_wake - now : 0);
            if (timeout_ms < 0 || delta < timeout_ms) {
                timeout_ms = delta;
            }
        }

        struct timeval tv;
        struct timeval *tvp = NULL;
        if (timeout_ms >= 0) {
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            tvp = &tv;
        }

        int r = select(maxfd + 1, &rfds, NULL, NULL, tvp);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (r > 0 && FD_ISSET(listenfd, &rfds)) {
            int cfd = accept(listenfd, NULL, NULL);
            if (cfd >= 0) {
                struct timeval tvto = {5, 0};
                setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tvto, sizeof(tvto));
                setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tvto, sizeof(tvto));
                char reqbuf[IPC_MAX_LEN];
                ssize_t n = read(cfd, reqbuf, sizeof(reqbuf) - 1);
                if (n > 0) {
                    reqbuf[n] = 0;
                    char resp[IPC_MAX_LEN];
                    handle_ipc_message(reqbuf, resp, sizeof(resp));
                    if (write(cfd, resp, strlen(resp)) < 0) {
                        perror("xispanel: write");
                    }
                }
                close(cfd);
            }
        }

        if (r > 0 && FD_ISSET(xfd, &rfds)) {
            while (XPending(g_dpy)) {
                XEvent ev;
                XNextEvent(g_dpy, &ev);
                if (g_rr_event_base >= 0 && ev.type == g_rr_event_base + RRScreenChangeNotify) {
                    XRRUpdateConfiguration(&ev);
                    reload_all_panels();
                    XFlush(g_dpy);
                } else if (hotkey_handle_event(&ev)) {
                    /* consumed by a registered global hotkey -- see hotkey.c */
                } else if (thumb_handle_event(&ev)) {
                    /* an XDamage notification for a watched thumbnail window --
                     * see thumb.c/tooltip.c's tooltip_tick() */
                } else if (panel_menu_handle_event(&ev)) {
                    /* consumed by the open context menu */
                } else if (tooltip_handle_event(&ev)) {
                    /* consumed by the tooltip popup (just Expose -- it
                     * takes no grab and never handles clicks) */
                } else if (ev.type == ButtonPress) {
                    int is_sensor = 0;
                    Panel *p = find_panel_by_window(ev.xbutton.window, &is_sensor);
                    if (p && !is_sensor) {
                        tooltip_close();
                        dispatch_button(p, (int)ev.xbutton.button, ev.xbutton.x, ev.xbutton.y, ev.xbutton.x_root, ev.xbutton.y_root);
                    }
                } else if (ev.type == MotionNotify) {
                    int is_sensor = 0;
                    Panel *p = find_panel_by_window(ev.xmotion.window, &is_sensor);
                    if (p && !is_sensor) {
                        int axis_pos = (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM) ? ev.xmotion.x : ev.xmotion.y;
                        tooltip_notice_motion(p, axis_pos);
                    }
                } else if (ev.type == EnterNotify) {
                    int is_sensor = 0;
                    Panel *p = find_panel_by_window(ev.xcrossing.window, &is_sensor);
                    if (p) {
                        panel_autohide_enter(p);
                    }
                } else if (ev.type == LeaveNotify) {
                    int is_sensor = 0;
                    Panel *p = find_panel_by_window(ev.xcrossing.window, &is_sensor);
                    if (p && !is_sensor) {
                        panel_autohide_leave(p);
                        tooltip_notice_leave(p);
                    }
                } else if (ev.type == Expose) {
                    int is_sensor = 0;
                    Panel *p = find_panel_by_window(ev.xexpose.window, &is_sensor);
                    if (p && !is_sensor) {
                        p->dirty = 1;
                    }
                }
            }
        }

        if (modtapfd >= 0 && r > 0 && FD_ISSET(modtapfd, &rfds)) {
            modtap_process();
        }

        now = now_ms();
        tooltip_tick(now);
        panel_menu_tick(now);
        mpris_poll(now);
        sni_poll(now);
        for (int i = 0; i < MAX_PANELS; i++) {
            Panel *p = &g_panels[i];
            if (!p->in_use) {
                continue;
            }
            panel_autohide_tick(p, now);
            for (int j = 0; j < p->n_widgets; j++) {
                PanelWidget *w = &p->widgets[j];
                if (w->next_tick_ms != 0 && now >= w->next_tick_ms && w->ops->on_tick) {
                    w->ops->on_tick(w, now);
                    p->dirty = 1;
                }
            }
            if (p->dirty && p->mapped) {
                panel_layout(p);
                panel_repaint(p);
            }
        }
        /* Autohide's XMoveWindow/XMapWindow/XUnmapWindow calls above (and
         * panel_autohide_enter()'s, from the event-handling block earlier
         * in this iteration) are buffered by Xlib until something flushes
         * them. Xlib only auto-flushes from XPending()/XNextEvent(), which
         * we only call when the X fd is already readable -- without this,
         * a pure animation/timeout-driven tick (no incoming X event) could
         * sit in the client buffer indefinitely, waiting for unrelated
         * server traffic to nudge it out. */
        XFlush(g_dpy);
    }

    panel_menu_close();
    tooltip_close();
    for (int i = 0; i < MAX_PANELS; i++) {
        if (g_panels[i].in_use) {
            panel_deactivate(&g_panels[i]);
        }
    }
    close(listenfd);
    unlink(sockpath);
    if (g_font_face) {
        cairo_font_face_destroy(g_font_face);
    }
    if (g_ft_face) {
        FT_Done_Face(g_ft_face);
    }
    if (g_ft_lib) {
        FT_Done_FreeType(g_ft_lib);
    }
    XCloseDisplay(g_dpy);
    return 0;
}

/* ------------------------------------------------------------------ */
/* entry point                                                          */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [options]\n"
            "\n"
            "  --reload    tell the running daemon to reload its config\n"
            "  --quit      stop the running daemon\n"
            "  --version   print version and exit\n"
            "\n"
            "With no options, runs as the daemon (or does nothing but report\n"
            "'already running' if one is active). Panels/widgets/theme are\n"
            "configured in $XDG_CONFIG_HOME/xispanel.conf -- see PROTOCOL.md.\n",
            prog);
}

int main(int argc, char **argv)
{
    /* LC_TIME affects strftime()'s %A/%B (full weekday/month names) --
     * clock's short "%H:%M" panel format is locale-independent, but its
     * tooltip's full "weekday, day de month de year" isn't. */
    setlocale(LC_TIME, "");

    const char *rundir = getenv("XDG_RUNTIME_DIR");
    if (!rundir || !*rundir) {
        rundir = "/tmp";
    }
    char sockpath[PATH_MAX];
    char lockpath[PATH_MAX];
    snprintf(sockpath, sizeof(sockpath), "%s/xispanel-ctl.sock", rundir);
    snprintf(lockpath, sizeof(lockpath), "%s/xispanel.lock", rundir);

    const char *xdg_config = getenv("XDG_CONFIG_HOME");
    if (xdg_config && *xdg_config) {
        mkdir(xdg_config, 0700);
        snprintf(g_configpath, sizeof(g_configpath), "%s/xispanel.conf", xdg_config);
    } else {
        const char *home = getenv("HOME");
        if (!home || !*home) {
            home = "/tmp";
        }
        char configdir[PATH_MAX];
        snprintf(configdir, sizeof(configdir), "%s/.config", home);
        mkdir(configdir, 0700);
        snprintf(g_configpath, sizeof(g_configpath), "%s/xispanel.conf", configdir);
    }

    if (argc > 1) {
        if (!strcmp(argv[1], "--version")) {
            printf("xispanel %s\n", XISPANEL_VERSION);
            return 0;
        }
        if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
            usage(argv[0]);
            return 0;
        }
        if (!strcmp(argv[1], "--quit")) {
            return ipc_client_request(sockpath, "{\"cmd\":\"QUIT\"}\n");
        }
        if (!strcmp(argv[1], "--reload")) {
            return ipc_client_request(sockpath, "{\"cmd\":\"RELOAD\"}\n");
        }
        fprintf(stderr, "xispanel: unknown option '%s'\n", argv[1]);
        usage(argv[0]);
        return 1;
    }

    int lockfd = open(lockpath, O_CREAT | O_RDWR, 0600);
    if (lockfd < 0) {
        perror("xispanel: open lock");
        return 1;
    }
    if (flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
        close(lockfd);
        fprintf(stderr, "xispanel: already running\n");
        return 1;
    }

    return run_as_daemon(sockpath);
}
