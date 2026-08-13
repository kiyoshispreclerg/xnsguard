/*
 * xisback - minimal desktop-layer wallpaper daemon.
 *
 * Creates one or more windows tagged _NET_WM_WINDOW_TYPE_DESKTOP so
 * compositing window managers (KWin included) have something to composite
 * for the desktop layer -- without such a window a compositor just clears
 * that area to black instead of reading the X root pixmap the way
 * feh/xwallpaper/nitrogen expect.
 *
 * Each wallpaper "layer" is keyed by (output, desktop):
 *   - output: "*" (spans the whole virtual screen) or an XRandR output
 *     name (e.g. "HDMI-1"), in which case the window is sized/positioned
 *     to exactly that output's CRTC geometry.
 *   - desktop: "*" (sticky, _NET_WM_DESKTOP = 0xFFFFFFFF, shown on every
 *     virtual desktop) or a 0-based virtual desktop index (_NET_WM_DESKTOP
 *     = N); the window manager takes care of showing/hiding it when the
 *     desktop is switched, this program does not track desktop switches
 *     itself.
 *
 * Layers never need to be stacking-ordered against each other as long as
 * the caller doesn't define overlapping (output, desktop) coverage for the
 * same moment in time -- it is the caller's responsibility (see
 * PROTOCOL.md) to keep that consistent, e.g. by using --clear-all before
 * switching between "single wallpaper" and "per-output" mode.
 *
 * A source can be a single image file (static) or a directory (slideshow,
 * cycled every --interval seconds, no fade/effects; sorted alphabetically
 * by default or, with --shuffle, in random order that reshuffles every
 * time it wraps around).
 *
 * Only one instance runs per session (guarded by an flock'd lock file under
 * XDG_RUNTIME_DIR). Any further invocation - including simply running this
 * binary again with new arguments - talks to the already running instance
 * over a Unix socket instead of spawning a second process. See
 * PROTOCOL.md for the wire format, meant to be driven from other tools
 * (e.g. a Python GUI) without needing to link against this program.
 *
 * The daemon persists every successful SET/CLEAR/CLEARALL to
 * $XDG_CONFIG_HOME/xisback.conf (fallback ~/.config/xisback.conf) and
 * replays it on startup, so a plain `xisback` with no arguments (e.g. run
 * from a login autostart entry) comes back up showing whatever was last
 * configured instead of a blank desktop.
 */

#include <Imlib2.h>
#include <X11/Xatom.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/Xrandr.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <malloc.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
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

#define XISBACK_VERSION "0.3.0"
#define MAX_LAYERS 32
#define LINE_MAX_LEN (PATH_MAX + 256)
#define FADE_MS_MIN 0
#define FADE_MS_MAX 5000
#define FADE_TICK_USEC 33000 /* ~30fps while a crossfade is in flight */
#define ACTION_CMD_LEN 512
#define DOUBLE_CLICK_MS 400

enum mode { MODE_FILL, MODE_STRETCH };

/* Click action commands travel as tab-separated protocol fields and
 * newline-terminated config lines, so a literal tab/CR/LF embedded in one
 * would corrupt the parsing of whatever comes after it. Flatten those to
 * spaces rather than rejecting the command outright -- multi-line shell
 * isn't supported here anyway (point the command at a script if you need
 * that). */
static void sanitize_action_cmd(char *s)
{
    for (char *p = s; *p; p++) {
        if (*p == '\t' || *p == '\n' || *p == '\r') {
            *p = ' ';
        }
    }
}

static int clamp_fade_ms(int ms)
{
    if (ms < FADE_MS_MIN) {
        return FADE_MS_MIN;
    }
    if (ms > FADE_MS_MAX) {
        return FADE_MS_MAX;
    }
    return ms;
}

typedef struct {
    int in_use;
    char output[64]; /* "*" or an XRandR output name */
    int desktop; /* -1 for "*" (sticky), else 0-based virtual desktop index */
    enum mode mode;
    int interval; /* seconds between slideshow switches; 0 = never auto-advance */
    int shuffle; /* 0 = alphabetical order, 1 = random order (reshuffled each wrap) */
    int fade_ms; /* crossfade duration on image switch, ms; 0 = instant swap */
    char source[PATH_MAX]; /* image file or directory */

    Window win;
    Pixmap cur_pixmap;
    int x, y, width, height;

    /* in-flight crossfade transition (only meaningful while fading != 0):
     * fade_win sits on top of win, showing next_pixmap at increasing
     * opacity; the compositor does the actual blending. Once the fade
     * completes, fade_win/next_pixmap are promoted into win/cur_pixmap. */
    int fading;
    Window fade_win;
    Pixmap fade_pixmap;
    struct timespec fade_start;

    char **images;
    int n_images;
    int img_idx;
    time_t next_switch; /* 0 = no pending auto-advance */
} Layer;

static Display *g_dpy;
static Window g_root;
static int g_screen;
static int g_depth;
static Visual *g_visual;
static Colormap g_cmap;
static GC g_gc;
static int g_rr_event_base;
static volatile sig_atomic_t g_quit = 0;
static Layer g_layers[MAX_LAYERS];
static char g_configpath[PATH_MAX];
static Atom g_atom_opacity;

/* Click actions are global (not per-layer): one shell command per mouse
 * button, plus one for double-click (any button). Run via `sh -c` with
 * XISBACK_OUTPUT/XISBACK_DESKTOP set to the clicked layer's key, so a
 * single generic command (e.g. `xisback --next`) can react to whichever
 * layer was clicked without the daemon needing to know what "next
 * wallpaper" even means for click purposes. */
static char g_action_left[ACTION_CMD_LEN];
static char g_action_right[ACTION_CMD_LEN];
static char g_action_middle[ACTION_CMD_LEN];
static char g_action_double[ACTION_CMD_LEN];

/* Single in-flight click debounce: waiting to see if a second same-button
 * click arrives within DOUBLE_CLICK_MS before deciding it was a single
 * click. Only used when a double-click action is actually configured --
 * otherwise single clicks fire immediately with zero added latency. */
static int g_click_pending_button; /* 0 = none */
static struct timespec g_click_pending_time;
static char g_click_pending_output[64];
static int g_click_pending_desktop;

/* ------------------------------------------------------------------ */
/* command line / wire protocol                                       */
/* ------------------------------------------------------------------ */

typedef enum { CMD_NONE, CMD_SET, CMD_CLEAR, CMD_CLEARALL, CMD_LIST, CMD_PING, CMD_QUIT,
               CMD_NEXT, CMD_SETACTIONS, CMD_GETACTIONS } CmdType;

typedef struct {
    CmdType type;
    char output[64];
    char desktop_str[16];
    int desktop;
    char mode_str[16];
    enum mode mode;
    int interval;
    int shuffle;
    int fade_ms;
    char source[PATH_MAX];

    /* CMD_SETACTIONS: only the *_set flags that are true get applied on top
     * of whatever the daemon currently has (run_as_client fetches the
     * current bindings first) -- so `--on-left-click foo` alone doesn't
     * wipe out the other three. */
    char action_left[ACTION_CMD_LEN];
    char action_right[ACTION_CMD_LEN];
    char action_middle[ACTION_CMD_LEN];
    char action_double[ACTION_CMD_LEN];
    int action_left_set, action_right_set, action_middle_set, action_double_set;
} Command;

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [options] [image-or-folder]\n"
            "\n"
            "  --output NAME|*     target xrandr output (default *: all)\n"
            "  --desktop N|*       target virtual desktop, 0-based (default *: all)\n"
            "  --mode fill|stretch scaling mode (default fill)\n"
            "  --interval SECONDS  slideshow interval, folders only (default 300)\n"
            "  --shuffle           slideshow in random order (default: alphabetical)\n"
            "  --fade SECONDS      crossfade duration on image switch, 0-5 (default 1)\n"
            "  --clear             remove the given (output,desktop) layer\n"
            "  --clear-all         remove all layers\n"
            "  --list              list active layers\n"
            "  --next              advance the given layer's slideshow now (no-op if\n"
            "                      it isn't a slideshow); honors --output/--desktop\n"
            "  --on-left-click CMD, --on-right-click CMD, --on-middle-click CMD,\n"
            "  --on-double-click CMD\n"
            "                      shell command to run when a layer's window is\n"
            "                      clicked (global, not per-layer); empty string\n"
            "                      clears it. Runs with XISBACK_OUTPUT/\n"
            "                      XISBACK_DESKTOP set to the clicked layer's key, so\n"
            "                      e.g. `--on-left-click 'xisback --next'` advances\n"
            "                      whichever layer was clicked\n"
            "  --get-actions       print the currently configured click commands\n"
            "  --quit              stop the daemon\n"
            "  --version           print version and exit\n"
            "\n"
            "If an xisback instance is already running in this session, the command\n"
            "is sent to it over a socket instead of spawning a second process. See\n"
            "PROTOCOL.md for the wire format.\n",
            prog);
}

static int parse_argv(int argc, char **argv, Command *cmd)
{
    memset(cmd, 0, sizeof(*cmd));
    cmd->type = CMD_NONE;
    snprintf(cmd->output, sizeof(cmd->output), "*");
    snprintf(cmd->desktop_str, sizeof(cmd->desktop_str), "*");
    cmd->desktop = -1;
    snprintf(cmd->mode_str, sizeof(cmd->mode_str), "fill");
    cmd->mode = MODE_FILL;
    cmd->interval = 300;
    cmd->fade_ms = 1000;

    /* Lets a click-bound command like `xisback --next` (with no explicit
     * --output/--desktop) target whichever layer was actually clicked: the
     * daemon sets these env vars on the child before exec. An explicit
     * --output/--desktop flag below still overrides. */
    const char *env_output = getenv("XISBACK_OUTPUT");
    if (env_output && *env_output) {
        snprintf(cmd->output, sizeof(cmd->output), "%s", env_output);
    }
    const char *env_desktop = getenv("XISBACK_DESKTOP");
    if (env_desktop && *env_desktop) {
        snprintf(cmd->desktop_str, sizeof(cmd->desktop_str), "%s", env_desktop);
        cmd->desktop = (strcmp(env_desktop, "*") == 0) ? -1 : atoi(env_desktop);
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--output") && i + 1 < argc) {
            snprintf(cmd->output, sizeof(cmd->output), "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--desktop") && i + 1 < argc) {
            i++;
            snprintf(cmd->desktop_str, sizeof(cmd->desktop_str), "%s", argv[i]);
            cmd->desktop = (strcmp(argv[i], "*") == 0) ? -1 : atoi(argv[i]);
        } else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
            i++;
            snprintf(cmd->mode_str, sizeof(cmd->mode_str), "%s", argv[i]);
            cmd->mode = (strcmp(argv[i], "stretch") == 0) ? MODE_STRETCH : MODE_FILL;
        } else if (!strcmp(argv[i], "--interval") && i + 1 < argc) {
            cmd->interval = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--shuffle")) {
            cmd->shuffle = 1;
        } else if (!strcmp(argv[i], "--fade") && i + 1 < argc) {
            cmd->fade_ms = clamp_fade_ms((int)(atof(argv[++i]) * 1000.0 + 0.5));
        } else if (!strcmp(argv[i], "--version")) {
            printf("xisback %s\n", XISBACK_VERSION);
            exit(0);
        } else if (!strcmp(argv[i], "--clear")) {
            cmd->type = CMD_CLEAR;
        } else if (!strcmp(argv[i], "--clear-all")) {
            cmd->type = CMD_CLEARALL;
        } else if (!strcmp(argv[i], "--list")) {
            cmd->type = CMD_LIST;
        } else if (!strcmp(argv[i], "--next")) {
            cmd->type = CMD_NEXT;
        } else if (!strcmp(argv[i], "--on-left-click") && i + 1 < argc) {
            snprintf(cmd->action_left, sizeof(cmd->action_left), "%s", argv[++i]);
            sanitize_action_cmd(cmd->action_left);
            cmd->action_left_set = 1;
            cmd->type = CMD_SETACTIONS;
        } else if (!strcmp(argv[i], "--on-right-click") && i + 1 < argc) {
            snprintf(cmd->action_right, sizeof(cmd->action_right), "%s", argv[++i]);
            sanitize_action_cmd(cmd->action_right);
            cmd->action_right_set = 1;
            cmd->type = CMD_SETACTIONS;
        } else if (!strcmp(argv[i], "--on-middle-click") && i + 1 < argc) {
            snprintf(cmd->action_middle, sizeof(cmd->action_middle), "%s", argv[++i]);
            sanitize_action_cmd(cmd->action_middle);
            cmd->action_middle_set = 1;
            cmd->type = CMD_SETACTIONS;
        } else if (!strcmp(argv[i], "--on-double-click") && i + 1 < argc) {
            snprintf(cmd->action_double, sizeof(cmd->action_double), "%s", argv[++i]);
            sanitize_action_cmd(cmd->action_double);
            cmd->action_double_set = 1;
            cmd->type = CMD_SETACTIONS;
        } else if (!strcmp(argv[i], "--get-actions")) {
            cmd->type = CMD_GETACTIONS;
        } else if (!strcmp(argv[i], "--quit")) {
            cmd->type = CMD_QUIT;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            return -1;
        } else if (argv[i][0] != '-') {
            snprintf(cmd->source, sizeof(cmd->source), "%s", argv[i]);
            if (cmd->type == CMD_NONE) {
                cmd->type = CMD_SET;
            }
        } else {
            fprintf(stderr, "xisback: unknown option '%s'\n", argv[i]);
            return -1;
        }
    }
    return 0;
}

static void build_line(const Command *c, char *buf, size_t bufsz)
{
    switch (c->type) {
    case CMD_SET:
        snprintf(buf, bufsz, "SET\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n", c->output, c->desktop_str, c->mode_str, c->interval, c->shuffle, c->fade_ms, c->source);
        break;
    case CMD_CLEAR:
        snprintf(buf, bufsz, "CLEAR\t%s\t%s\n", c->output, c->desktop_str);
        break;
    case CMD_CLEARALL:
        snprintf(buf, bufsz, "CLEARALL\n");
        break;
    case CMD_LIST:
        snprintf(buf, bufsz, "LIST\n");
        break;
    case CMD_NEXT:
        snprintf(buf, bufsz, "NEXT\t%s\t%s\n", c->output, c->desktop_str);
        break;
    case CMD_SETACTIONS:
        snprintf(buf, bufsz, "SETACTIONS\t%s\t%s\t%s\t%s\n", c->action_left, c->action_right, c->action_middle, c->action_double);
        break;
    case CMD_GETACTIONS:
        snprintf(buf, bufsz, "ACTIONS\n");
        break;
    case CMD_PING:
        snprintf(buf, bufsz, "PING\n");
        break;
    case CMD_QUIT:
        snprintf(buf, bufsz, "QUIT\n");
        break;
    default:
        buf[0] = 0;
    }
}

/* ------------------------------------------------------------------ */
/* layer bookkeeping                                                   */
/* ------------------------------------------------------------------ */

static int parse_desktop(const char *s)
{
    return (strcmp(s, "*") == 0) ? -1 : atoi(s);
}

static int find_layer(const char *output, int desktop)
{
    for (int i = 0; i < MAX_LAYERS; i++) {
        if (g_layers[i].in_use && strcmp(g_layers[i].output, output) == 0 && g_layers[i].desktop == desktop) {
            return i;
        }
    }
    return -1;
}

static int find_layer_by_window(Window w)
{
    for (int i = 0; i < MAX_LAYERS; i++) {
        if (g_layers[i].in_use && (g_layers[i].win == w || (g_layers[i].fading && g_layers[i].fade_win == w))) {
            return i;
        }
    }
    return -1;
}

static int alloc_layer(void)
{
    for (int i = 0; i < MAX_LAYERS; i++) {
        if (!g_layers[i].in_use) {
            return i;
        }
    }
    return -1;
}

static void destroy_layer(Layer *l)
{
    if (l->fading) {
        if (l->fade_win != None) {
            XDestroyWindow(g_dpy, l->fade_win);
        }
        if (l->fade_pixmap != None) {
            XFreePixmap(g_dpy, l->fade_pixmap);
        }
    }
    if (l->win != None) {
        XDestroyWindow(g_dpy, l->win);
    }
    if (l->cur_pixmap != None) {
        XFreePixmap(g_dpy, l->cur_pixmap);
    }
    for (int i = 0; i < l->n_images; i++) {
        free(l->images[i]);
    }
    free(l->images);
    memset(l, 0, sizeof(*l));
}

/* ------------------------------------------------------------------ */
/* click actions                                                       */
/* ------------------------------------------------------------------ */

/* Runs `cmd` via `sh -c`, detached, without waiting for it: SIGCHLD is set
 * to SIG_IGN in run_as_daemon() so the child is auto-reaped and never
 * becomes a zombie. output/desktop identify the layer whose window was
 * clicked and are exposed to the command as XISBACK_OUTPUT/
 * XISBACK_DESKTOP, so e.g. `xisback --next` run as the command reacts to
 * whichever layer triggered it instead of needing a hardcoded target. */
static void run_action(const char *cmd, const char *output, int desktop)
{
    if (!cmd || !cmd[0]) {
        return;
    }
    pid_t pid = fork();
    if (pid < 0) {
        perror("xisback: fork");
        return;
    }
    if (pid == 0) {
        char dstr[16];
        if (desktop < 0) {
            snprintf(dstr, sizeof(dstr), "*");
        } else {
            snprintf(dstr, sizeof(dstr), "%d", desktop);
        }
        setenv("XISBACK_OUTPUT", output ? output : "*", 1);
        setenv("XISBACK_DESKTOP", dstr, 1);
        setsid();
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
}

/* ------------------------------------------------------------------ */
/* X11 / RandR / rendering                                             */
/* ------------------------------------------------------------------ */

static int resolve_output_geometry(const char *name, int *ox, int *oy, int *ow, int *oh)
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

/* Fills `names` with the currently connected, actively-driven (has a CRTC)
 * XRandR output names, in their natural enumeration order. Used to
 * reconcile config output names against reality at startup -- see
 * build_output_rename_map(). */
static int list_connected_outputs(char names[][64], int max)
{
    XRRScreenResources *res = XRRGetScreenResourcesCurrent(g_dpy, g_root);
    if (!res) {
        return 0;
    }
    int n = 0;
    for (int i = 0; i < res->noutput && n < max; i++) {
        XRROutputInfo *oi = XRRGetOutputInfo(g_dpy, res, res->outputs[i]);
        if (oi && oi->connection == RR_Connected && oi->crtc) {
            snprintf(names[n], 64, "%s", oi->name);
            n++;
        }
        if (oi) {
            XRRFreeOutputInfo(oi);
        }
    }
    XRRFreeScreenResources(res);
    return n;
}

static void layer_geometry(Layer *l, int *x, int *y, int *w, int *h)
{
    if (strcmp(l->output, "*") == 0 || !resolve_output_geometry(l->output, x, y, w, h)) {
        if (strcmp(l->output, "*") != 0) {
            fprintf(stderr, "xisback: output '%s' not found, falling back to full screen\n", l->output);
        }
        *x = 0;
        *y = 0;
        *w = DisplayWidth(g_dpy, g_screen);
        *h = DisplayHeight(g_dpy, g_screen);
    }
}

static Window create_layer_window(Layer *l, int x, int y, int w, int h)
{
    Window win = XCreateSimpleWindow(g_dpy, g_root, x, y, (unsigned)w, (unsigned)h, 0, 0, BlackPixel(g_dpy, g_screen));

    char title[128];
    snprintf(title, sizeof(title), "xisback:%s:%d", l->output, l->desktop);
    XStoreName(g_dpy, win, title);

    XClassHint ch;
    ch.res_name = (char *)"xisback";
    ch.res_class = (char *)"xisback";
    XSetClassHint(g_dpy, win, &ch);

    Atom wmWindowType = XInternAtom(g_dpy, "_NET_WM_WINDOW_TYPE", False);
    Atom wmWindowTypeDesktop = XInternAtom(g_dpy, "_NET_WM_WINDOW_TYPE_DESKTOP", False);
    XChangeProperty(g_dpy, win, wmWindowType, XA_ATOM, 32, PropModeReplace, (unsigned char *)&wmWindowTypeDesktop, 1);

    Atom wmDesktop = XInternAtom(g_dpy, "_NET_WM_DESKTOP", False);
    long desktopVal = (l->desktop < 0) ? 0xFFFFFFFFL : (long)l->desktop;
    XChangeProperty(g_dpy, win, wmDesktop, XA_CARDINAL, 32, PropModeReplace, (unsigned char *)&desktopVal, 1);

    /* ICCCM: tells the WM this window never wants keyboard focus, so a
     * click on the wallpaper (needed for ButtonPress, below) doesn't
     * steal focus from whatever the user was actually using. */
    XWMHints hints;
    hints.flags = InputHint;
    hints.input = False;
    XSetWMHints(g_dpy, win, &hints);

    XSelectInput(g_dpy, win, ButtonPressMask);

    return win;
}

/* _NET_WM_WINDOW_OPACITY (the xcompmgr/compton/picom/KWin convention): a
 * CARDINAL fraction of 0xFFFFFFFF, so the compositor cross-fades the window
 * on the GPU -- we never touch pixel data ourselves for the animation. */
static void set_window_opacity(Window win, double opacity)
{
    if (opacity < 0.0) {
        opacity = 0.0;
    }
    if (opacity > 1.0) {
        opacity = 1.0;
    }
    uint32_t val = (uint32_t)(opacity * (double)UINT32_MAX);
    XChangeProperty(g_dpy, win, g_atom_opacity, XA_CARDINAL, 32, PropModeReplace, (unsigned char *)&val, 1);
}

static void layer_ensure_window(Layer *l)
{
    int x, y, w, h;
    layer_geometry(l, &x, &y, &w, &h);

    if (l->win == None) {
        l->win = create_layer_window(l, x, y, w, h);
        XMapWindow(g_dpy, l->win);
        XLowerWindow(g_dpy, l->win);
        l->x = x;
        l->y = y;
        l->width = w;
        l->height = h;
    } else if (x != l->x || y != l->y || w != l->width || h != l->height) {
        XMoveResizeWindow(g_dpy, l->win, x, y, (unsigned)w, (unsigned)h);
        l->x = x;
        l->y = y;
        l->width = w;
        l->height = h;
    }
}

static int is_probably_image(const char *name)
{
    const char *dot = strrchr(name, '.');
    if (!dot) {
        return 0;
    }
    static const char *exts[] = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff", ".pnm", ".tga", NULL};
    for (int i = 0; exts[i]; i++) {
        if (strcasecmp(dot, exts[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void shuffle_images(char **arr, int n)
{
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        char *tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

static void layer_load_sources(Layer *l)
{
    for (int i = 0; i < l->n_images; i++) {
        free(l->images[i]);
    }
    free(l->images);
    l->images = NULL;
    l->n_images = 0;
    l->img_idx = 0;

    struct stat st;
    if (stat(l->source, &st) != 0) {
        fprintf(stderr, "xisback: could not find '%s'\n", l->source);
        return;
    }

    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(l->source);
        if (!d) {
            return;
        }
        struct dirent *de;
        char **list = NULL;
        int n = 0, cap = 0;
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.' || !is_probably_image(de->d_name)) {
                continue;
            }
            if (n == cap) {
                cap = cap ? cap * 2 : 16;
                list = realloc(list, sizeof(char *) * (size_t)cap);
            }
            char full[PATH_MAX];
            snprintf(full, sizeof(full), "%s/%s", l->source, de->d_name);
            list[n++] = strdup(full);
        }
        closedir(d);
        if (n > 0) {
            if (l->shuffle) {
                shuffle_images(list, n);
            } else {
                qsort(list, (size_t)n, sizeof(char *), cmp_str);
            }
        }
        l->images = list;
        l->n_images = n;
    } else {
        l->images = malloc(sizeof(char *));
        l->images[0] = strdup(l->source);
        l->n_images = 1;
    }
}

static Pixmap render_pixmap(int w, int h, const char *path, enum mode mode)
{
    Imlib_Image image = imlib_load_image(path);
    if (!image) {
        fprintf(stderr, "xisback: failed to load '%s'\n", path);
        return None;
    }
    imlib_context_set_image(image);
    int iw = imlib_image_get_width();
    int ih = imlib_image_get_height();

    Pixmap pmap = XCreatePixmap(g_dpy, g_root, (unsigned)w, (unsigned)h, (unsigned)g_depth);
    imlib_context_set_drawable(pmap);
    XFillRectangle(g_dpy, pmap, g_gc, 0, 0, (unsigned)w, (unsigned)h);

    if (mode == MODE_STRETCH) {
        imlib_render_image_on_drawable_at_size(0, 0, w, h);
    } else {
        double scale = fmax((double)w / iw, (double)h / ih);
        int dw = (int)(iw * scale + 0.5);
        int dh = (int)(ih * scale + 0.5);
        int dx = (w - dw) / 2;
        int dy = (h - dh) / 2;
        imlib_render_image_on_drawable_at_size(dx, dy, dw, dh);
    }
    imlib_free_image();
    return pmap;
}

/* Drops an in-flight crossfade by promoting fade_win/fade_pixmap into
 * win/cur_pixmap and destroying whatever they replace -- used both when a
 * fade completes naturally and when it needs to be cut short (a new switch
 * arrives, or the layer is being resized/destroyed). */
static void layer_finish_fade(Layer *l)
{
    if (!l->fading) {
        return;
    }
    if (l->win != None) {
        XDestroyWindow(g_dpy, l->win);
    }
    if (l->cur_pixmap != None) {
        XFreePixmap(g_dpy, l->cur_pixmap);
    }
    l->win = l->fade_win;
    l->cur_pixmap = l->fade_pixmap;
    l->fade_win = None;
    l->fade_pixmap = None;
    l->fading = 0;
}

/* Renders the current slide into the layer's window. With use_fade and a
 * configured fade_ms, the new image is drawn into a second window stacked
 * above the current one and cross-faded in via _NET_WM_WINDOW_OPACITY
 * (animated from layer_fade_tick()) instead of swapping instantly -- the
 * compositor does the actual blending, so this costs us nothing beyond one
 * extra window and a property change per frame. use_fade is turned off for
 * geometry-driven re-renders (e.g. an output resize), where an animated
 * transition doesn't make sense. */
static void layer_render(Layer *l, int use_fade)
{
    if (l->n_images == 0) {
        return;
    }
    Pixmap next = render_pixmap(l->width, l->height, l->images[l->img_idx], l->mode);
    if (next == None) {
        return;
    }

    if (l->fading) {
        layer_finish_fade(l);
    }

    if (!use_fade || l->fade_ms <= 0) {
        XSetWindowBackgroundPixmap(g_dpy, l->win, next);
        XClearWindow(g_dpy, l->win);
        if (l->cur_pixmap != None) {
            XFreePixmap(g_dpy, l->cur_pixmap);
        }
        l->cur_pixmap = next;
        return;
    }

    l->fade_win = create_layer_window(l, l->x, l->y, l->width, l->height);
    XSetWindowBackgroundPixmap(g_dpy, l->fade_win, next);
    XClearWindow(g_dpy, l->fade_win);
    set_window_opacity(l->fade_win, 0.0);
    XMapWindow(g_dpy, l->fade_win);
    XRaiseWindow(g_dpy, l->fade_win);
    l->fade_pixmap = next;
    l->fading = 1;
    clock_gettime(CLOCK_MONOTONIC, &l->fade_start);
}

static void layer_render_current(Layer *l)
{
    layer_render(l, 1);
}

/* Advances any in-flight crossfade by one animation step. Returns non-zero
 * while still fading (caller keeps ticking at FADE_TICK_USEC), 0 once the
 * transition has completed or there was nothing to do. */
static int layer_fade_tick(Layer *l, const struct timespec *now)
{
    if (!l->fading) {
        return 0;
    }
    double elapsed_ms = (double)(now->tv_sec - l->fade_start.tv_sec) * 1000.0 + (double)(now->tv_nsec - l->fade_start.tv_nsec) / 1e6;
    double progress = elapsed_ms / (double)l->fade_ms;
    if (progress >= 1.0) {
        layer_finish_fade(l);
        return 0;
    }
    set_window_opacity(l->fade_win, progress);
    return 1;
}

static void layer_advance(Layer *l, time_t now)
{
    layer_render_current(l);
    if (l->n_images > 1 && l->interval > 0) {
        l->img_idx = (l->img_idx + 1) % l->n_images;
        if (l->img_idx == 0 && l->shuffle) {
            shuffle_images(l->images, l->n_images);
        }
        l->next_switch = now + l->interval;
    } else {
        l->next_switch = 0;
    }
    /* Decoding a big source image leaves freed heap behind that glibc
     * won't hand back to the OS on its own; force it so RSS actually
     * drops after a slideshow switch instead of just sitting there. */
    malloc_trim(0);
}

/* ------------------------------------------------------------------ */
/* config persistence ($XDG_CONFIG_HOME/xisback.conf)                  */
/* ------------------------------------------------------------------ */

/* Applies a SET (creating or replacing the (output,desktop) layer) directly
 * against the layer table. Shared by the protocol's SET handler and by
 * load_config() at startup, so restoring last session's layers goes through
 * the exact same path a live client would use. On failure returns -1 and
 * writes a human-readable reason into errbuf. */
static int layer_apply_set(const char *output, int desktop, enum mode mode, int interval, int shuffle, int fade_ms, const char *path, char *errbuf, size_t errbufsz)
{
    int idx = find_layer(output, desktop);
    if (idx < 0) {
        idx = alloc_layer();
    }
    if (idx < 0) {
        snprintf(errbuf, errbufsz, "limit of %d layers reached", MAX_LAYERS);
        return -1;
    }

    Layer *l = &g_layers[idx];
    snprintf(l->output, sizeof(l->output), "%s", output);
    l->desktop = desktop;
    l->mode = mode;
    l->interval = interval;
    l->shuffle = shuffle;
    l->fade_ms = clamp_fade_ms(fade_ms);
    snprintf(l->source, sizeof(l->source), "%s", path);
    l->in_use = 1;

    layer_ensure_window(l);
    layer_load_sources(l);
    if (l->n_images == 0) {
        snprintf(errbuf, errbufsz, "no valid image found in '%s'", path);
        destroy_layer(l);
        return -1;
    }
    layer_advance(l, time(NULL));
    return 0;
}

static void save_config(void)
{
    if (!g_configpath[0]) {
        return;
    }
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_configpath);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        fprintf(stderr, "xisback: could not write '%s': %s\n", tmp, strerror(errno));
        return;
    }
    for (int i = 0; i < MAX_LAYERS; i++) {
        if (!g_layers[i].in_use) {
            continue;
        }
        Layer *l = &g_layers[i];
        char dstr[16];
        if (l->desktop < 0) {
            snprintf(dstr, sizeof(dstr), "*");
        } else {
            snprintf(dstr, sizeof(dstr), "%d", l->desktop);
        }
        fprintf(f, "LAYER\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n", l->output, dstr, l->mode == MODE_STRETCH ? "stretch" : "fill", l->interval, l->shuffle, l->fade_ms, l->source);
    }
    fprintf(f, "ACTIONS\t%s\t%s\t%s\t%s\n", g_action_left, g_action_right, g_action_middle, g_action_double);
    fclose(f);
    if (rename(tmp, g_configpath) != 0) {
        fprintf(stderr, "xisback: could not save '%s': %s\n", g_configpath, strerror(errno));
    }
}

typedef struct {
    char from[64];
    char to[64];
} OutputRename;

/* Reconciles the config's output names against what's actually connected
 * right now. Outputs get renamed by drivers/re-plugging often enough that a
 * saved "HDMI-1" layer can silently stop matching anything on the next
 * boot -- layer_geometry() then falls back to full-screen for it, and with
 * one full-screen layer per originally-per-output wallpaper stacked on top
 * of each other, it looks like a single wallpaper covering everything.
 *
 * Names that already match exactly are left alone. The remaining
 * (config name, real name) pairs are only auto-matched positionally when
 * their counts agree -- i.e. the monitor count didn't change, just the
 * names -- since that's the one case where "just renumber them in order"
 * is a safe guess rather than a coin flip. Returns the number of pairs
 * written to `map` (possibly 0, meaning no remapping is needed or possible). */
static int build_output_rename_map(const char *path, OutputRename *map, int max_map)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        return 0;
    }

    char cfg_outputs[MAX_LAYERS][64];
    int n_cfg = 0;
    char line[LINE_MAX_LEN];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = 0;
        }
        if (len == 0) {
            continue;
        }
        char *fields[8];
        int nf = 0;
        char *p = line;
        fields[nf++] = p;
        while (nf < 8 && (p = strchr(p, '\t'))) {
            *p = 0;
            p++;
            fields[nf++] = p;
        }
        /* Same output field position in both the current "LAYER\t..." format
         * and the pre-0.4 unprefixed one. */
        const char *output = (strcmp(fields[0], "LAYER") == 0 && nf >= 2) ? fields[1]
                            : (nf == 7) ? fields[0]
                            : NULL;
        if (!output || strcmp(output, "*") == 0) {
            continue;
        }
        int dup = 0;
        for (int i = 0; i < n_cfg; i++) {
            if (strcmp(cfg_outputs[i], output) == 0) {
                dup = 1;
                break;
            }
        }
        if (!dup && n_cfg < MAX_LAYERS) {
            snprintf(cfg_outputs[n_cfg], sizeof(cfg_outputs[n_cfg]), "%s", output);
            n_cfg++;
        }
    }
    fclose(f);

    char real_outputs[MAX_LAYERS][64];
    int n_real = list_connected_outputs(real_outputs, MAX_LAYERS);

    if (n_cfg == 0 || n_cfg != n_real) {
        return 0;
    }

    char unmatched_cfg[MAX_LAYERS][64];
    char unmatched_real[MAX_LAYERS][64];
    int n_unmatched_cfg = 0, n_unmatched_real = 0;

    for (int i = 0; i < n_cfg; i++) {
        int found = 0;
        for (int j = 0; j < n_real; j++) {
            if (strcmp(cfg_outputs[i], real_outputs[j]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            snprintf(unmatched_cfg[n_unmatched_cfg], sizeof(unmatched_cfg[0]), "%s", cfg_outputs[i]);
            n_unmatched_cfg++;
        }
    }
    for (int j = 0; j < n_real; j++) {
        int found = 0;
        for (int i = 0; i < n_cfg; i++) {
            if (strcmp(real_outputs[j], cfg_outputs[i]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            snprintf(unmatched_real[n_unmatched_real], sizeof(unmatched_real[0]), "%s", real_outputs[j]);
            n_unmatched_real++;
        }
    }

    /* n_unmatched_cfg == n_unmatched_real is guaranteed here: n_cfg == n_real
     * and both lists remove the same exactly-matched names from equal-size
     * pools. */
    int n_map = 0;
    for (int i = 0; i < n_unmatched_cfg && n_map < max_map; i++) {
        snprintf(map[n_map].from, sizeof(map[n_map].from), "%s", unmatched_cfg[i]);
        snprintf(map[n_map].to, sizeof(map[n_map].to), "%s", unmatched_real[i]);
        n_map++;
    }
    return n_map;
}

static const char *apply_output_rename(const OutputRename *map, int n_map, const char *name)
{
    for (int i = 0; i < n_map; i++) {
        if (strcmp(map[i].from, name) == 0) {
            return map[i].to;
        }
    }
    return name;
}

static void load_config(void)
{
    OutputRename rename_map[MAX_LAYERS];
    int n_rename = build_output_rename_map(g_configpath, rename_map, MAX_LAYERS);
    for (int i = 0; i < n_rename; i++) {
        fprintf(stderr, "xisback: config: output '%s' not found but screen count still matches, using '%s' instead (by screen order)\n", rename_map[i].from, rename_map[i].to);
    }

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
        if (len == 0) {
            continue;
        }

        char *fields[8];
        int nf = 0;
        char *p = line;
        fields[nf++] = p;
        while (nf < 8 && (p = strchr(p, '\t'))) {
            *p = 0;
            p++;
            fields[nf++] = p;
        }

        if (strcmp(fields[0], "LAYER") == 0) {
            if (nf < 8) {
                fprintf(stderr, "xisback: config: skipping malformed line: '%s'\n", line);
                continue;
            }
            enum mode mode = (strcmp(fields[3], "stretch") == 0) ? MODE_STRETCH : MODE_FILL;
            const char *output = apply_output_rename(rename_map, n_rename, fields[1]);
            char errbuf[256];
            if (layer_apply_set(output, parse_desktop(fields[2]), mode, atoi(fields[4]), atoi(fields[5]), atoi(fields[6]), fields[7], errbuf, sizeof(errbuf)) != 0) {
                fprintf(stderr, "xisback: config: %s\n", errbuf);
            }
        } else if (strcmp(fields[0], "ACTIONS") == 0) {
            if (nf < 5) {
                fprintf(stderr, "xisback: config: skipping malformed line: '%s'\n", line);
                continue;
            }
            snprintf(g_action_left, sizeof(g_action_left), "%s", fields[1]);
            snprintf(g_action_right, sizeof(g_action_right), "%s", fields[2]);
            snprintf(g_action_middle, sizeof(g_action_middle), "%s", fields[3]);
            snprintf(g_action_double, sizeof(g_action_double), "%s", fields[4]);
        } else if (nf == 7) {
            /* Pre-0.4 config lines had no leading LAYER tag -- keep reading
             * them so upgrading the binary doesn't silently drop whatever
             * wallpaper was already configured. */
            enum mode mode = (strcmp(fields[2], "stretch") == 0) ? MODE_STRETCH : MODE_FILL;
            const char *output = apply_output_rename(rename_map, n_rename, fields[0]);
            char errbuf[256];
            if (layer_apply_set(output, parse_desktop(fields[1]), mode, atoi(fields[3]), atoi(fields[4]), atoi(fields[5]), fields[6], errbuf, sizeof(errbuf)) != 0) {
                fprintf(stderr, "xisback: config: %s\n", errbuf);
            }
        } else {
            fprintf(stderr, "xisback: config: skipping unknown line: '%s'\n", line);
        }
    }
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* protocol handling (server side)                                     */
/* ------------------------------------------------------------------ */

static void handle_line(char *line, FILE *out)
{
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = 0;
    }

    char *fields[9];
    int nf = 0;
    char *p = line;
    fields[nf++] = p;
    while (nf < 9 && (p = strchr(p, '\t'))) {
        *p = 0;
        p++;
        fields[nf++] = p;
    }

    if (strcmp(fields[0], "PING") == 0) {
        fprintf(out, "PONG\n");
        return;
    }
    if (strcmp(fields[0], "QUIT") == 0) {
        fprintf(out, "OK\n");
        g_quit = 1;
        return;
    }
    if (strcmp(fields[0], "LIST") == 0) {
        for (int i = 0; i < MAX_LAYERS; i++) {
            if (!g_layers[i].in_use) {
                continue;
            }
            Layer *l = &g_layers[i];
            char dstr[16];
            if (l->desktop < 0) {
                snprintf(dstr, sizeof(dstr), "*");
            } else {
                snprintf(dstr, sizeof(dstr), "%d", l->desktop);
            }
            fprintf(out, "%s\t%s\t%s\t%d\t%d\t%d\t%s\n", l->output, dstr, l->mode == MODE_STRETCH ? "stretch" : "fill", l->interval, l->shuffle, l->fade_ms, l->source);
        }
        return;
    }
    if (strcmp(fields[0], "CLEARALL") == 0) {
        for (int i = 0; i < MAX_LAYERS; i++) {
            if (g_layers[i].in_use) {
                destroy_layer(&g_layers[i]);
            }
        }
        save_config();
        fprintf(out, "OK\n");
        return;
    }
    if (strcmp(fields[0], "CLEAR") == 0) {
        if (nf < 3) {
            fprintf(out, "ERR usage: CLEAR output desktop\n");
            return;
        }
        int idx = find_layer(fields[1], parse_desktop(fields[2]));
        if (idx < 0) {
            fprintf(out, "ERR layer not found\n");
            return;
        }
        destroy_layer(&g_layers[idx]);
        save_config();
        fprintf(out, "OK\n");
        return;
    }
    if (strcmp(fields[0], "NEXT") == 0) {
        if (nf < 3) {
            fprintf(out, "ERR usage: NEXT output desktop\n");
            return;
        }
        int idx = find_layer(fields[1], parse_desktop(fields[2]));
        if (idx < 0) {
            fprintf(out, "ERR layer not found\n");
            return;
        }
        /* No-op (but still OK) for a single image or interval=0: there's
         * nothing to advance to, same as the automatic slideshow timer
         * would find. */
        layer_advance(&g_layers[idx], time(NULL));
        XFlush(g_dpy);
        fprintf(out, "OK\n");
        return;
    }
    if (strcmp(fields[0], "ACTIONS") == 0) {
        fprintf(out, "%s\t%s\t%s\t%s\n", g_action_left, g_action_right, g_action_middle, g_action_double);
        return;
    }
    if (strcmp(fields[0], "SETACTIONS") == 0) {
        if (nf < 5) {
            fprintf(out, "ERR usage: SETACTIONS left right middle double\n");
            return;
        }
        snprintf(g_action_left, sizeof(g_action_left), "%s", fields[1]);
        snprintf(g_action_right, sizeof(g_action_right), "%s", fields[2]);
        snprintf(g_action_middle, sizeof(g_action_middle), "%s", fields[3]);
        snprintf(g_action_double, sizeof(g_action_double), "%s", fields[4]);
        sanitize_action_cmd(g_action_left);
        sanitize_action_cmd(g_action_right);
        sanitize_action_cmd(g_action_middle);
        sanitize_action_cmd(g_action_double);
        save_config();
        fprintf(out, "OK\n");
        return;
    }
    if (strcmp(fields[0], "SET") == 0) {
        if (nf < 8) {
            fprintf(out, "ERR usage: SET output desktop mode interval shuffle fade_ms path\n");
            return;
        }
        const char *output = fields[1];
        int desktop = parse_desktop(fields[2]);
        enum mode mode = (strcmp(fields[3], "stretch") == 0) ? MODE_STRETCH : MODE_FILL;
        int interval = atoi(fields[4]);
        int shuffle = atoi(fields[5]);
        int fade_ms = atoi(fields[6]);
        const char *path = fields[7];

        char errbuf[256];
        if (layer_apply_set(output, desktop, mode, interval, shuffle, fade_ms, path, errbuf, sizeof(errbuf)) != 0) {
            fprintf(out, "ERR %s\n", errbuf);
            return;
        }
        XFlush(g_dpy);
        save_config();
        fprintf(out, "OK\n");
        return;
    }

    fprintf(out, "ERR unknown command: %s\n", fields[0]);
}

/* ------------------------------------------------------------------ */
/* client / daemon entry points                                        */
/* ------------------------------------------------------------------ */

static void handle_signal(int sig)
{
    (void)sig;
    g_quit = 1;
}

/* Fetches the daemon's current click-action bindings over a short-lived
 * connection. Used by run_as_client() to merge a partial `--on-*-click`
 * invocation on top of whatever is already configured, instead of the
 * single flag the caller passed wiping out the other three. Returns -1 (and
 * leaves the outputs untouched) on any failure -- callers treat that as
 * "assume unset/empty", same as a fresh daemon with no bindings yet. */
static int fetch_actions(const char *sockpath, char *left, size_t leftsz, char *right, size_t rightsz, char *middle, size_t middlesz, char *dbl, size_t dblsz)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    static const char query[] = "ACTIONS\n";
    if (write(fd, query, strlen(query)) < 0) {
        close(fd);
        return -1;
    }
    shutdown(fd, SHUT_WR);

    char buf[4 * ACTION_CMD_LEN];
    size_t total = 0;
    ssize_t n;
    while (total < sizeof(buf) - 1 && (n = read(fd, buf + total, sizeof(buf) - 1 - total)) > 0) {
        total += (size_t)n;
    }
    buf[total] = 0;
    close(fd);

    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = 0;
    }

    char *fields[4];
    int nf = 0;
    char *p = buf;
    fields[nf++] = p;
    while (nf < 4 && (p = strchr(p, '\t'))) {
        *p = 0;
        p++;
        fields[nf++] = p;
    }
    if (nf < 4) {
        return -1;
    }
    snprintf(left, leftsz, "%s", fields[0]);
    snprintf(right, rightsz, "%s", fields[1]);
    snprintf(middle, middlesz, "%s", fields[2]);
    snprintf(dbl, dblsz, "%s", fields[3]);
    return 0;
}

static int run_as_client(const char *sockpath, const Command *cmd_in)
{
    if (cmd_in->type == CMD_NONE) {
        fprintf(stderr, "xisback: daemon is already running; no command given.\n");
        return 0;
    }

    Command cmd_buf = *cmd_in;
    Command *cmd = &cmd_buf;

    if (cmd->type == CMD_SETACTIONS &&
        !(cmd->action_left_set && cmd->action_right_set && cmd->action_middle_set && cmd->action_double_set)) {
        char cur_left[ACTION_CMD_LEN] = "", cur_right[ACTION_CMD_LEN] = "";
        char cur_middle[ACTION_CMD_LEN] = "", cur_double[ACTION_CMD_LEN] = "";
        if (fetch_actions(sockpath, cur_left, sizeof(cur_left), cur_right, sizeof(cur_right), cur_middle, sizeof(cur_middle), cur_double, sizeof(cur_double)) == 0) {
            if (!cmd->action_left_set) {
                snprintf(cmd->action_left, sizeof(cmd->action_left), "%s", cur_left);
            }
            if (!cmd->action_right_set) {
                snprintf(cmd->action_right, sizeof(cmd->action_right), "%s", cur_right);
            }
            if (!cmd->action_middle_set) {
                snprintf(cmd->action_middle, sizeof(cmd->action_middle), "%s", cur_middle);
            }
            if (!cmd->action_double_set) {
                snprintf(cmd->action_double, sizeof(cmd->action_double), "%s", cur_double);
            }
        }
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("xisback: socket");
        return 1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);

    int connected = -1;
    for (int i = 0; i < 50; i++) {
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            connected = 0;
            break;
        }
        usleep(100000);
    }
    if (connected != 0) {
        fprintf(stderr, "xisback: could not connect to daemon (%s)\n", sockpath);
        close(fd);
        return 1;
    }

    char line[LINE_MAX_LEN];
    build_line(cmd, line, sizeof(line));
    if (write(fd, line, strlen(line)) < 0) {
        perror("xisback: write");
    }
    shutdown(fd, SHUT_WR);

    char buf[4096];
    ssize_t n;
    int ok = 1;
    int first = 1;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = 0;
        fputs(buf, stdout);
        if (first && strncmp(buf, "ERR", 3) == 0) {
            ok = 0;
        }
        first = 0;
    }
    close(fd);
    return ok ? 0 : 1;
}

static int run_as_daemon(const char *sockpath, const char *configpath, const Command *initial_cmd)
{
    srand((unsigned)(time(NULL) ^ getpid()));

    g_dpy = XOpenDisplay(NULL);
    if (!g_dpy) {
        fprintf(stderr, "xisback: could not open the X display\n");
        return 1;
    }
    g_screen = DefaultScreen(g_dpy);
    g_root = RootWindow(g_dpy, g_screen);
    g_visual = DefaultVisual(g_dpy, g_screen);
    g_depth = DefaultDepth(g_dpy, g_screen);
    g_cmap = DefaultColormap(g_dpy, g_screen);
    g_gc = XCreateGC(g_dpy, g_root, 0, NULL);
    XSetForeground(g_dpy, g_gc, BlackPixel(g_dpy, g_screen));

    imlib_context_set_display(g_dpy);
    imlib_context_set_visual(g_visual);
    imlib_context_set_colormap(g_cmap);
    imlib_context_set_anti_alias(1);
    imlib_context_set_dither(1);
    /* This is a wallpaper daemon: images are (re)rendered rarely (slideshow
     * interval or output change), so Imlib2's decode cache just holds onto
     * memory between switches for no benefit here. Keep footprint minimal. */
    imlib_set_cache_size(0);

    g_atom_opacity = XInternAtom(g_dpy, "_NET_WM_WINDOW_OPACITY", False);

    int rr_error_base;
    if (!XRRQueryExtension(g_dpy, &g_rr_event_base, &rr_error_base)) {
        fprintf(stderr, "xisback: RandR extension unavailable, named outputs won't work\n");
        g_rr_event_base = -1;
    } else {
        XRRSelectInput(g_dpy, g_root, RRScreenChangeNotifyMask);
    }

    unlink(sockpath);
    int listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);
    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(listenfd, 16) != 0) {
        perror("xisback: bind/listen");
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);
    /* Click actions are fire-and-forget children (run_action() never
     * waitpid()s them); ignoring SIGCHLD makes the kernel reap them itself
     * instead of leaving zombies behind. */
    signal(SIGCHLD, SIG_IGN);

    /* Keep the listening socket and X connection out of any command a
     * click action execs -- they'd otherwise inherit them across fork(). */
    fcntl(listenfd, F_SETFD, FD_CLOEXEC);
    fcntl(ConnectionNumber(g_dpy), F_SETFD, FD_CLOEXEC);

    snprintf(g_configpath, sizeof(g_configpath), "%s", configpath);
    load_config();
    XFlush(g_dpy);

    if (initial_cmd->type != CMD_NONE) {
        char line[LINE_MAX_LEN];
        build_line(initial_cmd, line, sizeof(line));
        handle_line(line, stdout);
    }

    int xfd = ConnectionNumber(g_dpy);
    while (!g_quit) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listenfd, &rfds);
        FD_SET(xfd, &rfds);
        int maxfd = listenfd > xfd ? listenfd : xfd;

        time_t now = time(NULL);
        time_t soonest = 0;
        int any_fading = 0;
        for (int i = 0; i < MAX_LAYERS; i++) {
            if (g_layers[i].in_use) {
                if (g_layers[i].next_switch > 0 && (soonest == 0 || g_layers[i].next_switch < soonest)) {
                    soonest = g_layers[i].next_switch;
                }
                if (g_layers[i].fading) {
                    any_fading = 1;
                }
            }
        }
        /* -1 = block indefinitely; otherwise the soonest of: a fade
         * animation tick, a pending click's double-click window expiring,
         * or the next slideshow switch. */
        long timeout_ms = -1;
        if (any_fading) {
            timeout_ms = FADE_TICK_USEC / 1000;
        }
        if (g_click_pending_button) {
            struct timespec mono_now;
            clock_gettime(CLOCK_MONOTONIC, &mono_now);
            double elapsed_ms = (double)(mono_now.tv_sec - g_click_pending_time.tv_sec) * 1000.0 +
                                 (double)(mono_now.tv_nsec - g_click_pending_time.tv_nsec) / 1e6;
            long remaining = (long)(DOUBLE_CLICK_MS - elapsed_ms);
            if (remaining < 0) {
                remaining = 0;
            }
            if (timeout_ms < 0 || remaining < timeout_ms) {
                timeout_ms = remaining;
            }
        }
        if (soonest > 0) {
            long delta = (long)(soonest - now) * 1000;
            if (delta < 0) {
                delta = 0;
            }
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

                char linebuf[LINE_MAX_LEN];
                ssize_t n = read(cfd, linebuf, sizeof(linebuf) - 1);
                if (n > 0) {
                    linebuf[n] = 0;
                    FILE *wf = fdopen(dup(cfd), "w");
                    if (wf) {
                        handle_line(linebuf, wf);
                        fclose(wf);
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
                    for (int i = 0; i < MAX_LAYERS; i++) {
                        if (g_layers[i].in_use) {
                            /* Snap any in-flight crossfade to its final state
                             * first: an animated transition doesn't make
                             * sense for a geometry change forced by a
                             * monitor reconfiguration. */
                            layer_finish_fade(&g_layers[i]);
                            layer_ensure_window(&g_layers[i]);
                            layer_render(&g_layers[i], 0);
                        }
                    }
                    malloc_trim(0);
                    XFlush(g_dpy);
                } else if (ev.type == ButtonPress) {
                    /* Button2 is the middle button in X11's numbering (not
                     * Button3 -- that's right). Wheel scroll shows up as
                     * Button4/5; we don't bind anything to those. */
                    int idx = find_layer_by_window(ev.xbutton.window);
                    if (idx >= 0 && (ev.xbutton.button == Button1 || ev.xbutton.button == Button2 || ev.xbutton.button == Button3)) {
                        Layer *l = &g_layers[idx];
                        int button = (int)ev.xbutton.button;

                        if (!g_action_double[0]) {
                            /* Nobody bound a double-click action, so there's
                             * nothing to disambiguate against: fire the
                             * single-click action immediately, no delay. */
                            const char *single = (button == Button1) ? g_action_left : (button == Button2) ? g_action_middle : g_action_right;
                            run_action(single, l->output, l->desktop);
                        } else if (g_click_pending_button == button) {
                            struct timespec mono_now;
                            clock_gettime(CLOCK_MONOTONIC, &mono_now);
                            double elapsed_ms = (double)(mono_now.tv_sec - g_click_pending_time.tv_sec) * 1000.0 +
                                                 (double)(mono_now.tv_nsec - g_click_pending_time.tv_nsec) / 1e6;
                            g_click_pending_button = 0;
                            if (elapsed_ms <= DOUBLE_CLICK_MS) {
                                run_action(g_action_double, l->output, l->desktop);
                            } else {
                                /* Second click arrived too late to count as
                                 * a double: treat the first one as a single
                                 * (already timed out) and this one starts a
                                 * fresh pending click. */
                                const char *single = (button == Button1) ? g_action_left : (button == Button2) ? g_action_middle : g_action_right;
                                run_action(single, l->output, l->desktop);
                            }
                        } else {
                            /* A different button was already pending (rare:
                             * only happens if both clicks landed in the same
                             * XPending() batch) -- flush it as a single click
                             * before starting to track this one. */
                            if (g_click_pending_button) {
                                const char *pending_single = (g_click_pending_button == Button1) ? g_action_left
                                                            : (g_click_pending_button == Button2) ? g_action_middle
                                                            : g_action_right;
                                run_action(pending_single, g_click_pending_output, g_click_pending_desktop);
                            }
                            g_click_pending_button = button;
                            clock_gettime(CLOCK_MONOTONIC, &g_click_pending_time);
                            snprintf(g_click_pending_output, sizeof(g_click_pending_output), "%s", l->output);
                            g_click_pending_desktop = l->desktop;
                        }
                    }
                }
            }
        }

        if (g_click_pending_button) {
            struct timespec mono_now;
            clock_gettime(CLOCK_MONOTONIC, &mono_now);
            double elapsed_ms = (double)(mono_now.tv_sec - g_click_pending_time.tv_sec) * 1000.0 +
                                 (double)(mono_now.tv_nsec - g_click_pending_time.tv_nsec) / 1e6;
            if (elapsed_ms >= DOUBLE_CLICK_MS) {
                const char *single = (g_click_pending_button == Button1) ? g_action_left
                                    : (g_click_pending_button == Button2) ? g_action_middle
                                    : g_action_right;
                run_action(single, g_click_pending_output, g_click_pending_desktop);
                g_click_pending_button = 0;
            }
        }

        int still_fading = 0;
        for (int i = 0; i < MAX_LAYERS; i++) {
            if (g_layers[i].in_use && g_layers[i].fading) {
                still_fading = 1;
                break;
            }
        }
        if (still_fading) {
            struct timespec tick_now;
            clock_gettime(CLOCK_MONOTONIC, &tick_now);
            for (int i = 0; i < MAX_LAYERS; i++) {
                if (g_layers[i].in_use) {
                    layer_fade_tick(&g_layers[i], &tick_now);
                }
            }
            XFlush(g_dpy);
        }

        now = time(NULL);
        for (int i = 0; i < MAX_LAYERS; i++) {
            if (g_layers[i].in_use && g_layers[i].next_switch > 0 && now >= g_layers[i].next_switch) {
                layer_advance(&g_layers[i], now);
                XFlush(g_dpy);
            }
        }
    }

    for (int i = 0; i < MAX_LAYERS; i++) {
        if (g_layers[i].in_use) {
            destroy_layer(&g_layers[i]);
        }
    }
    close(listenfd);
    unlink(sockpath);
    XFreeGC(g_dpy, g_gc);
    XCloseDisplay(g_dpy);
    return 0;
}

int main(int argc, char **argv)
{
    Command cmd;
    if (parse_argv(argc, argv, &cmd) != 0) {
        usage(argv[0]);
        return 1;
    }

    const char *rundir = getenv("XDG_RUNTIME_DIR");
    if (!rundir || !*rundir) {
        rundir = "/tmp";
    }
    char sockpath[PATH_MAX];
    char lockpath[PATH_MAX];
    snprintf(sockpath, sizeof(sockpath), "%s/xisback.sock", rundir);
    snprintf(lockpath, sizeof(lockpath), "%s/xisback.lock", rundir);

    char configpath[PATH_MAX];
    const char *xdg_config = getenv("XDG_CONFIG_HOME");
    if (xdg_config && *xdg_config) {
        mkdir(xdg_config, 0700);
        snprintf(configpath, sizeof(configpath), "%s/xisback.conf", xdg_config);
    } else {
        const char *home = getenv("HOME");
        if (!home || !*home) {
            home = "/tmp";
        }
        char configdir[PATH_MAX];
        snprintf(configdir, sizeof(configdir), "%s/.config", home);
        mkdir(configdir, 0700);
        snprintf(configpath, sizeof(configpath), "%s/xisback.conf", configdir);
    }

    int lockfd = open(lockpath, O_CREAT | O_RDWR, 0600);
    if (lockfd < 0) {
        perror("xisback: open lock");
        return 1;
    }

    if (flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
        close(lockfd);
        return run_as_client(sockpath, &cmd);
    }

    return run_as_daemon(sockpath, configpath, &cmd);
}
