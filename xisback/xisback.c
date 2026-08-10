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

enum mode { MODE_FILL, MODE_STRETCH };

typedef struct {
    int in_use;
    char output[64]; /* "*" or an XRandR output name */
    int desktop; /* -1 for "*" (sticky), else 0-based virtual desktop index */
    enum mode mode;
    int interval; /* seconds between slideshow switches; 0 = never auto-advance */
    int shuffle; /* 0 = alphabetical order, 1 = random order (reshuffled each wrap) */
    char source[PATH_MAX]; /* image file or directory */

    Window win;
    Pixmap cur_pixmap;
    int x, y, width, height;

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

/* ------------------------------------------------------------------ */
/* command line / wire protocol                                       */
/* ------------------------------------------------------------------ */

typedef enum { CMD_NONE, CMD_SET, CMD_CLEAR, CMD_CLEARALL, CMD_LIST, CMD_PING, CMD_QUIT } CmdType;

typedef struct {
    CmdType type;
    char output[64];
    char desktop_str[16];
    int desktop;
    char mode_str[16];
    enum mode mode;
    int interval;
    int shuffle;
    char source[PATH_MAX];
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
            "  --clear             remove the given (output,desktop) layer\n"
            "  --clear-all         remove all layers\n"
            "  --list              list active layers\n"
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
        } else if (!strcmp(argv[i], "--version")) {
            printf("xisback %s\n", XISBACK_VERSION);
            exit(0);
        } else if (!strcmp(argv[i], "--clear")) {
            cmd->type = CMD_CLEAR;
        } else if (!strcmp(argv[i], "--clear-all")) {
            cmd->type = CMD_CLEARALL;
        } else if (!strcmp(argv[i], "--list")) {
            cmd->type = CMD_LIST;
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
        snprintf(buf, bufsz, "SET\t%s\t%s\t%s\t%d\t%d\t%s\n", c->output, c->desktop_str, c->mode_str, c->interval, c->shuffle, c->source);
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

static void layer_ensure_window(Layer *l)
{
    int x, y, w, h;
    layer_geometry(l, &x, &y, &w, &h);

    if (l->win == None) {
        l->win = XCreateSimpleWindow(g_dpy, g_root, x, y, (unsigned)w, (unsigned)h, 0, 0, BlackPixel(g_dpy, g_screen));

        char title[128];
        snprintf(title, sizeof(title), "xisback:%s:%d", l->output, l->desktop);
        XStoreName(g_dpy, l->win, title);

        XClassHint ch;
        ch.res_name = (char *)"xisback";
        ch.res_class = (char *)"xisback";
        XSetClassHint(g_dpy, l->win, &ch);

        Atom wmWindowType = XInternAtom(g_dpy, "_NET_WM_WINDOW_TYPE", False);
        Atom wmWindowTypeDesktop = XInternAtom(g_dpy, "_NET_WM_WINDOW_TYPE_DESKTOP", False);
        XChangeProperty(g_dpy, l->win, wmWindowType, XA_ATOM, 32, PropModeReplace, (unsigned char *)&wmWindowTypeDesktop, 1);

        Atom wmDesktop = XInternAtom(g_dpy, "_NET_WM_DESKTOP", False);
        long desktopVal = (l->desktop < 0) ? 0xFFFFFFFFL : (long)l->desktop;
        XChangeProperty(g_dpy, l->win, wmDesktop, XA_CARDINAL, 32, PropModeReplace, (unsigned char *)&desktopVal, 1);

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

static void layer_render_current(Layer *l)
{
    if (l->n_images == 0) {
        return;
    }
    Pixmap next = render_pixmap(l->width, l->height, l->images[l->img_idx], l->mode);
    if (next == None) {
        return;
    }
    XSetWindowBackgroundPixmap(g_dpy, l->win, next);
    XClearWindow(g_dpy, l->win);
    if (l->cur_pixmap != None) {
        XFreePixmap(g_dpy, l->cur_pixmap);
    }
    l->cur_pixmap = next;
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
static int layer_apply_set(const char *output, int desktop, enum mode mode, int interval, int shuffle, const char *path, char *errbuf, size_t errbufsz)
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
        fprintf(f, "%s\t%s\t%s\t%d\t%d\t%s\n", l->output, dstr, l->mode == MODE_STRETCH ? "stretch" : "fill", l->interval, l->shuffle, l->source);
    }
    fclose(f);
    if (rename(tmp, g_configpath) != 0) {
        fprintf(stderr, "xisback: could not save '%s': %s\n", g_configpath, strerror(errno));
    }
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
        if (len == 0) {
            continue;
        }

        char *fields[6];
        int nf = 0;
        char *p = line;
        fields[nf++] = p;
        while (nf < 6 && (p = strchr(p, '\t'))) {
            *p = 0;
            p++;
            fields[nf++] = p;
        }
        if (nf < 6) {
            fprintf(stderr, "xisback: config: skipping malformed line: '%s'\n", line);
            continue;
        }

        enum mode mode = (strcmp(fields[2], "stretch") == 0) ? MODE_STRETCH : MODE_FILL;
        char errbuf[256];
        if (layer_apply_set(fields[0], parse_desktop(fields[1]), mode, atoi(fields[3]), atoi(fields[4]), fields[5], errbuf, sizeof(errbuf)) != 0) {
            fprintf(stderr, "xisback: config: %s\n", errbuf);
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

    char *fields[8];
    int nf = 0;
    char *p = line;
    fields[nf++] = p;
    while (nf < 8 && (p = strchr(p, '\t'))) {
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
            fprintf(out, "%s\t%s\t%s\t%d\t%d\t%s\n", l->output, dstr, l->mode == MODE_STRETCH ? "stretch" : "fill", l->interval, l->shuffle, l->source);
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
    if (strcmp(fields[0], "SET") == 0) {
        if (nf < 7) {
            fprintf(out, "ERR usage: SET output desktop mode interval shuffle path\n");
            return;
        }
        const char *output = fields[1];
        int desktop = parse_desktop(fields[2]);
        enum mode mode = (strcmp(fields[3], "stretch") == 0) ? MODE_STRETCH : MODE_FILL;
        int interval = atoi(fields[4]);
        int shuffle = atoi(fields[5]);
        const char *path = fields[6];

        char errbuf[256];
        if (layer_apply_set(output, desktop, mode, interval, shuffle, path, errbuf, sizeof(errbuf)) != 0) {
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

static int run_as_client(const char *sockpath, const Command *cmd)
{
    if (cmd->type == CMD_NONE) {
        fprintf(stderr, "xisback: daemon is already running; no command given.\n");
        return 0;
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
        for (int i = 0; i < MAX_LAYERS; i++) {
            if (g_layers[i].in_use && g_layers[i].next_switch > 0) {
                if (soonest == 0 || g_layers[i].next_switch < soonest) {
                    soonest = g_layers[i].next_switch;
                }
            }
        }
        struct timeval tv;
        struct timeval *tvp = NULL;
        if (soonest > 0) {
            long delta = (long)(soonest - now);
            if (delta < 0) {
                delta = 0;
            }
            tv.tv_sec = delta;
            tv.tv_usec = 0;
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
                            layer_ensure_window(&g_layers[i]);
                            layer_render_current(&g_layers[i]);
                        }
                    }
                    malloc_trim(0);
                    XFlush(g_dpy);
                }
            }
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
