/*
 * xisserve - GTK2 application launcher (kickoff/krunner-style), companion
 * to xispanel's `xisserve` widget (see ../xispanel/widgets/xisserve.c --
 * already implemented and shipping; `launcher` stays the simple
 * pin-a-shortcut widget, no search/no .desktop parsing).
 *
 * v1 scope: parse the argv contract PROTOCOL.md documents, enforce a
 * flock'd singleton (same pattern xisback/xisguard already use) that
 * relays a second invocation's argv to the running instance over a
 * control socket as a reposition+retheme+toggle-visibility, scan
 * .desktop files across $XDG_DATA_DIRS + ~/.local/share/applications
 * into a filterable list, and launch whichever entry is clicked (or
 * Enter-activated) via the same "shell out through sh -c, don't wait"
 * pattern xispanel's own run_detached() uses. No icon rendering yet, no
 * in-app action search (HUD) -- see README.md's "Planned scope".
 *
 * Positioning: the window is a GTK_WINDOW_POPUP (override-redirect,
 * unmanaged by the WM) so its on-screen position is exactly what we ask
 * for, per PROTOCOL.md's anchor/edge/output flags, without fighting a
 * WM's own placement policy.
 */
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define WIN_WIDTH 380
#define WIN_HEIGHT 460

enum { COL_NAME = 0, COL_EXEC, N_COLS };

typedef struct {
    int anchor_x, anchor_y, anchor_w, anchor_h;
    char edge[8];
    int output_x, output_y, output_w, output_h;
    char bg[10];
    char fg[10];
    char font[128];
    int font_size;
} LaunchArgs;

static LaunchArgs g_args;
static GtkWidget *g_window;
static GtkWidget *g_entry;
static GtkWidget *g_treeview;
static GtkListStore *g_store;
static GtkTreeModel *g_filter;
static pid_t g_watch_pid;

/* ---- argv / JSON plumbing -------------------------------------------- */

enum {
    OPT_ANCHOR_X = 1000, OPT_ANCHOR_Y, OPT_ANCHOR_W, OPT_ANCHOR_H,
    OPT_EDGE, OPT_OUTPUT_X, OPT_OUTPUT_Y, OPT_OUTPUT_W, OPT_OUTPUT_H,
    OPT_BG, OPT_FG, OPT_FONT, OPT_FONT_SIZE,
};

static const struct option kLongOpts[] = {
    {"anchor-x", required_argument, 0, OPT_ANCHOR_X},
    {"anchor-y", required_argument, 0, OPT_ANCHOR_Y},
    {"anchor-w", required_argument, 0, OPT_ANCHOR_W},
    {"anchor-h", required_argument, 0, OPT_ANCHOR_H},
    {"edge", required_argument, 0, OPT_EDGE},
    {"output-x", required_argument, 0, OPT_OUTPUT_X},
    {"output-y", required_argument, 0, OPT_OUTPUT_Y},
    {"output-w", required_argument, 0, OPT_OUTPUT_W},
    {"output-h", required_argument, 0, OPT_OUTPUT_H},
    {"bg", required_argument, 0, OPT_BG},
    {"fg", required_argument, 0, OPT_FG},
    {"font", required_argument, 0, OPT_FONT},
    {"font-size", required_argument, 0, OPT_FONT_SIZE},
    {0, 0, 0, 0},
};

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s --anchor-x=<px> --anchor-y=<px> --anchor-w=<px> --anchor-h=<px> "
            "--edge=top|bottom|left|right --output-x=<px> --output-y=<px> --output-w=<px> "
            "--output-h=<px> --bg=#RRGGBBAA --fg=#RRGGBBAA --font=<family> --font-size=<px>\n",
            argv0);
}

static int parse_argv(int argc, char **argv, LaunchArgs *a)
{
    memset(a, 0, sizeof(*a));
    snprintf(a->edge, sizeof(a->edge), "top");
    snprintf(a->bg, sizeof(a->bg), "#282828ff");
    snprintf(a->fg, sizeof(a->fg), "#ffffffff");
    snprintf(a->font, sizeof(a->font), "sans-serif");
    a->font_size = 12;
    a->output_w = 1920;
    a->output_h = 1080;

    int c;
    optind = 1;
    while ((c = getopt_long(argc, argv, "", kLongOpts, NULL)) != -1) {
        switch (c) {
        case OPT_ANCHOR_X: a->anchor_x = atoi(optarg); break;
        case OPT_ANCHOR_Y: a->anchor_y = atoi(optarg); break;
        case OPT_ANCHOR_W: a->anchor_w = atoi(optarg); break;
        case OPT_ANCHOR_H: a->anchor_h = atoi(optarg); break;
        case OPT_EDGE: snprintf(a->edge, sizeof(a->edge), "%s", optarg); break;
        case OPT_OUTPUT_X: a->output_x = atoi(optarg); break;
        case OPT_OUTPUT_Y: a->output_y = atoi(optarg); break;
        case OPT_OUTPUT_W: a->output_w = atoi(optarg); break;
        case OPT_OUTPUT_H: a->output_h = atoi(optarg); break;
        case OPT_BG: snprintf(a->bg, sizeof(a->bg), "%s", optarg); break;
        case OPT_FG: snprintf(a->fg, sizeof(a->fg), "%s", optarg); break;
        case OPT_FONT: snprintf(a->font, sizeof(a->font), "%s", optarg); break;
        case OPT_FONT_SIZE: a->font_size = atoi(optarg); break;
        default: return -1;
        }
    }
    return 0;
}

/* Same hand-rolled flat-JSON helpers xisguard.c's control socket uses
 * (json_escape_str/json_get_str/json_get_int) -- duplicated here rather
 * than shared since xisserve is its own binary with no common library. */
static void json_escape_str(char *dst, size_t dst_sz, const char *src)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 1 < dst_sz; i++) {
        if (src[i] == '"' || src[i] == '\\') {
            if (j + 2 >= dst_sz) break;
            dst[j++] = '\\';
            dst[j++] = src[i];
        } else if ((unsigned char)src[i] >= 0x20) {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

static int json_get_str(const char *msg, const char *key, char *dst, size_t dst_sz)
{
    dst[0] = '\0';
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(msg, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ') p++;
    if (*p != '"') return 0;
    p++;
    const char *end = strchr(p, '"');
    if (!end) return 0;
    size_t len = (size_t)(end - p);
    if (len >= dst_sz) len = dst_sz - 1;
    strncpy(dst, p, len);
    dst[len] = '\0';
    return 1;
}

static int json_get_int(const char *msg, const char *key, int *out)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(msg, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ') p++;
    return sscanf(p, "%d", out) == 1;
}

static int parse_json_args(const char *msg, LaunchArgs *a)
{
    memset(a, 0, sizeof(*a));
    int ok = 1;
    ok &= json_get_int(msg, "anchor_x", &a->anchor_x);
    ok &= json_get_int(msg, "anchor_y", &a->anchor_y);
    ok &= json_get_int(msg, "anchor_w", &a->anchor_w);
    ok &= json_get_int(msg, "anchor_h", &a->anchor_h);
    ok &= json_get_str(msg, "edge", a->edge, sizeof(a->edge));
    ok &= json_get_int(msg, "output_x", &a->output_x);
    ok &= json_get_int(msg, "output_y", &a->output_y);
    ok &= json_get_int(msg, "output_w", &a->output_w);
    ok &= json_get_int(msg, "output_h", &a->output_h);
    ok &= json_get_str(msg, "bg", a->bg, sizeof(a->bg));
    ok &= json_get_str(msg, "fg", a->fg, sizeof(a->fg));
    json_get_str(msg, "font", a->font, sizeof(a->font));
    json_get_int(msg, "font_size", &a->font_size);
    return ok;
}

/* ---- singleton / control socket --------------------------------------- */

static int send_to_running(const char *sockpath, const LaunchArgs *a)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("xisserve: socket");
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("xisserve: connect");
        close(fd);
        return -1;
    }

    char font_esc[256];
    json_escape_str(font_esc, sizeof(font_esc), a->font);
    char msg[768];
    int n = snprintf(msg, sizeof(msg),
                      "{\"anchor_x\":%d,\"anchor_y\":%d,\"anchor_w\":%d,\"anchor_h\":%d,\"edge\":\"%s\","
                      "\"output_x\":%d,\"output_y\":%d,\"output_w\":%d,\"output_h\":%d,"
                      "\"bg\":\"%s\",\"fg\":\"%s\",\"font\":\"%s\",\"font_size\":%d}\n",
                      a->anchor_x, a->anchor_y, a->anchor_w, a->anchor_h, a->edge, a->output_x, a->output_y,
                      a->output_w, a->output_h, a->bg, a->fg, font_esc, a->font_size);
    if (n > 0) {
        ssize_t written = write(fd, msg, (size_t)n);
        (void)written;
    }
    close(fd);
    return 0;
}

static int open_listen_socket(const char *sockpath)
{
    unlink(sockpath);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("xisserve: socket");
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("xisserve: bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 8) != 0) {
        perror("xisserve: listen");
        close(fd);
        return -1;
    }
    return fd;
}

/* ---- app launching ----------------------------------------------------- */

/* Same fork+setsid+execl-via-sh-c pattern xispanel.c's run_detached()
 * uses -- duplicated here since xisserve is a standalone binary. */
static void run_detached(const char *cmd)
{
    if (!cmd || !cmd[0]) return;
    pid_t pid = fork();
    if (pid < 0) {
        perror("xisserve: fork");
        return;
    }
    if (pid == 0) {
        setsid();
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
}

/* Same single-quote shell-escaping helper folder.c/xisserve widget.c
 * duplicate locally rather than share, per existing repo convention. */
static void shell_quote(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    if (o + 1 < outsz) out[o++] = '\'';
    for (const char *p = in; *p; p++) {
        if (*p == '\'') {
            const char *seq = "'\\''";
            for (const char *s = seq; *s && o + 1 < outsz; s++) out[o++] = *s;
        } else if (o + 1 < outsz) {
            out[o++] = *p;
        }
    }
    if (o + 1 < outsz) out[o++] = '\'';
    out[o < outsz ? o : outsz - 1] = 0;
}

/* Same terminal fallback chain folder.c's run_terminal_at() uses. */
static void build_terminal_exec(const char *cmd, char *out, size_t outsz)
{
    char q[600];
    shell_quote(cmd, q, sizeof(q));
    snprintf(out, outsz,
             "(exec xdg-terminal-exec -- %s 2>/dev/null) || "
             "([ -n \"$TERMINAL\" ] && exec \"$TERMINAL\" -e %s) || "
             "(exec x-terminal-emulator -e %s 2>/dev/null) || "
             "(exec xterm -e %s)",
             q, q, q, q);
}

/* Drops %f/%F/%u/%U/%i/%c/%k/etc field codes per the .desktop spec (we
 * pass no files/URIs), keeps a literal %% as a single %. */
static void strip_exec_field_codes(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    for (const char *p = in; *p && o + 1 < outsz; p++) {
        if (*p == '%' && p[1]) {
            if (p[1] == '%' && o + 1 < outsz) out[o++] = '%';
            p++;
            continue;
        }
        out[o++] = *p;
    }
    out[o] = 0;
}

static void parse_desktop_file(const char *path, GtkListStore *store)
{
    FILE *f = fopen(path, "r");
    if (!f) return;

    char name[256] = "";
    char exec_raw[1024] = "";
    char try_exec[512] = "";
    int is_application = 1;
    int no_display = 0;
    int hidden = 0;
    int terminal = 0;
    int in_entry = 0;
    int seen_entry = 0;

    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0;
        if (line[0] == '[') {
            if (strncmp(line, "[Desktop Entry]", 15) == 0) {
                in_entry = 1;
                seen_entry = 1;
            } else if (seen_entry) {
                break;
            } else {
                in_entry = 0;
            }
            continue;
        }
        if (!in_entry) continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        const char *key = line;
        const char *val = eq + 1;
        if (strcmp(key, "Name") == 0) snprintf(name, sizeof(name), "%s", val);
        else if (strcmp(key, "Exec") == 0) snprintf(exec_raw, sizeof(exec_raw), "%s", val);
        else if (strcmp(key, "Type") == 0) is_application = (strcmp(val, "Application") == 0);
        else if (strcmp(key, "NoDisplay") == 0) no_display = (strcasecmp(val, "true") == 0);
        else if (strcmp(key, "Hidden") == 0) hidden = (strcasecmp(val, "true") == 0);
        else if (strcmp(key, "Terminal") == 0) terminal = (strcasecmp(val, "true") == 0);
        else if (strcmp(key, "TryExec") == 0) snprintf(try_exec, sizeof(try_exec), "%s", val);
    }
    fclose(f);

    if (!name[0] || !exec_raw[0] || !is_application || no_display || hidden) return;
    if (try_exec[0]) {
        char *found = g_find_program_in_path(try_exec);
        if (!found) return;
        g_free(found);
    }

    char exec_clean[1024];
    strip_exec_field_codes(exec_raw, exec_clean, sizeof(exec_clean));

    char final_exec[1200];
    if (terminal) {
        build_terminal_exec(exec_clean, final_exec, sizeof(final_exec));
    } else {
        snprintf(final_exec, sizeof(final_exec), "%s", exec_clean);
    }

    GtkTreeIter it;
    gtk_list_store_append(store, &it);
    gtk_list_store_set(store, &it, COL_NAME, name, COL_EXEC, final_exec, -1);
}

static void scan_dir_desktop_files(const char *dir, GtkListStore *store, GHashTable *seen)
{
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        size_t nlen = strlen(de->d_name);
        if (nlen < 9 || strcmp(de->d_name + nlen - 8, ".desktop") != 0) continue;
        if (g_hash_table_contains(seen, de->d_name)) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        parse_desktop_file(path, store);
        g_hash_table_add(seen, g_strdup(de->d_name));
    }
    closedir(d);
}

/* Home dir first (XDG_DATA_HOME takes priority), then each entry of
 * XDG_DATA_DIRS in order -- basenames already seen are skipped so an
 * earlier, higher-priority directory's copy of a .desktop file wins. */
static void rescan_apps(void)
{
    gtk_list_store_clear(g_store);
    GHashTable *seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    char home_apps[PATH_MAX];
    const char *xdg_data_home = getenv("XDG_DATA_HOME");
    if (xdg_data_home && *xdg_data_home) {
        snprintf(home_apps, sizeof(home_apps), "%s/applications", xdg_data_home);
    } else {
        const char *home = getenv("HOME");
        snprintf(home_apps, sizeof(home_apps), "%s/.local/share/applications", home ? home : "");
    }
    scan_dir_desktop_files(home_apps, g_store, seen);

    const char *xdg_data_dirs = getenv("XDG_DATA_DIRS");
    if (!xdg_data_dirs || !*xdg_data_dirs) xdg_data_dirs = "/usr/local/share:/usr/share";
    char *dirs_copy = g_strdup(xdg_data_dirs);
    char *saveptr = NULL;
    for (char *tok = strtok_r(dirs_copy, ":", &saveptr); tok; tok = strtok_r(NULL, ":", &saveptr)) {
        char dirpath[PATH_MAX];
        snprintf(dirpath, sizeof(dirpath), "%s/applications", tok);
        scan_dir_desktop_files(dirpath, g_store, seen);
    }
    g_free(dirs_copy);
    g_hash_table_destroy(seen);
}

static void hide_launcher(void); /* defined below, alongside the pointer/keyboard grab it releases */

static void launch_iter(GtkTreeModel *model, GtkTreeIter *iter)
{
    gchar *exec = NULL;
    gtk_tree_model_get(model, iter, COL_EXEC, &exec, -1);
    if (exec) {
        run_detached(exec);
        g_free(exec);
    }
    hide_launcher();
}

/* ---- theming / positioning --------------------------------------------- */

static void hex_to_rgba(const char *hex, double *r, double *g, double *b, double *a)
{
    unsigned ri = 0, gi = 0, bi = 0, ai = 255;
    if (hex && hex[0] == '#' && strlen(hex) >= 7) {
        sscanf(hex + 1, "%2x%2x%2x", &ri, &gi, &bi);
        if (strlen(hex) >= 9) sscanf(hex + 7, "%2x", &ai);
    }
    *r = ri / 255.0;
    *g = gi / 255.0;
    *b = bi / 255.0;
    *a = ai / 255.0;
}

static gboolean on_window_expose(GtkWidget *w, GdkEventExpose *ev, gpointer data)
{
    (void)data;
    cairo_t *cr = gdk_cairo_create(w->window);
    gdk_cairo_region(cr, ev->region);
    cairo_clip(cr);
    double r, g, b, a;
    hex_to_rgba(g_args.bg, &r, &g, &b, &a);
    cairo_set_operator(cr, CAIRO_OPERATOR_SOURCE);
    cairo_set_source_rgba(cr, r, g, b, a);
    cairo_paint(cr);
    cairo_destroy(cr);
    return FALSE;
}

static void apply_theme(void)
{
    double r, g, b, a;
    hex_to_rgba(g_args.fg, &r, &g, &b, &a);
    GdkColor fg_color = {0, (guint16)(r * 65535), (guint16)(g * 65535), (guint16)(b * 65535)};
    hex_to_rgba(g_args.bg, &r, &g, &b, &a);
    GdkColor bg_color = {0, (guint16)(r * 65535), (guint16)(g * 65535), (guint16)(b * 65535)};

    gtk_widget_modify_text(g_entry, GTK_STATE_NORMAL, &fg_color);
    gtk_widget_modify_base(g_entry, GTK_STATE_NORMAL, &bg_color);
    gtk_widget_modify_text(g_treeview, GTK_STATE_NORMAL, &fg_color);
    gtk_widget_modify_base(g_treeview, GTK_STATE_NORMAL, &bg_color);

    PangoFontDescription *desc = pango_font_description_new();
    pango_font_description_set_family(desc, g_args.font[0] ? g_args.font : "sans-serif");
    if (g_args.font_size > 0) pango_font_description_set_absolute_size(desc, g_args.font_size * PANGO_SCALE);
    gtk_widget_modify_font(g_entry, desc);
    gtk_widget_modify_font(g_treeview, desc);
    pango_font_description_free(desc);

    gtk_widget_queue_draw(g_window);
}

/* Glues the popup to the panel's outer edge aligned with the anchor
 * rect, then clamps it inside the output rect -- the same convention
 * PROTOCOL.md documents and menu.c's panel_menu_open_tree_lazy() already
 * applies for xispanel's own popups. */
static void reposition_window(void)
{
    int ww = WIN_WIDTH, wh = WIN_HEIGHT;
    int x, y;
    if (strcmp(g_args.edge, "top") == 0) {
        x = g_args.anchor_x;
        y = g_args.anchor_y + g_args.anchor_h;
    } else if (strcmp(g_args.edge, "bottom") == 0) {
        x = g_args.anchor_x;
        y = g_args.anchor_y - wh;
    } else if (strcmp(g_args.edge, "left") == 0) {
        x = g_args.anchor_x + g_args.anchor_w;
        y = g_args.anchor_y;
    } else {
        x = g_args.anchor_x - ww;
        y = g_args.anchor_y;
    }

    int min_x = g_args.output_x, max_x = g_args.output_x + g_args.output_w - ww;
    if (max_x < min_x) max_x = min_x;
    if (x < min_x) x = min_x;
    if (x > max_x) x = max_x;

    int min_y = g_args.output_y, max_y = g_args.output_y + g_args.output_h - wh;
    if (max_y < min_y) max_y = min_y;
    if (y < min_y) y = min_y;
    if (y > max_y) y = max_y;

    gtk_window_move(GTK_WINDOW(g_window), x, y);
}

/* Pointer grab uses owner_events=TRUE: clicks landing on one of our own
 * widgets are reported to that widget as usual (normal GTK event
 * delivery), while clicks on any *other* window on screen -- since
 * nothing else can steal the grab -- are reported to g_window itself,
 * which on_window_button_press() below treats as "clicked outside,
 * dismiss". Same idea GtkMenu's own popups use internally. Keyboard grab
 * is what guarantees this override-redirect window actually receives
 * key events on open, since it isn't WM-managed and so never goes
 * through the normal click-to-focus/WM_TAKE_FOCUS path. */
static void grab_input(void)
{
    guint32 t = gtk_get_current_event_time();
    GdkGrabStatus pg = gdk_pointer_grab(g_window->window, TRUE, GDK_BUTTON_PRESS_MASK, NULL, NULL, t);
    if (pg != GDK_GRAB_SUCCESS) {
        g_warning("xisserve: pointer grab failed (status %d), outside-click-to-close won't work", pg);
    }
    GdkGrabStatus kg = gdk_keyboard_grab(g_window->window, TRUE, t);
    if (kg != GDK_GRAB_SUCCESS) {
        g_warning("xisserve: keyboard grab failed (status %d)", kg);
    }
}

static void ungrab_input(void)
{
    guint32 t = gtk_get_current_event_time();
    gdk_pointer_ungrab(t);
    gdk_keyboard_ungrab(t);
}

static void hide_launcher(void)
{
    ungrab_input();
    gtk_widget_hide(g_window);
}

static void show_launcher(void)
{
    rescan_apps();
    gtk_entry_set_text(GTK_ENTRY(g_entry), "");
    gtk_widget_show_all(g_window);
    gtk_window_present(GTK_WINDOW(g_window));
    gdk_window_raise(g_window->window);
    gdk_window_focus(g_window->window, GDK_CURRENT_TIME);
    grab_input();
    gtk_widget_grab_focus(g_entry);
}

static void toggle_visibility(void)
{
    if (GTK_WIDGET_VISIBLE(g_window)) {
        hide_launcher();
    } else {
        show_launcher();
    }
}

/* Reads /proc/<pid>/comm (trimmed). Returns 0 if the process is gone or
 * /proc isn't available, leaving comm untouched. */
static int read_proc_comm(pid_t pid, char *comm, size_t comm_sz)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int ok = fgets(comm, comm_sz, f) != NULL;
    fclose(f);
    if (!ok) return 0;
    size_t l = strlen(comm);
    while (l > 0 && (comm[l - 1] == '\n' || comm[l - 1] == '\r')) comm[--l] = 0;
    return 1;
}

static pid_t read_proc_ppid(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256];
    pid_t ppid = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            sscanf(line + 5, "%d", &ppid);
            break;
        }
    }
    fclose(f);
    return ppid;
}

/* xispanel's run_detached() forks a single "sh -c '<cmd>'" child and
 * never waits on it. Some shells tail-call-exec the last command of a
 * -c string, which would make that child become xisserve itself
 * (getppid() then reads as xispanel's own PID directly) -- but that
 * optimization isn't guaranteed, and in practice the shell here stays
 * alive as an intermediary, blocked waiting on us, so our direct parent
 * is that shell and never changes even after xispanel dies. Climb past
 * a shell-named direct parent to the grandparent, which is xispanel. */
static pid_t resolve_watch_pid(void)
{
    pid_t p = getppid();
    char comm[64];
    if (read_proc_comm(p, comm, sizeof(comm)) &&
        (strcmp(comm, "sh") == 0 || strcmp(comm, "bash") == 0 || strcmp(comm, "dash") == 0 ||
         strcmp(comm, "ash") == 0)) {
        pid_t gp = read_proc_ppid(p);
        if (gp > 0) p = gp;
    }
    return p;
}

/* Polled rather than event-driven: there's no portable "notify me when
 * this other process exits" primitive (Linux's PR_SET_PDEATHSIG only
 * covers one's own direct parent, which per resolve_watch_pid() above
 * isn't reliably xispanel here anyway, and still just delivers a signal
 * we'd have to poll for regardless). */
static gboolean check_parent_alive(gpointer data)
{
    (void)data;
    if (kill(g_watch_pid, 0) != 0 && errno == ESRCH) {
        gtk_main_quit();
    }
    return TRUE;
}

/* ---- power actions -------------------------------------------------------- */

typedef struct {
    const char *label;
    const char *probe_bin; /* must resolve via $PATH for this button to be shown; NULL = always shown */
    const char *cmd;       /* shell command run (after confirmation) on click; NULL = stub, no action yet */
    const char *confirm_msg;
} PowerAction;

/* systemd-logind's `loginctl`/`systemctl` cover shutdown/reboot/suspend/
 * lock on any systemd system without needing a desktop-specific tool;
 * "Trocar usuario" only has a real answer under LightDM's `dm-tool`, and
 * "Sair" (logout) has no generic single command at all for a
 * WM-agnostic session like this one -- both ship as visible buttons per
 * the ask, the latter always shown (cmd left NULL, a stub), the former
 * hidden unless dm-tool is actually installed. */
static const PowerAction kPowerActions[] = {
    {"Desligar", "systemctl", "systemctl poweroff", "Desligar o computador agora?"},
    {"Reiniciar", "systemctl", "systemctl reboot", "Reiniciar o computador agora?"},
    {"Suspender", "systemctl", "systemctl suspend", "Suspender o computador agora?"},
    {"Sair", NULL, NULL, "Encerrar a sessao atual?"},
    {"Trocar usuario", "dm-tool", "dm-tool switch-to-greeter", "Trocar de usuario agora?"},
    {"Bloquear tela", "loginctl", "loginctl lock-session", "Bloquear a tela agora?"},
};
#define N_POWER_ACTIONS ((int)(sizeof(kPowerActions) / sizeof(kPowerActions[0])))

static void on_power_button_clicked(GtkWidget *btn, gpointer user_data)
{
    (void)btn;
    const PowerAction *action = (const PowerAction *)user_data;
    hide_launcher();

    GtkWidget *dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "%s",
                                                action->confirm_msg);
    gtk_window_set_title(GTK_WINDOW(dialog), action->label);
    gint resp = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);

    if (resp == GTK_RESPONSE_YES && action->cmd) {
        run_detached(action->cmd);
    }
}

/* ---- control socket I/O -------------------------------------------------- */

static gboolean on_ctl_accept(GIOChannel *source, GIOCondition cond, gpointer data)
{
    (void)cond;
    (void)data;
    int listenfd = g_io_channel_unix_get_fd(source);
    int cfd = accept(listenfd, NULL, NULL);
    if (cfd < 0) return TRUE;

    char buf[1024];
    size_t len = 0;
    while (len + 1 < sizeof(buf)) {
        ssize_t n = recv(cfd, buf + len, sizeof(buf) - 1 - len, 0);
        if (n <= 0) break;
        len += (size_t)n;
        if (memchr(buf, '\n', len)) break;
    }
    buf[len] = 0;
    close(cfd);

    LaunchArgs newargs;
    if (parse_json_args(buf, &newargs)) {
        g_args = newargs;
        apply_theme();
        reposition_window();
        toggle_visibility();
    }
    return TRUE;
}

/* ---- UI callbacks --------------------------------------------------------- */

static gboolean filter_visible_func(GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
    (void)data;
    const char *query = gtk_entry_get_text(GTK_ENTRY(g_entry));
    if (!query || !*query) return TRUE;
    gchar *name = NULL;
    gtk_tree_model_get(model, iter, COL_NAME, &name, -1);
    gboolean visible = FALSE;
    if (name) {
        gchar *nl = g_utf8_casefold(name, -1);
        gchar *ql = g_utf8_casefold(query, -1);
        visible = strstr(nl, ql) != NULL;
        g_free(nl);
        g_free(ql);
        g_free(name);
    }
    return visible;
}

static void on_entry_changed(GtkEditable *e, gpointer data)
{
    (void)e;
    (void)data;
    gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(g_filter));
    GtkTreeIter iter;
    if (gtk_tree_model_get_iter_first(g_filter, &iter)) {
        gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(g_treeview)), &iter);
    }
}

static void on_entry_activate(GtkEntry *entry, gpointer data)
{
    (void)entry;
    (void)data;
    GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(g_treeview));
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(g_treeview));
    GtkTreeIter iter;
    if (gtk_tree_selection_get_selected(sel, NULL, &iter)) {
        launch_iter(model, &iter);
        return;
    }
    if (gtk_tree_model_get_iter_first(model, &iter)) launch_iter(model, &iter);
}

static gboolean on_entry_key_press(GtkWidget *w, GdkEventKey *ev, gpointer data)
{
    (void)w;
    (void)data;
    if (ev->keyval == GDK_Escape) {
        hide_launcher();
        return TRUE;
    }
    if (ev->keyval == GDK_Up || ev->keyval == GDK_Down) {
        GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(g_treeview));
        GtkTreeModel *model = NULL;
        GtkTreeIter iter;
        GtkTreePath *path;
        if (!gtk_tree_selection_get_selected(sel, &model, &iter)) {
            model = gtk_tree_view_get_model(GTK_TREE_VIEW(g_treeview));
            if (!gtk_tree_model_get_iter_first(model, &iter)) return TRUE;
            path = gtk_tree_model_get_path(model, &iter);
        } else {
            path = gtk_tree_model_get_path(model, &iter);
            if (ev->keyval == GDK_Down) gtk_tree_path_next(path);
            else gtk_tree_path_prev(path);
        }
        if (gtk_tree_model_get_iter(model, &iter, path)) {
            gtk_tree_selection_select_iter(sel, &iter);
            gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(g_treeview), path, NULL, FALSE, 0, 0);
        }
        gtk_tree_path_free(path);
        return TRUE;
    }
    return FALSE;
}

static gboolean on_tree_button_press(GtkWidget *tv, GdkEventButton *ev, gpointer data)
{
    (void)data;
    if (ev->type != GDK_BUTTON_PRESS || ev->button != 1) return FALSE;
    GtkTreePath *path = NULL;
    if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(tv), (int)ev->x, (int)ev->y, &path, NULL, NULL, NULL)) {
        GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(tv));
        GtkTreeIter iter;
        if (gtk_tree_model_get_iter(model, &iter, path)) launch_iter(model, &iter);
        gtk_tree_path_free(path);
    }
    return FALSE;
}

/* Fires both for genuine outside clicks (owner_events=TRUE reports those
 * to the grab window, i.e. us, per grab_input()'s comment) and for
 * clicks landing on g_window's own background between child widgets
 * (the vbox has no GdkWindow of its own, so those land here too) --
 * only the former should close the popup, hence the bounds check. */
static gboolean on_window_button_press(GtkWidget *w, GdkEventButton *ev, gpointer data)
{
    (void)data;
    if (ev->type != GDK_BUTTON_PRESS) return FALSE;
    if (ev->x < 0 || ev->y < 0 || ev->x >= w->allocation.width || ev->y >= w->allocation.height) {
        hide_launcher();
        return TRUE;
    }
    return FALSE;
}

/* The WM or another client can steal an active grab out from under us
 * (e.g. a different app opening its own grabbing popup); when that
 * happens we're no longer guaranteed input focus or outside-click
 * detection, so just close rather than linger in a half-working state. */
static gboolean on_window_grab_broken(GtkWidget *w, GdkEventGrabBroken *ev, gpointer data)
{
    (void)w;
    (void)ev;
    (void)data;
    gtk_widget_hide(g_window);
    return FALSE;
}

static gint sort_by_name(GtkTreeModel *model, GtkTreeIter *ia, GtkTreeIter *ib, gpointer data)
{
    (void)data;
    gchar *a = NULL, *b = NULL;
    gtk_tree_model_get(model, ia, COL_NAME, &a, -1);
    gtk_tree_model_get(model, ib, COL_NAME, &b, -1);
    gint r = g_ascii_strcasecmp(a ? a : "", b ? b : "");
    g_free(a);
    g_free(b);
    return r;
}

static void build_ui(void)
{
    g_window = gtk_window_new(GTK_WINDOW_POPUP);
    gtk_widget_set_size_request(g_window, WIN_WIDTH, WIN_HEIGHT);
    gtk_widget_add_events(g_window, GDK_BUTTON_PRESS_MASK);

    GdkScreen *screen = gtk_widget_get_screen(g_window);
    GdkColormap *cmap = gdk_screen_get_rgba_colormap(screen);
    if (cmap) gtk_widget_set_colormap(g_window, cmap);
    gtk_widget_set_app_paintable(g_window, TRUE);

    g_signal_connect(g_window, "expose-event", G_CALLBACK(on_window_expose), NULL);
    g_signal_connect(g_window, "button-press-event", G_CALLBACK(on_window_button_press), NULL);
    g_signal_connect(g_window, "grab-broken-event", G_CALLBACK(on_window_grab_broken), NULL);

    GtkWidget *vbox = gtk_vbox_new(FALSE, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 6);
    gtk_container_add(GTK_CONTAINER(g_window), vbox);

    g_entry = gtk_entry_new();
    g_signal_connect(g_entry, "changed", G_CALLBACK(on_entry_changed), NULL);
    g_signal_connect(g_entry, "activate", G_CALLBACK(on_entry_activate), NULL);
    g_signal_connect(g_entry, "key-press-event", G_CALLBACK(on_entry_key_press), NULL);
    gtk_box_pack_start(GTK_BOX(vbox), g_entry, FALSE, FALSE, 0);

    g_store = gtk_list_store_new(N_COLS, G_TYPE_STRING, G_TYPE_STRING);
    gtk_tree_sortable_set_sort_func(GTK_TREE_SORTABLE(g_store), COL_NAME, sort_by_name, NULL, NULL);
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(g_store), COL_NAME, GTK_SORT_ASCENDING);

    g_filter = gtk_tree_model_filter_new(GTK_TREE_MODEL(g_store), NULL);
    gtk_tree_model_filter_set_visible_func(GTK_TREE_MODEL_FILTER(g_filter), filter_visible_func, NULL, NULL);

    g_treeview = gtk_tree_view_new_with_model(g_filter);
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(g_treeview), FALSE);
    GtkCellRenderer *rend = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes("Name", rend, "text", COL_NAME, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(g_treeview), col);
    g_signal_connect(g_treeview, "button-press-event", G_CALLBACK(on_tree_button_press), NULL);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll), g_treeview);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    GtkWidget *sep = gtk_hseparator_new();
    gtk_box_pack_start(GTK_BOX(vbox), sep, FALSE, FALSE, 0);

    GtkWidget *footer = gtk_hbox_new(TRUE, 2);
    for (int i = 0; i < N_POWER_ACTIONS; i++) {
        const PowerAction *action = &kPowerActions[i];
        if (action->probe_bin) {
            gchar *found = g_find_program_in_path(action->probe_bin);
            if (!found) continue;
            g_free(found);
        }
        GtkWidget *btn = gtk_button_new_with_label(action->label);
        g_signal_connect(btn, "clicked", G_CALLBACK(on_power_button_clicked), (gpointer)action);
        gtk_box_pack_start(GTK_BOX(footer), btn, TRUE, TRUE, 0);
    }
    gtk_box_pack_start(GTK_BOX(vbox), footer, FALSE, FALSE, 0);
}

int main(int argc, char **argv)
{
    gtk_init(&argc, &argv);

    LaunchArgs args;
    if (parse_argv(argc, argv, &args) != 0) {
        usage(argv[0]);
        return 1;
    }

    const char *rundir = getenv("XDG_RUNTIME_DIR");
    if (!rundir || !*rundir) rundir = "/tmp";
    char lockpath[PATH_MAX], sockpath[PATH_MAX];
    snprintf(lockpath, sizeof(lockpath), "%s/xisserve.lock", rundir);
    snprintf(sockpath, sizeof(sockpath), "%s/xisserve.sock", rundir);

    int lockfd = open(lockpath, O_CREAT | O_RDWR, 0600);
    if (lockfd < 0) {
        perror("xisserve: open lock");
        return 1;
    }

    if (flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
        close(lockfd);
        if (send_to_running(sockpath, &args) != 0) {
            fprintf(stderr, "xisserve: another instance appears to be running but is not reachable at %s\n",
                    sockpath);
            return 1;
        }
        return 0;
    }

    /* We hold the lock: this invocation becomes the singleton daemon. */
    g_watch_pid = resolve_watch_pid();
    g_timeout_add_seconds(2, check_parent_alive, NULL);

    g_args = args;
    build_ui();
    apply_theme();
    reposition_window();

    int listenfd = open_listen_socket(sockpath);
    if (listenfd < 0) {
        fprintf(stderr,
                "xisserve: failed to open control socket %s, later invocations won't be able to "
                "toggle this instance\n",
                sockpath);
    } else {
        GIOChannel *chan = g_io_channel_unix_new(listenfd);
        g_io_add_watch(chan, G_IO_IN, on_ctl_accept, NULL);
        g_io_channel_unref(chan);
    }

    show_launcher();
    gtk_main();

    unlink(sockpath);
    flock(lockfd, LOCK_UN);
    close(lockfd);
    return 0;
}
