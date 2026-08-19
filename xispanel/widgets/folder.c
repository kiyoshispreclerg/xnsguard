/*
 * folder widget - a single folder icon (path=<dir>) that, on click, shows
 * that folder's contents as a real cascading menu (menu.c's
 * panel_menu_open_tree_lazy() -- see its own header comment): every
 * directory level gets "Abrir esta pasta" / "Abrir terminal aqui" (both
 * shelling out to xdg-open / a terminal, same "don't reimplement it"
 * philosophy every other launch action in this codebase already uses --
 * see run_detached()), followed by its entries; a subfolder entry opens
 * its own contents as a nested submenu, and so on.
 *
 * Unlike a DBusMenu tree (bounded by however deep an app's own menu
 * structure goes, fetched with one GetLayout(-1) call), a filesystem tree
 * has no natural bound -- so this reads *one directory level at a time*,
 * only when its submenu is actually opened (menu.c's lazy-expand
 * mechanism), rather than eagerly walking the whole tree up front. Each
 * level is still capped on every axis that could make a single readdir()
 * call slow or unbounded: at most FOLDER_MAX_PER_DIR entries per
 * directory (with a "... mais itens" note if truncated), the overall
 * item count across every level opened so far shares menu.c's own
 * MENU_TREE_MAX_ITEMS cap, and symlinks are never followed at all (the
 * simplest way to rule out a symlink loop). Hidden entries (leading '.')
 * are skipped. The whole menu is rebuilt fresh on every click of the
 * folder icon (not cached across clicks) -- a stale listing from an
 * earlier click would be more confusing than the cost of a bounded
 * readdir() per level actually opened.
 */
#include "../xispanel.h"

#include <X11/Xlib.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define FOLDER_MAX_PER_DIR 100

enum folder_action { ACT_NONE = 0, ACT_OPEN_FOLDER, ACT_OPEN_TERMINAL, ACT_ACTIVATE_ENTRY };

typedef struct {
    char path[PATH_MAX];
    char name[64]; /* tooltip text -- basename of path, or path itself for "/" */
    cairo_surface_t *icon;

    /* One entry per flat menu index handed to menu.c, growing across the
     * whole menu session as more levels get lazily expanded (not just
     * the initial click) -- see folder_lazy_children(). Reset to empty
     * only when a brand new menu is opened (folder_on_button()). */
    enum folder_action action[MENU_TREE_MAX_ITEMS];
    char item_path[MENU_TREE_MAX_ITEMS][PATH_MAX];
    int n_items;
} FolderPriv;

/* Wraps `in` in single quotes for safe use inside an `sh -c` command
 * string, escaping any embedded single quote as the standard POSIX
 * '\'' sequence -- filenames can contain arbitrary shell metacharacters
 * (spaces, $, ;, backticks...), so this can't just be interpolated raw. */
static void shell_quote(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    if (o + 1 < outsz) {
        out[o++] = '\'';
    }
    for (const char *p = in; *p; p++) {
        if (*p == '\'') {
            const char *seq = "'\\''";
            for (const char *s = seq; *s && o + 1 < outsz; s++) {
                out[o++] = *s;
            }
        } else if (o + 1 < outsz) {
            out[o++] = *p;
        }
    }
    if (o + 1 < outsz) {
        out[o++] = '\'';
    }
    out[o < outsz ? o : outsz - 1] = 0;
}

static void run_open_path(const char *path)
{
    char q[PATH_MAX + 8];
    shell_quote(path, q, sizeof(q));
    char cmd[PATH_MAX + 32];
    snprintf(cmd, sizeof(cmd), "xdg-open %s", q);
    run_detached(cmd);
}

/* No single universal "xdg-open for a terminal" the way there is for
 * files -- xdg-terminal-exec is the modern freedesktop proposal but isn't
 * installed everywhere yet, so this tries it first and falls back through
 * $TERMINAL, Debian's x-terminal-emulator alternative, then a plain
 * xterm, each attempt cd-ing into the target directory first. */
static void run_terminal_at(const char *dir)
{
    char q[PATH_MAX + 8];
    shell_quote(dir, q, sizeof(q));
    char cmd[4 * sizeof(q) + 256]; /* q is substituted 4 times below */
    snprintf(cmd, sizeof(cmd),
             "(cd %s && exec xdg-terminal-exec . 2>/dev/null) || "
             "(cd %s && [ -n \"$TERMINAL\" ] && exec \"$TERMINAL\") || "
             "(cd %s && exec x-terminal-emulator 2>/dev/null) || "
             "(cd %s && exec xterm)",
             q, q, q, q);
    run_detached(cmd);
}

static void folder_open_menu(PanelWidget *w);

static int folder_init(PanelWidget *w)
{
    FolderPriv *fp = w->priv;
    if (!kv_get(w->config_kv, "path", fp->path, sizeof(fp->path)) || !fp->path[0]) {
        fprintf(stderr, "xispanel: folder: missing required path=, widget will stay empty\n");
        fp->path[0] = 0;
        return 0;
    }
    /* Strip a single trailing slash (if any, and not just "/" itself) so
     * "<path>/<entry>" concatenation below never doubles up. */
    size_t plen = strlen(fp->path);
    if (plen > 1 && fp->path[plen - 1] == '/') {
        fp->path[plen - 1] = 0;
    }
    if (!kv_get(w->config_kv, "name", fp->name, sizeof(fp->name)) || !fp->name[0]) {
        const char *base = strrchr(fp->path, '/');
        snprintf(fp->name, sizeof(fp->name), "%s", (base && base[1]) ? base + 1 : fp->path);
    }
    /* w->thickness isn't resolved yet this early (init() runs before
     * panel_resolve_geometry() -- see notif_init()'s doc comment in
     * notif.c) -- fall back to the panel's configured thickness_cfg
     * (already set from this panel's own PANEL line) instead of shrinking
     * every icon to a blurry fixed 16px. */
    int thickness = w->thickness > 0 ? w->thickness : w->panel->thickness_cfg;
    int icon_px = thickness > 6 ? thickness - 6 : 16;
    char icon_path[PATH_MAX];
    if (kv_get(w->config_kv, "icon", icon_path, sizeof(icon_path)) && icon_path[0]) {
        fp->icon = load_icon_argb(icon_path, icon_px);
        if (!fp->icon) {
            fprintf(stderr, "xispanel: folder: could not load icon '%s', falling back\n", icon_path);
        }
    }
    if (!fp->icon) {
        fp->icon = resolve_icon_theme_name("folder", icon_px);
    }
    char hotkey[64];
    if (kv_get(w->config_kv, "hotkey", hotkey, sizeof(hotkey)) && hotkey[0]) {
        hotkey_register(w, hotkey, folder_open_menu);
    }
    return 0;
}

static void folder_destroy(PanelWidget *w)
{
    FolderPriv *fp = w->priv;
    if (fp->icon) {
        cairo_surface_destroy(fp->icon);
    }
    hotkey_unregister_widget(w);
}

static void folder_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    FolderPriv *fp = w->priv;
    *out_len = fp->path[0] ? cross_axis : 0;
    *out_min_len = *out_len;
}

static void folder_paint(PanelWidget *w, cairo_t *cr)
{
    FolderPriv *fp = w->priv;
    if (!fp->path[0]) {
        return;
    }
    Panel *p = w->panel;
    int ox, oy, owidth, oheight;
    widget_get_rect(w, &ox, &oy, &owidth, &oheight);
    (void)owidth;
    (void)oheight;
    widget_paint_hover_bg(w, cr);

    int icon_px = w->thickness > 6 ? w->thickness - 6 : 16;
    int icon_x = ox + (w->thickness - icon_px) / 2;
    int icon_y = oy + (w->thickness - icon_px) / 2;
    if (fp->icon) {
        draw_icon_scaled(cr, fp->icon, icon_x, icon_y, icon_px);
    } else {
        draw_fallback_icon(cr, icon_x, icon_y, icon_px, fp->name, p->fg_r, p->fg_g, p->fg_b, panel_text_size(p));
    }
}

static int folder_get_tooltip(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w,
                               int *out_closable, void **out_ctx)
{
    (void)local_x;
    (void)out_closable;
    (void)out_ctx;
    FolderPriv *fp = w->priv;
    if (!fp->path[0]) {
        return 0;
    }
    snprintf(buf, bufsz, "%s", fp->name);
    *anchor_x = 0;
    *anchor_w = w->len;
    return 1;
}

struct folder_entry {
    char name[256];
    int is_dir;
};

static int cmp_folder_entries(const void *a, const void *b)
{
    const struct folder_entry *ea = a, *eb = b;
    if (ea->is_dir != eb->is_dir) {
        return eb->is_dir - ea->is_dir; /* directories first */
    }
    return strcasecmp(ea->name, eb->name);
}

/* Reads *just* dirpath's own immediate listing -- "Abrir esta pasta"/
 * "Abrir terminal aqui" followed by its entries (subdirectories marked
 * out_lazy=1, so *their* contents are only read if/when they get opened
 * in turn) -- into out_items[]/out_lazy[] (this batch, 0-based) and
 * fp->action[]/fp->item_path[] (the widget's whole-session flat tables,
 * offset by `base`). Returns how many items this level produced. */
static int build_one_level(FolderPriv *fp, const char *dirpath, int base, MenuItem *out_items, int *out_lazy,
                            int max_items)
{
    int n = 0;
    if (n < max_items) {
        MenuItem *mi = &out_items[n];
        memset(mi, 0, sizeof(*mi));
        mi->enabled = 1;
        snprintf(mi->label, sizeof(mi->label), "Abrir esta pasta");
        out_lazy[n] = 0;
        fp->action[base + n] = ACT_OPEN_FOLDER;
        snprintf(fp->item_path[base + n], sizeof(fp->item_path[0]), "%s", dirpath);
        n++;
    }
    if (n < max_items) {
        MenuItem *mi = &out_items[n];
        memset(mi, 0, sizeof(*mi));
        mi->enabled = 1;
        snprintf(mi->label, sizeof(mi->label), "Abrir terminal aqui");
        out_lazy[n] = 0;
        fp->action[base + n] = ACT_OPEN_TERMINAL;
        snprintf(fp->item_path[base + n], sizeof(fp->item_path[0]), "%s", dirpath);
        n++;
    }
    if (n >= max_items) {
        return n;
    }

    DIR *d = opendir(dirpath);
    if (!d) {
        return n;
    }
    struct folder_entry entries[FOLDER_MAX_PER_DIR];
    int ne = 0;
    int overflow = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') {
            continue; /* skips ".", "..", and hidden entries alike */
        }
        if (ne >= FOLDER_MAX_PER_DIR) {
            overflow = 1;
            continue; /* keep draining readdir(), just stop collecting */
        }
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dirpath, de->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) {
            continue;
        }
        if (S_ISLNK(st.st_mode)) {
            continue; /* never follow symlinks -- simplest way to rule out a loop */
        }
        snprintf(entries[ne].name, sizeof(entries[ne].name), "%s", de->d_name);
        entries[ne].is_dir = S_ISDIR(st.st_mode);
        ne++;
    }
    closedir(d);
    qsort(entries, (size_t)ne, sizeof(entries[0]), cmp_folder_entries);

    if (ne > 0 && n < max_items) {
        MenuItem *mi = &out_items[n];
        memset(mi, 0, sizeof(*mi));
        mi->is_separator = 1;
        out_lazy[n] = 0;
        fp->action[base + n] = ACT_NONE;
        n++;
    }

    for (int i = 0; i < ne && n < max_items; i++) {
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dirpath, entries[i].name);
        MenuItem *mi = &out_items[n];
        memset(mi, 0, sizeof(*mi));
        mi->enabled = 1;
        snprintf(mi->label, sizeof(mi->label), "%s%s", entries[i].name, entries[i].is_dir ? "/" : "");
        /* Directories are always expand-on-demand (lazy) -- clicking one
         * opens its own submenu (this same build, rooted one level
         * deeper), it never fires folder_select() directly, so there's
         * no separate "too deep, just xdg-open it" fallback needed
         * anymore -- see the file comment. */
        out_lazy[n] = entries[i].is_dir ? 1 : 0;
        fp->action[base + n] = ACT_ACTIVATE_ENTRY;
        snprintf(fp->item_path[base + n], sizeof(fp->item_path[0]), "%s", full);
        n++;
    }
    if (overflow && n < max_items) {
        MenuItem *mi = &out_items[n];
        memset(mi, 0, sizeof(*mi));
        mi->enabled = 0;
        snprintf(mi->label, sizeof(mi->label), "... mais itens (%d+)", FOLDER_MAX_PER_DIR);
        out_lazy[n] = 0;
        fp->action[base + n] = ACT_NONE;
        n++;
    }
    return n;
}

/* menu.c's MenuLazyFn -- called the first time a directory entry's
 * submenu is actually opened. `parent_index` is that entry's flat index,
 * looked up in fp->item_path[] (populated when that entry was itself
 * appended, whether from the initial click or an earlier lazy expand). */
static int folder_lazy_children(void *ctx, int parent_index, MenuItem *out_items, int *out_lazy, int max_items)
{
    PanelWidget *w = ctx;
    FolderPriv *fp = w->priv;
    if (parent_index < 0 || parent_index >= fp->n_items) {
        return 0;
    }
    int room = MENU_TREE_MAX_ITEMS - fp->n_items;
    if (room < max_items) {
        max_items = room;
    }
    if (max_items <= 0) {
        return 0;
    }
    int base = fp->n_items;
    int n = build_one_level(fp, fp->item_path[parent_index], base, out_items, out_lazy, max_items);
    fp->n_items += n;
    return n;
}

static void folder_select(Panel *panel, PanelWidget *widget, void *ctx, int index)
{
    (void)panel;
    (void)ctx;
    FolderPriv *fp = widget->priv;
    if (index < 0 || index >= fp->n_items) {
        return;
    }
    switch (fp->action[index]) {
    case ACT_OPEN_FOLDER:
        run_open_path(fp->item_path[index]);
        break;
    case ACT_OPEN_TERMINAL:
        run_terminal_at(fp->item_path[index]);
        break;
    case ACT_ACTIVATE_ENTRY:
        /* Only ever a file at this point -- directories always have a
         * submenu (see build_one_level()) so clicking one opens it
         * instead of reaching this callback at all. xdg-open runs the
         * file's default app. */
        run_open_path(fp->item_path[index]);
        break;
    default:
        break;
    }
}

/* Shared by the click handler and the (optional) hotkey= binding -- both
 * open the same menu, anchored the same way (the widget's own [0, w->len)
 * span), just triggered differently. */
static void folder_open_menu(PanelWidget *w)
{
    FolderPriv *fp = w->priv;
    if (!fp->path[0]) {
        return;
    }
    fp->n_items = 0; /* fresh session -- see the file comment on why this isn't cached */

    MenuItem items[MENU_TREE_MAX_ITEMS];
    int depth[MENU_TREE_MAX_ITEMS];
    int lazy[MENU_TREE_MAX_ITEMS];
    int n = build_one_level(fp, fp->path, 0, items, lazy, MENU_TREE_MAX_ITEMS);
    fp->n_items = n;
    if (n <= 0) {
        return;
    }
    memset(depth, 0, sizeof(int) * (size_t)n);
    panel_menu_open_tree_lazy(w->panel, w, 0, w->len, items, depth, lazy, n, w, folder_select, folder_lazy_children,
                               NULL, NULL);
}

static int folder_on_button(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y)
{
    (void)local_x;
    (void)local_y;
    (void)root_x;
    (void)root_y;
    FolderPriv *fp = w->priv;
    if (button != Button1 || !fp->path[0]) {
        return 0;
    }
    folder_open_menu(w);
    return 1;
}

const PanelWidgetOps folder_ops = {
    .type_name = "folder",
    .priv_size = sizeof(FolderPriv),
    .init = folder_init,
    .destroy = folder_destroy,
    .measure = folder_measure,
    .paint = folder_paint,
    .on_button = folder_on_button,
    .get_tooltip = folder_get_tooltip,
};
