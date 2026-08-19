/*
 * launcher widget - a single generic clickable icon: the user supplies an
 * image (icon=<path>, any format Imlib2 can decode), a name (used for the
 * hover tooltip, and as the fallback single-letter icon if icon= is
 * missing/fails to load), and a shell command run detached on click
 * (cmd=<command>, via run_detached() -- same "shell out, don't reimplement
 * a launcher" philosophy xisconf/xisback already use for their own click
 * actions). This is deliberately not a full application launcher (no
 * .desktop parsing, no icon-theme resolution, no search) -- multiple
 * `launcher` widgets on one panel is how the user pins individual
 * shortcuts today; `.desktop`-based pinning is future launcher-phase
 * territory (see tasklist's "pin" TODO).
 *
 * `cmd=` covers left-click; `cmd_middle=`/`cmd_right=`/`cmd_scroll_up=`/
 * `cmd_scroll_down=` are all optional extra actions on the same icon for
 * the other buttons and the scroll wheel (X11 reports wheel motion as
 * ButtonPress with button 4/5, so it falls through the exact same
 * dispatch as a click -- no separate scroll handling needed). This turns
 * a single `launcher` into a small multi-action control -- e.g. a volume
 * icon where scroll adjusts it and a click opens a mixer -- without
 * needing a dedicated widget type for that shape of interaction. Any
 * action left unset is simply a no-op for that button/direction. */
#include "../xispanel.h"

#include <X11/Xlib.h>

#include <stdio.h>
#include <string.h>

typedef struct {
    char name[64];
    char cmd[256];         /* left click */
    char cmd_middle[256];  /* middle click */
    char cmd_right[256];   /* right click */
    char cmd_scroll_up[256];
    char cmd_scroll_down[256];
    cairo_surface_t *icon; /* NULL if icon= wasn't set or failed to load */
} LauncherPriv;

static int launcher_init(PanelWidget *w)
{
    LauncherPriv *lp = w->priv;
    kv_get(w->config_kv, "name", lp->name, sizeof(lp->name));
    kv_get(w->config_kv, "cmd", lp->cmd, sizeof(lp->cmd));
    kv_get(w->config_kv, "cmd_middle", lp->cmd_middle, sizeof(lp->cmd_middle));
    kv_get(w->config_kv, "cmd_right", lp->cmd_right, sizeof(lp->cmd_right));
    kv_get(w->config_kv, "cmd_scroll_up", lp->cmd_scroll_up, sizeof(lp->cmd_scroll_up));
    kv_get(w->config_kv, "cmd_scroll_down", lp->cmd_scroll_down, sizeof(lp->cmd_scroll_down));

    char icon_path[PATH_MAX];
    if (kv_get(w->config_kv, "icon", icon_path, sizeof(icon_path)) && icon_path[0]) {
        lp->icon = load_png_argb(icon_path);
        if (!lp->icon) {
            fprintf(stderr, "xispanel: launcher: could not load icon '%s', falling back to a placeholder\n",
                    icon_path);
        }
    }
    return 0;
}

static void launcher_destroy(PanelWidget *w)
{
    LauncherPriv *lp = w->priv;
    if (lp->icon) {
        cairo_surface_destroy(lp->icon);
    }
}

static void launcher_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    (void)w;
    *out_len = cross_axis;
    *out_min_len = cross_axis;
}

static void launcher_paint(PanelWidget *w, cairo_t *cr)
{
    LauncherPriv *lp = w->priv;
    Panel *p = w->panel;
    int ox, oy, owidth, oheight;
    widget_get_rect(w, &ox, &oy, &owidth, &oheight);
    (void)owidth;
    (void)oheight;
    widget_paint_hover_bg(w, cr);

    int icon_px = w->thickness > 6 ? w->thickness - 6 : 16;
    int icon_x = ox + (w->thickness - icon_px) / 2;
    int icon_y = oy + (w->thickness - icon_px) / 2;
    if (lp->icon) {
        draw_icon_scaled(cr, lp->icon, icon_x, icon_y, icon_px);
    } else {
        draw_fallback_icon(cr, icon_x, icon_y, icon_px, lp->name, p->fg_r, p->fg_g, p->fg_b, panel_text_size(p));
    }
}

static int launcher_get_tooltip(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w,
                                 int *out_closable, void **out_ctx)
{
    (void)local_x;
    (void)out_closable;
    (void)out_ctx;
    LauncherPriv *lp = w->priv;
    if (!lp->name[0]) {
        return 0;
    }
    snprintf(buf, bufsz, "%s", lp->name);
    *anchor_x = 0;
    *anchor_w = w->len;
    return 1;
}

static int launcher_on_button(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y)
{
    (void)local_x;
    (void)local_y;
    (void)root_x;
    (void)root_y;
    LauncherPriv *lp = w->priv;
    const char *cmd;
    switch (button) {
    case Button1:
        cmd = lp->cmd;
        break;
    case Button2:
        cmd = lp->cmd_middle;
        break;
    case Button3:
        cmd = lp->cmd_right;
        break;
    case Button4:
        cmd = lp->cmd_scroll_up;
        break;
    case Button5:
        cmd = lp->cmd_scroll_down;
        break;
    default:
        return 0;
    }
    run_detached(cmd);
    return 1;
}

const PanelWidgetOps launcher_ops = {
    .type_name = "launcher",
    .priv_size = sizeof(LauncherPriv),
    .init = launcher_init,
    .destroy = launcher_destroy,
    .measure = launcher_measure,
    .paint = launcher_paint,
    .on_button = launcher_on_button,
    .get_tooltip = launcher_get_tooltip,
};
