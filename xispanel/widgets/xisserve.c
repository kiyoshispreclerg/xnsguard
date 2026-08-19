/*
 * xisserve widget - a single button that launches the separate `xisserve`
 * process (../../xisserve/xisserve.c), a GTK2 krunner/kickoff-style
 * application launcher kept out-of-process because a real search popup
 * with icon-grid results is GTK-shaped UI work that doesn't fit
 * xispanel's "no toolkit, plain Cairo" philosophy -- see
 * xisserve/README.md's "Why a separate process" section.
 *
 * On click, spawns `cmd` (default "xisserve", resolved via $PATH) with
 * this button's on-screen anchor rectangle, the owning panel's edge and
 * output geometry, and this panel's own theme (bg/fg color, font family
 * and size) as command-line flags -- see xisserve/PROTOCOL.md for the
 * exact contract. xisserve is expected to be a singleton (flock, same
 * pattern xisback/xisguard already use) that treats a second invocation
 * as "reposition/retheme and toggle visibility" rather than opening a
 * second window, so this widget never tracks any PID/socket state
 * itself -- it just runs the same command unconditionally on every
 * click, exactly like clicking a taskbar icon for an app that might
 * already be running.
 *
 * `hotkey=<spec>` (optional) binds a global keyboard shortcut that runs
 * the exact same launch action as clicking the icon -- see "Global
 * hotkeys" in PROTOCOL.md. Note this always needs a real trailing key
 * (e.g. `Meta+Space`), not a bare modifier: XGrabKey has no concept of
 * "this modifier alone, released without any other key having been
 * pressed" (that needs seeing every keyboard event in between, which a
 * plain passive grab doesn't give you) -- a naive grab on just the
 * modifier's own keycode fires on *every* press of it, including as the
 * first half of any other Meta+something combo already bound elsewhere
 * (e.g. folder's own hotkey=Meta+D would also trigger this). If a real
 * "tap Meta alone" launcher key is wanted, do it upstream with a tool
 * like `xcape` (remaps a tap into a synthetic keysym via XRecord) and
 * point `hotkey=` at that synthetic key instead.
 */
#include "../xispanel.h"

#include <X11/Xlib.h>

#include <stdio.h>
#include <string.h>

typedef struct {
    char cmd[192];    /* xisserve binary path/name */
    char name[64];    /* tooltip text + fallback icon letter */
    char hotkey[32];  /* optional global hotkey spec, see hotkey_register() */
    cairo_surface_t *icon;
} XisservePriv;

static void xisserve_launch(PanelWidget *w);

static int xisserve_init(PanelWidget *w)
{
    XisservePriv *xp = w->priv;
    if (!kv_get(w->config_kv, "cmd", xp->cmd, sizeof(xp->cmd)) || !xp->cmd[0]) {
        snprintf(xp->cmd, sizeof(xp->cmd), "xisserve");
    }
    if (!kv_get(w->config_kv, "name", xp->name, sizeof(xp->name)) || !xp->name[0]) {
        snprintf(xp->name, sizeof(xp->name), "Applications");
    }

    char icon_path[PATH_MAX];
    if (kv_get(w->config_kv, "icon", icon_path, sizeof(icon_path)) && icon_path[0]) {
        /* w->thickness isn't resolved yet this early -- see the same fix
         * in folder_init(). */
        int thickness = w->thickness > 0 ? w->thickness : w->panel->thickness_cfg;
        int icon_px = thickness > 6 ? thickness - 6 : 16;
        xp->icon = load_icon_argb(icon_path, icon_px);
        if (!xp->icon) {
            fprintf(stderr, "xispanel: xisserve: could not load icon '%s', falling back to a placeholder\n",
                    icon_path);
        }
    }

    if (kv_get(w->config_kv, "hotkey", xp->hotkey, sizeof(xp->hotkey)) && xp->hotkey[0]) {
        hotkey_register(w, xp->hotkey, xisserve_launch);
    }
    return 0;
}

static void xisserve_destroy(PanelWidget *w)
{
    XisservePriv *xp = w->priv;
    if (xp->icon) {
        cairo_surface_destroy(xp->icon);
    }
    hotkey_unregister_widget(w);
}

static void xisserve_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    (void)w;
    *out_len = cross_axis;
    *out_min_len = cross_axis;
}

static void xisserve_paint(PanelWidget *w, cairo_t *cr)
{
    XisservePriv *xp = w->priv;
    Panel *p = w->panel;
    int ox, oy, owidth, oheight;
    widget_get_rect(w, &ox, &oy, &owidth, &oheight);
    (void)owidth;
    (void)oheight;
    widget_paint_hover_bg(w, cr);

    int icon_px = w->thickness > 6 ? w->thickness - 6 : 16;
    int icon_x = ox + (w->thickness - icon_px) / 2;
    int icon_y = oy + (w->thickness - icon_px) / 2;
    if (xp->icon) {
        draw_icon_scaled(cr, xp->icon, icon_x, icon_y, icon_px);
    } else {
        draw_fallback_icon(cr, icon_x, icon_y, icon_px, xp->name, p->fg_r, p->fg_g, p->fg_b, panel_text_size(p));
    }
}

static int xisserve_get_tooltip(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w,
                                 int *out_closable, void **out_ctx)
{
    (void)local_x;
    (void)out_closable;
    (void)out_ctx;
    XisservePriv *xp = w->priv;
    snprintf(buf, bufsz, "%s", xp->name);
    *anchor_x = 0;
    *anchor_w = w->len;
    return 1;
}

/* This button's own on-screen rectangle in root coordinates -- same
 * "panel position + widget's main-axis offset" arithmetic menu.c's
 * panel_menu_open_tree_lazy() uses to glue a popup to the panel's outer
 * edge aligned with the triggering item, reused here so xisserve can
 * apply the identical convention without duplicating panel geometry
 * lookups of its own. */
static void anchor_rect(PanelWidget *w, int *ax, int *ay, int *aw, int *ah)
{
    Panel *p = w->panel;
    if (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM) {
        *ax = p->x + w->x;
        *ay = p->y;
        *aw = w->len;
        *ah = p->thickness;
    } else {
        *ax = p->x;
        *ay = p->y + w->x;
        *aw = p->thickness;
        *ah = w->len;
    }
}

static const char *edge_name(enum edge e)
{
    switch (e) {
    case EDGE_TOP:
        return "top";
    case EDGE_BOTTOM:
        return "bottom";
    case EDGE_LEFT:
        return "left";
    default:
        return "right";
    }
}

static void format_hex_color(double r, double g, double b, double a, char *out, size_t outsz)
{
    unsigned ri = (unsigned)(r * 255.0 + 0.5);
    unsigned gi = (unsigned)(g * 255.0 + 0.5);
    unsigned bi = (unsigned)(b * 255.0 + 0.5);
    unsigned ai = (unsigned)(a * 255.0 + 0.5);
    snprintf(out, outsz, "#%02x%02x%02x%02x", ri, gi, bi, ai);
}

/* Wraps `in` in single quotes for safe use inside an `sh -c` command
 * string -- same helper folder.c's shell_quote() implements, duplicated
 * here rather than promoted to xispanel.h since it's still only two call
 * sites total across the whole widget set. */
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

static void xisserve_launch(PanelWidget *w)
{
    XisservePriv *xp = w->priv;
    Panel *p = w->panel;

    int ax, ay, aw, ah;
    anchor_rect(w, &ax, &ay, &aw, &ah);

    char bg_hex[10], fg_hex[10];
    format_hex_color(p->bg_r, p->bg_g, p->bg_b, p->bg_a, bg_hex, sizeof(bg_hex));
    format_hex_color(p->fg_r, p->fg_g, p->fg_b, p->fg_a, fg_hex, sizeof(fg_hex));

    double font_size = p->font_size_px > 0 ? p->font_size_px : p->thickness * 0.4;

    char cmd_q[sizeof(xp->cmd) + 8];
    shell_quote(xp->cmd, cmd_q, sizeof(cmd_q));
    char font_q[sizeof(g_font_family) + 8];
    shell_quote(g_font_family[0] ? g_font_family : "sans-serif", font_q, sizeof(font_q));

    char cmd[768];
    snprintf(cmd, sizeof(cmd),
             "%s --anchor-x=%d --anchor-y=%d --anchor-w=%d --anchor-h=%d --edge=%s "
             "--output-x=%d --output-y=%d --output-w=%d --output-h=%d "
             "--bg=%s --fg=%s --font=%s --font-size=%d",
             cmd_q, ax, ay, aw, ah, edge_name(p->edge), p->out_x, p->out_y, p->out_w, p->out_h, bg_hex, fg_hex,
             font_q, (int)(font_size + 0.5));
    run_detached(cmd);
}

static int xisserve_on_button(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y)
{
    (void)local_x;
    (void)local_y;
    (void)root_x;
    (void)root_y;
    if (button != Button1) {
        return 0;
    }
    xisserve_launch(w);
    return 1;
}

const PanelWidgetOps xisserve_ops = {
    .type_name = "xisserve",
    .priv_size = sizeof(XisservePriv),
    .init = xisserve_init,
    .destroy = xisserve_destroy,
    .measure = xisserve_measure,
    .paint = xisserve_paint,
    .on_button = xisserve_on_button,
    .get_tooltip = xisserve_get_tooltip,
};
