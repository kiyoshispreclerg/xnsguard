/*
 * tray widget - one square button per active StatusNotifierItem (see
 * sni.c for the actual DBus protocol work; this file is purely layout +
 * painting + click dispatch, same split as tasklist.c/mpris.c).
 *
 * Left-click Activate()s the item (e.g. opens the app's menu/window),
 * middle-click SecondaryActivate()s it, right-click opens its own
 * ContextMenu() -- xispanel doesn't render that menu itself, the item's
 * own process does (that's what the SNI protocol's ContextMenu(x,y) call
 * is for: the item pops up its own DBusMenu-backed menu near (x,y)).
 */
#include "../xispanel.h"

#include <X11/Xlib.h>

#include <stdio.h>
#include <string.h>

typedef struct {
    int unused; /* all real state lives in sni.c's own item cache */
} TrayPriv;

static int tray_init(PanelWidget *w)
{
    w->next_tick_ms = now_ms();
    return 0;
}

static void tray_on_tick(PanelWidget *w, uint64_t now)
{
    w->next_tick_ms = now + 1000;
}

static void tray_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    (void)w;
    int n = sni_count();
    *out_len = n * cross_axis;
    *out_min_len = *out_len;
}

static void tray_paint(PanelWidget *w, cairo_t *cr)
{
    int ox, oy, owidth, oheight;
    widget_get_rect(w, &ox, &oy, &owidth, &oheight);
    (void)owidth;
    (void)oheight;

    int n = sni_count();
    int icon_px = w->thickness > 6 ? w->thickness - 6 : 16;
    int icon_y = oy + (w->thickness - icon_px) / 2;
    for (int i = 0; i < n; i++) {
        int bx = ox + i * w->thickness;
        int by = icon_y;
        cairo_surface_t *icon = sni_icon(i);
        if (icon) {
            draw_icon_scaled(cr, icon, bx + 3, by, icon_px);
        } else {
            draw_fallback_icon(cr, bx + 3, by, icon_px, sni_title(i), w->panel->fg_r, w->panel->fg_g,
                                w->panel->fg_b);
        }
    }
}

static int tray_get_tooltip(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w,
                             int *out_closable, void **out_ctx)
{
    (void)out_closable;
    (void)out_ctx;
    if (w->thickness <= 0) {
        return 0;
    }
    int idx = local_x / w->thickness;
    if (idx < 0 || idx >= sni_count()) {
        return 0;
    }
    const char *title = sni_title(idx);
    if (!title[0]) {
        return 0;
    }
    snprintf(buf, bufsz, "%s", title);
    *anchor_x = idx * w->thickness;
    *anchor_w = w->thickness;
    return 1;
}

static int tray_on_button(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y)
{
    (void)local_y;
    if (w->thickness <= 0) {
        return 0;
    }
    int idx = local_x / w->thickness;
    if (idx < 0 || idx >= sni_count()) {
        return 0;
    }
    switch (button) {
    case Button1:
        sni_activate(idx, root_x, root_y);
        return 1;
    case Button2:
        sni_secondary_activate(idx, root_x, root_y);
        return 1;
    case Button3:
        sni_context_menu(idx, root_x, root_y);
        return 1;
    default:
        return 0;
    }
}

const PanelWidgetOps tray_ops = {
    .type_name = "tray",
    .priv_size = sizeof(TrayPriv),
    .init = tray_init,
    .paint = tray_paint,
    .measure = tray_measure,
    .on_button = tray_on_button,
    .on_tick = tray_on_tick,
    .get_tooltip = tray_get_tooltip,
};
