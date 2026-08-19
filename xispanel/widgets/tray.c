/*
 * tray widget - one square button per active StatusNotifierItem (see
 * sni.c for the actual DBus protocol work; this file is purely layout +
 * painting + click dispatch, same split as tasklist.c/mpris.c).
 *
 * Left-click always performs the item's primary action (Activate()) --
 * same convention plasmashell follows (e.g. left-click on OpenSnitch's
 * tray icon opens its UI, not a menu). Only right-click tries
 * sni_menu_open(): if the item has a Menu (DBusMenu) property set,
 * xispanel fetches+renders that menu itself (see sni.c's DBusMenu client)
 * rather than relying on the item's own process to pop up something near
 * (x,y) -- many real items (fcitx5's input-method switcher, network
 * applets) don't implement ContextMenu() at all once they set Menu,
 * expecting hosts to do exactly this. Falls back to plain ContextMenu(x,y)
 * when there's no Menu property. Middle-click always just
 * SecondaryActivate()s the item -- DBusMenu has no equivalent for it.
 */
#include "../xispanel.h"

#include <X11/Xlib.h>

#include <stdio.h>
#include <string.h>

typedef struct {
    /* px of empty space around the whole widget's icon row, *and* between
     * adjacent icons -- deliberately the same amount both places (not
     * doubled between icons the way padding-per-icon-slot would), so the
     * gap between two icons visually matches the gap from an icon to the
     * widget's own edge. 0 (default) = icons fill the whole button
     * height with no gaps at all, touching edge to edge. See
     * icon_size_for() in ewmh.c and tray_layout() below. */
    int icon_padding;
} TrayPriv;

static int tray_init(PanelWidget *w)
{
    TrayPriv *tp = w->priv;
    tp->icon_padding = kv_get_int(w->config_kv, "icon_padding", 0);
    if (tp->icon_padding < 0) {
        tp->icon_padding = 0;
    }
    w->next_tick_ms = now_ms();
    return 0;
}

static int tray_on_tick(PanelWidget *w, uint64_t now)
{
    /* The tray's data is owned by sni.c, refreshed by sni_poll() in the
     * main loop, which already tells the loop when to repaint (see
     * sni_poll()'s return value). So this widget's own tick has nothing
     * to detect and never asks for a repaint itself -- it only keeps a
     * tick scheduled so the loop stays warm enough to call sni_poll() at
     * its own cadence even on an otherwise-idle panel. */
    w->next_tick_ms = now + 1000;
    return 0;
}

/* icon_px: side length of each (square) icon. slot: icon_px + one
 * padding's worth of trailing gap -- the leading edge gets its own
 * padding too, so total width is `pad + n*slot` (the last icon's
 * trailing "slot" padding doubles as the widget's own trailing edge
 * padding). Shared by measure/paint/hit-testing so they can never
 * disagree about where an icon is, same pattern tasklist uses. */
static void tray_layout(PanelWidget *w, int *out_icon_px, int *out_slot, int *out_pad)
{
    TrayPriv *tp = w->priv;
    *out_icon_px = icon_size_for(w->thickness, tp->icon_padding);
    *out_pad = tp->icon_padding;
    *out_slot = *out_icon_px + *out_pad;
}

static void tray_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    (void)cross_axis;
    int icon_px, slot, pad;
    tray_layout(w, &icon_px, &slot, &pad);
    int n = sni_count();
    *out_len = n > 0 ? pad + n * slot : 0;
    *out_min_len = *out_len;
}

static int tray_hit_test(int local_x, int icon_px, int slot, int pad, int n);

static void tray_paint(PanelWidget *w, cairo_t *cr)
{
    int ox, oy, owidth, oheight;
    widget_get_rect(w, &ox, &oy, &owidth, &oheight);
    (void)owidth;
    (void)oheight;

    int icon_px, slot, pad;
    tray_layout(w, &icon_px, &slot, &pad);
    int n = sni_count();
    int icon_y = oy + (w->thickness - icon_px) / 2;
    int hover_local_x;
    int hovered = panel_widget_hover_local_x(w, &hover_local_x) ? tray_hit_test(hover_local_x, icon_px, slot, pad, n)
                                                                  : -1;
    for (int i = 0; i < n; i++) {
        int bx = ox + pad + i * slot;
        if (i == hovered) {
            widget_paint_hover_rect(w, cr, bx, icon_px);
        }
        cairo_surface_t *icon = sni_icon(i);
        if (icon) {
            draw_icon_scaled(cr, icon, bx, icon_y, icon_px);
        } else {
            draw_fallback_icon(cr, bx, icon_y, icon_px, sni_title(i), w->panel->fg_r, w->panel->fg_g, w->panel->fg_b,
                                panel_text_size(w->panel));
        }
    }
}

/* -1 if local_x isn't over any icon at all -- either before the leading
 * padding, past the last icon, or sitting in the gap between two icons
 * (local_x - pad within a slot but past that slot's icon_px). Plain
 * integer division of (local_x - pad) would mis-hit slot 0 for a
 * negative local_x - pad (truncates toward zero), so the leading-edge
 * case needs its own check rather than falling out of the division. */
static int tray_hit_test(int local_x, int icon_px, int slot, int pad, int n)
{
    if (slot <= 0 || local_x < pad) {
        return -1;
    }
    int idx = (local_x - pad) / slot;
    if (idx < 0 || idx >= n) {
        return -1;
    }
    int within_slot = (local_x - pad) - idx * slot;
    if (within_slot >= icon_px) {
        return -1; /* in the gap after this icon, before the next one */
    }
    return idx;
}

static int tray_get_tooltip(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w,
                             int *out_closable, void **out_ctx)
{
    (void)out_closable;
    (void)out_ctx;
    int icon_px, slot, pad;
    tray_layout(w, &icon_px, &slot, &pad);
    int idx = tray_hit_test(local_x, icon_px, slot, pad, sni_count());
    if (idx < 0) {
        return 0;
    }
    const char *title = sni_title(idx);
    if (!title[0]) {
        return 0;
    }
    snprintf(buf, bufsz, "%s", title);
    *anchor_x = pad + idx * slot;
    *anchor_w = icon_px;
    return 1;
}

static int tray_on_button(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y)
{
    (void)local_y;
    int icon_px, slot, pad;
    tray_layout(w, &icon_px, &slot, &pad);
    int idx = tray_hit_test(local_x, icon_px, slot, pad, sni_count());
    if (idx < 0) {
        return 0;
    }
    int anchor_x = pad + idx * slot;
    switch (button) {
    case Button1:
        sni_activate(idx, root_x, root_y);
        return 1;
    case Button2:
        sni_secondary_activate(idx, root_x, root_y);
        return 1;
    case Button3:
        if (!sni_menu_open(idx, w->panel, w, anchor_x, icon_px)) {
            sni_context_menu(idx, root_x, root_y);
        }
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
