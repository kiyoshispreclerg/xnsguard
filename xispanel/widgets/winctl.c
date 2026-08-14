/*
 * winctl widget - shows the active window's icon + title, plus a
 * configurable set of window-control buttons (minimize/maximize/close),
 * similar in spirit to KDE's "Active Window Control" plasmoid.
 *
 * Everything about which buttons appear, in what order, on which side of
 * the icon/title, and whether they're only shown while the active window
 * is maximized (vs. always) is a config key on the WIDGET line -- same
 * "hand-edit the .conf and RELOAD" mechanism every other widget's options
 * already go through, see PROTOCOL.md.
 */
#include "../xispanel.h"

#include <X11/Xlib.h>

#include <stdio.h>
#include <string.h>

#define WINCTL_MAX_BUTTONS 3

typedef struct {
    char buttons[WINCTL_MAX_BUTTONS]; /* 'i'=minimize, 'a'=maximize, 'x'=close */
    int n_buttons;
    int show_always; /* 0 = only while the active window is maximized, 1 = always */
    int side_start;  /* 1 = buttons before the icon/title, 0 = after (default) */

    Window active_win;
    char title[128];
    int minimized, maximized;
    cairo_surface_t *icon;

    /* Recomputed by winctl_layout() from the widget's actual allotted
     * w->len every paint/on_button call, same pattern as tasklist's
     * vis_x/vis_w -- keeps drawing and hit-testing from ever disagreeing. */
    int n_visible_buttons;
    int btn_x[WINCTL_MAX_BUTTONS];
    int btn_w[WINCTL_MAX_BUTTONS];
} WinctlPriv;

static void parse_buttons(const char *kvline, char *out, int *out_n)
{
    char buf[32];
    if (!kv_get(kvline, "buttons", buf, sizeof(buf))) {
        snprintf(buf, sizeof(buf), "min,max,close");
    }
    int n = 0;
    char *save = NULL;
    char *tok = strtok_r(buf, ",", &save);
    while (tok && n < WINCTL_MAX_BUTTONS) {
        if (!strcmp(tok, "min")) {
            out[n++] = 'i';
        } else if (!strcmp(tok, "max")) {
            out[n++] = 'a';
        } else if (!strcmp(tok, "close")) {
            out[n++] = 'x';
        } else {
            fprintf(stderr, "xispanel: winctl: unknown button '%s', ignoring\n", tok);
        }
        tok = strtok_r(NULL, ",", &save);
    }
    *out_n = n;
}

static int winctl_init(PanelWidget *w)
{
    WinctlPriv *wp = w->priv;
    parse_buttons(w->config_kv, wp->buttons, &wp->n_buttons);

    char buf[16];
    wp->show_always = kv_get(w->config_kv, "show", buf, sizeof(buf)) && strcmp(buf, "always") == 0;
    wp->side_start = kv_get(w->config_kv, "side", buf, sizeof(buf)) && strcmp(buf, "start") == 0;

    wp->active_win = None;
    w->next_tick_ms = now_ms();
    return 0;
}

static void winctl_destroy(PanelWidget *w)
{
    WinctlPriv *wp = w->priv;
    if (wp->icon) {
        cairo_surface_destroy(wp->icon);
    }
}

static void winctl_on_tick(PanelWidget *w, uint64_t now)
{
    WinctlPriv *wp = w->priv;
    w->next_tick_ms = now + 300;

    Window active = ewmh_get_active_window();
    if (active != wp->active_win) {
        if (wp->icon) {
            cairo_surface_destroy(wp->icon);
            wp->icon = NULL;
        }
        wp->active_win = active;
    }

    if (active != None) {
        ewmh_get_title(active, wp->title, sizeof(wp->title));
        ewmh_get_state_flags(active, &wp->minimized, &wp->maximized);
        if (!wp->icon) {
            int icon_px = w->thickness > 8 ? w->thickness - 8 : 16;
            wp->icon = ewmh_get_icon_surface(active, icon_px);
        }
    } else {
        wp->title[0] = 0;
        wp->minimized = 0;
        wp->maximized = 0;
    }
}

static void winctl_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    WinctlPriv *wp = w->priv;
    Panel *p = w->panel;

    if (wp->active_win == None) {
        *out_len = 0;
        *out_min_len = 0;
        return;
    }

    int icon_px = cross_axis > 8 ? cross_axis - 8 : 16;
    int len = 8 + icon_px + 8;
    if (wp->title[0]) {
        cairo_text_extents_t ext;
        cairo_text_extents(p->cr, wp->title, &ext);
        int tw = (int)ext.x_advance;
        if (tw > 220) {
            tw = 220;
        }
        len += tw + 8;
    }
    int show_buttons = wp->show_always || wp->maximized;
    if (show_buttons) {
        len += wp->n_buttons * cross_axis;
    }
    *out_len = len;
    *out_min_len = len; /* short/fixed enough content that shrinking isn't worth supporting yet */
}

/* Recomputes button hit-rects (and how many are actually shown) from the
 * widget's real allotted w->len -- see the WinctlPriv comment. */
static void winctl_layout(PanelWidget *w)
{
    WinctlPriv *wp = w->priv;
    int show_buttons = wp->active_win != None && (wp->show_always || wp->maximized);
    wp->n_visible_buttons = show_buttons ? wp->n_buttons : 0;

    int btn_w = w->thickness;
    int ox = wp->side_start ? 0 : w->len - wp->n_visible_buttons * btn_w;
    for (int i = 0; i < wp->n_visible_buttons; i++) {
        wp->btn_x[i] = ox + i * btn_w;
        wp->btn_w[i] = btn_w;
    }
}

static void winctl_paint(PanelWidget *w, cairo_t *cr)
{
    WinctlPriv *wp = w->priv;
    Panel *p = w->panel;
    if (wp->active_win == None) {
        wp->n_visible_buttons = 0;
        return;
    }

    int ox, oy, owidth, oheight;
    widget_get_rect(w, &ox, &oy, &owidth, &oheight);
    (void)oheight;

    winctl_layout(w);

    int icon_px = w->thickness > 8 ? w->thickness - 8 : 16;
    int icon_y = oy + (w->thickness - icon_px) / 2;
    int btn_w = w->thickness;
    int buttons_span = wp->n_visible_buttons * btn_w;

    int content_x = ox + (wp->side_start ? buttons_span : 0);
    int content_end = ox + owidth - (wp->side_start ? 0 : buttons_span);

    int tx = content_x + 8;
    if (wp->icon) {
        draw_icon_scaled(cr, wp->icon, tx, icon_y, icon_px);
    } else {
        draw_fallback_icon(cr, tx, icon_y, icon_px, wp->title, p->fg_r, p->fg_g, p->fg_b);
    }
    tx += icon_px + 8;

    if (wp->title[0]) {
        char label[160];
        snprintf(label, sizeof(label), "%s", wp->title);
        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.95);
        trim_to_width(cr, label, sizeof(label), content_end - tx - 8);
        cairo_text_extents_t ext;
        cairo_text_extents(cr, label, &ext);
        cairo_move_to(cr, tx, oy + (w->thickness - ext.height) / 2.0 - ext.y_bearing);
        cairo_show_text(cr, label);
    }

    cairo_set_line_width(cr, 1.4);
    for (int i = 0; i < wp->n_visible_buttons; i++) {
        double cx = ox + wp->btn_x[i] + wp->btn_w[i] / 2.0;
        double cy = oy + w->thickness / 2.0;
        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.85);
        switch (wp->buttons[i]) {
        case 'i':
            cairo_move_to(cr, cx - 5, cy + 5);
            cairo_line_to(cr, cx + 5, cy + 5);
            cairo_stroke(cr);
            break;
        case 'a':
            if (wp->maximized) {
                cairo_rectangle(cr, cx - 5, cy - 3, 8, 8);
                cairo_stroke(cr);
                cairo_rectangle(cr, cx - 3, cy - 5, 8, 8);
                cairo_stroke(cr);
            } else {
                cairo_rectangle(cr, cx - 5, cy - 5, 10, 10);
                cairo_stroke(cr);
            }
            break;
        case 'x':
            cairo_move_to(cr, cx - 5, cy - 5);
            cairo_line_to(cr, cx + 5, cy + 5);
            cairo_stroke(cr);
            cairo_move_to(cr, cx - 5, cy + 5);
            cairo_line_to(cr, cx + 5, cy - 5);
            cairo_stroke(cr);
            break;
        default:
            break;
        }
    }
}

static int winctl_get_tooltip(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w)
{
    (void)local_x;
    WinctlPriv *wp = w->priv;
    if (wp->active_win == None || !wp->title[0]) {
        return 0;
    }
    snprintf(buf, bufsz, "%s", wp->title); /* wp->title is never truncated, unlike the trimmed on-panel label */
    *anchor_x = 0;
    *anchor_w = w->len;
    return 1;
}

static int winctl_on_button(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y)
{
    (void)local_y;
    (void)root_x;
    (void)root_y;
    WinctlPriv *wp = w->priv;
    if (wp->active_win == None || button != Button1) {
        return 0;
    }
    winctl_layout(w);

    for (int i = 0; i < wp->n_visible_buttons; i++) {
        if (local_x >= wp->btn_x[i] && local_x < wp->btn_x[i] + wp->btn_w[i]) {
            switch (wp->buttons[i]) {
            case 'i':
                ewmh_toggle_minimize(wp->active_win, wp->minimized);
                break;
            case 'a':
                ewmh_toggle_maximize(wp->active_win);
                break;
            case 'x':
                ewmh_close(wp->active_win);
                break;
            default:
                break;
            }
            XFlush(g_dpy);
            w->panel->dirty = 1;
            return 1;
        }
    }
    return 0;
}

const PanelWidgetOps winctl_ops = {
    .type_name = "winctl",
    .priv_size = sizeof(WinctlPriv),
    .init = winctl_init,
    .destroy = winctl_destroy,
    .measure = winctl_measure,
    .paint = winctl_paint,
    .on_button = winctl_on_button,
    .on_tick = winctl_on_tick,
    .get_tooltip = winctl_get_tooltip,
};
