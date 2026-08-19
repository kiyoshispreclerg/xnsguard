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

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define WINCTL_MAX_BUTTONS 3

enum winctl_fallback {
    FALLBACK_NONE = 0,
    FALLBACK_CLOCK,
    FALLBACK_USERNAME,
    FALLBACK_OS,
    FALLBACK_OS_VERSION,
    FALLBACK_TEXT,
};

typedef struct {
    char buttons[WINCTL_MAX_BUTTONS]; /* 'i'=minimize, 'a'=maximize, 'x'=close */
    int n_buttons;
    int show_always; /* 0 = only while the active window is maximized, 1 = always */
    int side_start;  /* 1 = buttons before the icon/title, 0 = after (default) */
    int same_desktop_only; /* 1 = only show controls while the active window is on this panel's desktop */
    int same_output_only;  /* 1 = only show controls while the active window is on this panel's output */
    int fixed_width;     /* width= in raw pixels; 0 if unset or width= was a percentage instead */
    int fixed_width_pct; /* width= as "NN%"; 0 if unset or width= was raw pixels instead. Re-resolved
                           * against the panel's current main-axis length on every measure() call (not
                           * cached in pixels), so it tracks RandR/output geometry changes automatically. */

    /* What to show instead of icon+title+buttons when there's no
     * applicable active window -- only relevant when width=/width=NN% is
     * set (fixed_width/fixed_width_pct > 0), since otherwise the widget
     * just collapses to zero width as before. FALLBACK_CLOCK's text is
     * computed fresh every paint(); the rest are resolved once at init()
     * into fallback_static since they can't change at runtime. */
    enum winctl_fallback fallback;
    char fallback_format[32]; /* strftime format, FALLBACK_CLOCK only */
    char fallback_static[128];

    Window active_win;
    int active_applies; /* active_win != None, isn't a desktop/dock/skip-taskbar window, and passes
                          * same_desktop_only/same_output_only */
    char title[128];
    int minimized, maximized;
    cairo_surface_t *icon;
    /* 1 once a .desktop-entry icon fallback lookup has been attempted for
     * active_win -- reset alongside `icon` whenever active_win changes
     * (see winctl_on_tick()). Without this, a window whose icon never
     * resolves (no matching .desktop file) would get its directory scan
     * repeated every ~2s/property-event for as long as it stays active,
     * same concern tasklist.c's own icon_lookup_tried avoids. */
    int icon_lookup_tried;

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

/* Strips one matching pair of surrounding double quotes, if present --
 * /etc/os-release values are usually (not always) quoted. */
static void strip_quotes(const char *in, char *out, size_t outsz)
{
    size_t len = strlen(in);
    if (len >= 2 && in[0] == '"' && in[len - 1] == '"') {
        in++;
        len -= 2;
    }
    if (len >= outsz) {
        len = outsz - 1;
    }
    memcpy(out, in, len);
    out[len] = 0;
}

/* FALLBACK_OS uses NAME= (e.g. "Ubuntu"); FALLBACK_OS_VERSION uses
 * PRETTY_NAME= instead (e.g. "Ubuntu 22.04.3 LTS"), which already
 * includes the version -- no need to separately read VERSION= and
 * concatenate it. "Linux" if the file is missing or has neither key. */
static void read_os_release(int with_version, char *out, size_t outsz)
{
    snprintf(out, outsz, "Linux");
    FILE *f = fopen("/etc/os-release", "r");
    if (!f) {
        return;
    }
    char line[256];
    char name[128] = "";
    char pretty[128] = "";
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = 0;
        }
        if (!strncmp(line, "NAME=", 5)) {
            strip_quotes(line + 5, name, sizeof(name));
        } else if (!strncmp(line, "PRETTY_NAME=", 12)) {
            strip_quotes(line + 12, pretty, sizeof(pretty));
        }
    }
    fclose(f);
    const char *src = with_version ? (pretty[0] ? pretty : name) : (name[0] ? name : pretty);
    if (src[0]) {
        snprintf(out, outsz, "%s", src);
    }
}

/* Fills `out` with whatever winctl should show in place of icon+title
 * when there's no applicable active window. FALLBACK_CLOCK is the only
 * mode computed here rather than cached in fallback_static at init(),
 * since it has to change every call. */
static void winctl_fallback_text(WinctlPriv *wp, char *out, size_t outsz)
{
    if (wp->fallback == FALLBACK_CLOCK) {
        time_t t = time(NULL);
        struct tm tmv;
        localtime_r(&t, &tmv);
        if (strftime(out, outsz, wp->fallback_format, &tmv) == 0) {
            out[0] = 0;
        }
        return;
    }
    snprintf(out, outsz, "%s", wp->fallback_static);
}

static int winctl_init(PanelWidget *w)
{
    WinctlPriv *wp = w->priv;
    parse_buttons(w->config_kv, wp->buttons, &wp->n_buttons);

    char buf[16];
    wp->show_always = kv_get(w->config_kv, "show", buf, sizeof(buf)) && strcmp(buf, "always") == 0;
    wp->side_start = kv_get(w->config_kv, "side", buf, sizeof(buf)) && strcmp(buf, "start") == 0;
    wp->same_desktop_only = kv_get(w->config_kv, "same_desktop", buf, sizeof(buf)) && strcmp(buf, "yes") == 0;
    wp->same_output_only = kv_get(w->config_kv, "same_output", buf, sizeof(buf)) && strcmp(buf, "yes") == 0;

    char width_buf[16];
    if (kv_get(w->config_kv, "width", width_buf, sizeof(width_buf)) && width_buf[0]) {
        size_t wlen = strlen(width_buf);
        if (width_buf[wlen - 1] == '%') {
            width_buf[wlen - 1] = 0;
            int pct = atoi(width_buf);
            wp->fixed_width_pct = pct < 1 ? 1 : (pct > 100 ? 100 : pct);
        } else {
            wp->fixed_width = atoi(width_buf);
        }
    }

    char fallback_buf[16];
    if (kv_get(w->config_kv, "fallback", fallback_buf, sizeof(fallback_buf))) {
        if (!strcmp(fallback_buf, "clock")) {
            wp->fallback = FALLBACK_CLOCK;
        } else if (!strcmp(fallback_buf, "username")) {
            wp->fallback = FALLBACK_USERNAME;
        } else if (!strcmp(fallback_buf, "os")) {
            wp->fallback = FALLBACK_OS;
        } else if (!strcmp(fallback_buf, "os_version")) {
            wp->fallback = FALLBACK_OS_VERSION;
        } else if (!strcmp(fallback_buf, "text")) {
            wp->fallback = FALLBACK_TEXT;
        } else {
            fprintf(stderr, "xispanel: winctl: unknown fallback '%s', ignoring\n", fallback_buf);
        }
    }
    if (!kv_get(w->config_kv, "fallback_format", wp->fallback_format, sizeof(wp->fallback_format)) ||
        !wp->fallback_format[0]) {
        snprintf(wp->fallback_format, sizeof(wp->fallback_format), "%%H:%%M");
    }
    switch (wp->fallback) {
    case FALLBACK_USERNAME: {
        const char *u = getenv("USER");
        if (!u || !u[0]) {
            struct passwd *pw = getpwuid(getuid());
            u = pw ? pw->pw_name : "?";
        }
        snprintf(wp->fallback_static, sizeof(wp->fallback_static), "%s", u);
        break;
    }
    case FALLBACK_OS:
        read_os_release(0, wp->fallback_static, sizeof(wp->fallback_static));
        break;
    case FALLBACK_OS_VERSION:
        read_os_release(1, wp->fallback_static, sizeof(wp->fallback_static));
        break;
    case FALLBACK_TEXT:
        kv_get(w->config_kv, "fallback_text", wp->fallback_static, sizeof(wp->fallback_static));
        break;
    default:
        break;
    }

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

static int winctl_on_tick(PanelWidget *w, uint64_t now)
{
    WinctlPriv *wp = w->priv;
    /* Slow fallback only: active-window / title / max-min-state changes now
     * arrive as PropertyNotify events that re-poll this widget immediately
     * (see ewmh_watch_init() and the PropertyNotify handler in xispanel.c),
     * so this periodic tick just backstops anything the event path might
     * miss rather than being the primary refresh. */
    w->next_tick_ms = now + 2000;

    /* Snapshot everything winctl_paint() draws, so this tick only asks
     * for a repaint when one of them actually changed (the active window
     * usually isn't changing 3x/sec while the user works in it). */
    int o_applies = wp->active_applies, o_min = wp->minimized, o_max = wp->maximized;
    char o_title[sizeof(wp->title)];
    snprintf(o_title, sizeof(o_title), "%s", wp->title);
    cairo_surface_t *o_icon = wp->icon;

    Window active = ewmh_get_active_window();
    if (active != wp->active_win) {
        if (wp->icon) {
            cairo_surface_destroy(wp->icon);
            wp->icon = NULL;
        }
        wp->icon_lookup_tried = 0;
        wp->active_win = active;
    }

    /* _NET_ACTIVE_WINDOW can briefly point at a desktop/dock/skip-taskbar
     * window (e.g. clicking the desktop itself, or another panel) --
     * tasklist already excludes these from its own list, winctl should
     * likewise never show controls for one. */
    int applies = active != None && !ewmh_skip_taskbar(active);
    if (applies && wp->same_desktop_only) {
        int current_desktop = ewmh_get_current_desktop();
        int win_desktop = ewmh_get_desktop(active);
        if (current_desktop >= 0 && win_desktop >= 0 && win_desktop != current_desktop) {
            applies = 0;
        }
    }
    if (applies && wp->same_output_only &&
        !ewmh_window_in_rect(active, w->panel->out_x, w->panel->out_y, w->panel->out_w, w->panel->out_h)) {
        applies = 0;
    }
    wp->active_applies = applies;

    if (applies) {
        ewmh_get_title(active, wp->title, sizeof(wp->title));
        ewmh_get_state_flags(active, &wp->minimized, &wp->maximized);
        int icon_px = w->thickness > 8 ? w->thickness - 8 : 16;
        if (!wp->icon) {
            wp->icon = ewmh_get_icon_surface(active, icon_px);
        }
        if (!wp->icon && !wp->icon_lookup_tried) {
            /* _NET_WM_ICON didn't supply one -- fall back to the same
             * .desktop-entry lookup tasklist.c uses (see its on_tick doc
             * comment for the apps this covers). */
            wp->icon_lookup_tried = 1;
            char wm_class[64], icon_name[256] = "";
            ewmh_get_class(active, wm_class, sizeof(wm_class));
            if (wm_class[0] &&
                desktop_entry_find_by_wm_class(wm_class, NULL, 0, NULL, 0, icon_name, sizeof(icon_name)) &&
                icon_name[0]) {
                wp->icon = resolve_icon_theme_name(icon_name, icon_px);
            }
        }
    } else {
        wp->title[0] = 0;
        wp->minimized = 0;
        wp->maximized = 0;
    }

    return o_applies != wp->active_applies || o_min != wp->minimized || o_max != wp->maximized ||
           o_icon != wp->icon || strcmp(o_title, wp->title) != 0;
}

static void winctl_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    WinctlPriv *wp = w->priv;
    Panel *p = w->panel;

    int fixed = wp->fixed_width;
    if (wp->fixed_width_pct > 0) {
        /* Resolved fresh every measure() (not cached) against the panel's
         * current main-axis length, so a RandR/output geometry change
         * that resizes the panel keeps the percentage accurate instead of
         * freezing it at whatever it resolved to at startup. */
        int main_axis_len = (p->edge == EDGE_TOP || p->edge == EDGE_BOTTOM) ? p->w : p->h;
        fixed = (main_axis_len * wp->fixed_width_pct) / 100;
    }

    if (!wp->active_applies) {
        /* No active window to show -- keep reserving the configured
         * width (winctl_paint() renders `fallback` into it instead of
         * icon+title+buttons) rather than collapsing to zero, so nothing
         * else in the panel shifts just because focus moved to a window
         * this instance doesn't apply to. Auto width (fixed == 0) still
         * collapses, same as before -- there's no natural width to
         * reserve without an active window's title to measure. */
        *out_len = fixed > 0 ? fixed : 0;
        *out_min_len = *out_len;
        return;
    }

    if (fixed > 0) {
        /* Always exactly this wide regardless of title length or
         * whether the buttons are currently shown -- winctl_paint()
         * ellipsizes the title into whatever room that leaves instead. */
        *out_len = fixed;
        *out_min_len = fixed;
        return;
    }

    int icon_px = cross_axis > 8 ? cross_axis - 8 : 16;
    int len = 8 + icon_px + 8;
    if (wp->title[0]) {
        double tw;
        pango_text_extents_ellipsized(p->cr, wp->title, panel_text_size(p), 0, &tw, NULL);
        if (tw > 220) {
            tw = 220;
        }
        len += (int)tw + 8;
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
    int show_buttons = wp->active_applies && (wp->show_always || wp->maximized);
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
    if (!wp->active_applies) {
        wp->n_visible_buttons = 0;
        if (w->len <= 0 || wp->fallback == FALLBACK_NONE) {
            return;
        }
        char text[160];
        winctl_fallback_text(wp, text, sizeof(text));
        if (!text[0]) {
            return;
        }
        int ox, oy, owidth, oheight;
        widget_get_rect(w, &ox, &oy, &owidth, &oheight);
        (void)oheight;
        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.95);
        double tw;
        pango_text_extents_ellipsized(cr, text, panel_text_size(p), owidth - 16, &tw, NULL);
        pango_show_text_boxed(cr, ox + (owidth - tw) / 2.0, oy, w->thickness, owidth - 16, panel_text_size(p), text,
                               NULL);
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
        draw_fallback_icon(cr, tx, icon_y, icon_px, wp->title, p->fg_r, p->fg_g, p->fg_b, panel_text_size(p));
    }
    tx += icon_px + 8;

    /* When width= is tight enough that icon+buttons alone eat the whole
     * fixed width, there's no room left for any title text at all --
     * pango_show_text_boxed() with max_width_px <= 0 just skips
     * ellipsizing rather than shrinking to nothing, so still skip
     * drawing entirely rather than overflow into the buttons. */
    if (wp->title[0] && content_end - tx - 8 > 0) {
        cairo_set_source_rgba(cr, p->fg_r, p->fg_g, p->fg_b, 0.95);
        pango_show_text_boxed(cr, tx, oy, w->thickness, content_end - tx - 8, panel_text_size(p), wp->title, NULL);
    }

    int hover_local_x;
    int has_hover = panel_widget_hover_local_x(w, &hover_local_x);

    cairo_set_line_width(cr, 1.4);
    for (int i = 0; i < wp->n_visible_buttons; i++) {
        if (has_hover && hover_local_x >= wp->btn_x[i] && hover_local_x < wp->btn_x[i] + wp->btn_w[i]) {
            widget_paint_hover_rect(w, cr, wp->btn_x[i], wp->btn_w[i]);
        }
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

static int winctl_get_tooltip(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w,
                               int *out_closable, void **out_ctx)
{
    (void)local_x;
    (void)out_closable;
    (void)out_ctx;
    WinctlPriv *wp = w->priv;
    if (!wp->active_applies || !wp->title[0]) {
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
    if (!wp->active_applies || button != Button1) {
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
