/*
 * volume widget - single icon reflecting the default PulseAudio/PipeWire
 * sink's volume/mute state (see pulse.c for the pactl-shelling backend).
 * Scroll up/down adjusts the default sink's volume directly on the icon
 * (no need to open a mixer just to nudge the level); left-click toggles
 * mute; right-click runs a configurable external mixer (cmd_edit=,
 * default `pavucontrol`) for finer control -- same "shell out to a real
 * program instead of reimplementing one" idea as launcher's cmd=.
 *
 * The hover tooltip is intentionally simple for now: read-only text
 * showing the default output's and input's level/mute state. Per-device
 * interactive scrollbars (one output, plus every other sink/source) is a
 * real gap against the original ask -- tooltip.c has no concept of
 * multiple independently-scrollable sub-widgets yet, and building that
 * felt like its own separate feature rather than something to bolt on
 * here. Worth a follow-up if per-device control turns out to matter in
 * practice; `cmd_edit`'s external mixer covers that need in the meantime.
 */
#include "../xispanel.h"

#include <X11/Xlib.h>

#include <stdio.h>
#include <string.h>

typedef struct {
    int step; /* percent adjusted per scroll notch, default 5 */
    char cmd_edit[256];

    int have_sink;
    int sink_pct;
    int sink_muted;
    int have_source;
    int source_pct;
    int source_muted;
} VolumePriv;

static int volume_init(PanelWidget *w)
{
    VolumePriv *vp = w->priv;
    vp->step = kv_get_int(w->config_kv, "step", 5);
    if (vp->step < 1) {
        vp->step = 1;
    }
    if (!kv_get(w->config_kv, "cmd_edit", vp->cmd_edit, sizeof(vp->cmd_edit))) {
        snprintf(vp->cmd_edit, sizeof(vp->cmd_edit), "pavucontrol");
    }
    w->next_tick_ms = now_ms();
    return 0;
}

static int volume_on_tick(PanelWidget *w, uint64_t now)
{
    VolumePriv *vp = w->priv;
    w->next_tick_ms = now + 1000;
    int o_have_sink = vp->have_sink, o_sink_pct = vp->sink_pct, o_sink_muted = vp->sink_muted;
    int o_have_source = vp->have_source, o_source_pct = vp->source_pct, o_source_muted = vp->source_muted;
    vp->have_sink = pulse_get_sink_state("@DEFAULT_SINK@", &vp->sink_pct, &vp->sink_muted);
    vp->have_source = pulse_get_source_state("@DEFAULT_SOURCE@", &vp->source_pct, &vp->source_muted);
    return o_have_sink != vp->have_sink || o_sink_pct != vp->sink_pct || o_sink_muted != vp->sink_muted ||
           o_have_source != vp->have_source || o_source_pct != vp->source_pct || o_source_muted != vp->source_muted;
}

static void volume_measure(PanelWidget *w, int cross_axis, int *out_len, int *out_min_len)
{
    (void)w;
    *out_len = cross_axis;
    *out_min_len = cross_axis;
}

/* Speaker body + 0-3 sound-wave arcs depending on level, or a muted
 * slash -- same drawing weight/style as winctl's minimize/maximize/close
 * glyphs (plain cairo strokes, no icon theme dependency). */
static void draw_speaker(cairo_t *cr, double cx, double cy, double size, int pct, int muted, double fg_r,
                          double fg_g, double fg_b)
{
    cairo_save(cr);
    cairo_set_source_rgba(cr, fg_r, fg_g, fg_b, 0.9);
    cairo_set_line_width(cr, 1.4);

    double bw = size * 0.35;
    double bh = size * 0.4;
    double bx = cx - size * 0.45;
    double by = cy - bh / 2;

    cairo_move_to(cr, bx, by + bh * 0.25);
    cairo_line_to(cr, bx + bw * 0.5, by + bh * 0.25);
    cairo_line_to(cr, bx + bw * 1.1, by - bh * 0.15);
    cairo_line_to(cr, bx + bw * 1.1, by + bh * 1.15);
    cairo_line_to(cr, bx + bw * 0.5, by + bh * 0.75);
    cairo_line_to(cr, bx, by + bh * 0.75);
    cairo_close_path(cr);
    cairo_fill(cr);

    if (muted) {
        double sx = cx + size * 0.05;
        cairo_move_to(cr, sx, cy - size * 0.3);
        cairo_line_to(cr, cx + size * 0.45, cy + size * 0.3);
        cairo_stroke(cr);
        cairo_move_to(cr, cx + size * 0.45, cy - size * 0.3);
        cairo_line_to(cr, sx, cy + size * 0.3);
        cairo_stroke(cr);
    } else {
        int waves = pct <= 0 ? 0 : (pct < 34 ? 1 : (pct < 67 ? 2 : 3));
        double arc_x = bx + bw * 1.1;
        for (int i = 0; i < waves; i++) {
            double r = size * (0.18 + 0.13 * i);
            cairo_arc(cr, arc_x, cy, r, -0.6, 0.6);
            cairo_stroke(cr);
        }
    }
    cairo_restore(cr);
}

static void volume_paint(PanelWidget *w, cairo_t *cr)
{
    VolumePriv *vp = w->priv;
    Panel *p = w->panel;
    int ox, oy, owidth, oheight;
    widget_get_rect(w, &ox, &oy, &owidth, &oheight);
    (void)owidth;
    (void)oheight;
    widget_paint_hover_bg(w, cr);

    double cx = ox + w->thickness / 2.0;
    double cy = oy + w->thickness / 2.0;
    int pct = vp->have_sink ? vp->sink_pct : 0;
    int muted = !vp->have_sink || vp->sink_muted;
    draw_speaker(cr, cx, cy, w->thickness * 0.8, pct, muted, p->fg_r, p->fg_g, p->fg_b);
}

static int volume_get_tooltip(PanelWidget *w, int local_x, char *buf, size_t bufsz, int *anchor_x, int *anchor_w,
                               int *out_closable, void **out_ctx)
{
    (void)local_x;
    (void)out_closable;
    (void)out_ctx;
    VolumePriv *vp = w->priv;
    if (!vp->have_sink && !vp->have_source) {
        snprintf(buf, bufsz, "pactl não disponível");
    } else {
        char sink_line[64] = "Saída: indisponível";
        char source_line[64] = "Entrada: indisponível";
        if (vp->have_sink) {
            snprintf(sink_line, sizeof(sink_line), "Saída: %d%%%s", vp->sink_pct, vp->sink_muted ? " (mudo)" : "");
        }
        if (vp->have_source) {
            snprintf(source_line, sizeof(source_line), "Entrada: %d%%%s", vp->source_pct,
                      vp->source_muted ? " (mudo)" : "");
        }
        snprintf(buf, bufsz, "%s\n%s", sink_line, source_line);
    }
    *anchor_x = 0;
    *anchor_w = w->len;
    return 1;
}

static int volume_on_button(PanelWidget *w, int button, int local_x, int local_y, int root_x, int root_y)
{
    (void)local_x;
    (void)local_y;
    (void)root_x;
    (void)root_y;
    VolumePriv *vp = w->priv;
    switch (button) {
    case Button1:
        pulse_toggle_sink_mute("@DEFAULT_SINK@");
        break;
    case Button3:
        run_detached(vp->cmd_edit);
        break;
    case Button4:
        pulse_set_sink_volume_relative("@DEFAULT_SINK@", vp->step);
        break;
    case Button5:
        pulse_set_sink_volume_relative("@DEFAULT_SINK@", -vp->step);
        break;
    default:
        return 0;
    }
    /* Reflect the change immediately rather than waiting up to 1s for
     * the next tick -- scroll feedback in particular feels laggy
     * otherwise. */
    vp->have_sink = pulse_get_sink_state("@DEFAULT_SINK@", &vp->sink_pct, &vp->sink_muted);
    w->panel->dirty = 1;
    return 1;
}

const PanelWidgetOps volume_ops = {
    .type_name = "volume",
    .priv_size = sizeof(VolumePriv),
    .init = volume_init,
    .measure = volume_measure,
    .paint = volume_paint,
    .on_button = volume_on_button,
    .on_tick = volume_on_tick,
    .get_tooltip = volume_get_tooltip,
};
