/*
 * pulse.c - volume control backend for the `volume` widget, shelled out
 * to the `pactl` command-line tool instead of linking libpulse (or
 * libpipewire) directly. Same "shell out, don't reimplement" philosophy
 * xisback/xisconf already use for their own actions, and it sidesteps a
 * much heavier dependency than dlopen'ing libdbus-1 the way mpris.c/
 * sni.c do -- PulseAudio's/PipeWire-pulse's own client library isn't
 * designed around simple one-shot synchronous calls the way D-Bus is
 * (it's a persistent async connection + callback mainloop), so wrapping
 * it properly would mean pulling a chunk of that mainloop into xispanel's
 * own select() loop for comparatively little benefit over just running
 * `pactl` (bundled with pulseaudio-utils, and provided by pipewire-pulse
 * too, so it's present on both actual PulseAudio and PipeWire-with-
 * pulse-compat systems).
 *
 * `pactl` presence is checked once (pulse_available()) via a cheap
 * `pactl --version` run through popen() -- if it's missing, every
 * function below just reports "no audio" instead of erroring, same
 * fail-soft shape as mpris.c/sni.c's dlopen() failure path, just via a
 * missing binary instead of a missing shared library. No build-time
 * dependency at all (no headers, nothing to link) -- this file compiles
 * unconditionally.
 *
 * Every `pactl` invocation forces `LC_ALL=C` so its output is
 * locale-independent to parse (a pt_BR locale prints "Mute: não"
 * instead of "Mute: no", for example) -- verified against a real pt_BR
 * session.
 */
#include "xispanel.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checked = 0;
static int g_available = 0;

int pulse_available(void)
{
    if (g_checked) {
        return g_available;
    }
    g_checked = 1;
    FILE *f = popen("pactl --version 2>/dev/null", "r");
    if (!f) {
        g_available = 0;
        return 0;
    }
    char buf[64];
    g_available = fgets(buf, sizeof(buf), f) != NULL;
    pclose(f);
    return g_available;
}

/* Runs `pactl <args>` and returns its stdout, or NULL on failure. Caller
 * pclose()s the returned stream. */
static FILE *pactl_run(const char *args)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "LC_ALL=C pactl %s 2>/dev/null", args);
    return popen(cmd, "r");
}

/* Fire-and-forget variant for set-* commands, whose output nothing reads. */
static void pactl_run_fire(const char *args)
{
    FILE *f = pactl_run(args);
    if (f) {
        pclose(f);
    }
}

/* Parses the first "NN%" out of a `pactl get-{sink,source}-volume`
 * reply's first line (e.g. "Volume: front-left: 19661 /  30% / ..."),
 * ignoring everything else -- multi-channel volumes can differ slightly
 * per channel, but a single representative percentage is all a panel
 * icon needs. */
static int parse_volume_pct(FILE *f)
{
    char line[256];
    if (!fgets(line, sizeof(line), f)) {
        return -1;
    }
    char *pct = strchr(line, '%');
    if (!pct) {
        return -1;
    }
    char *p = pct;
    while (p > line && (isdigit((unsigned char)p[-1]) || p[-1] == ' ')) {
        p--;
    }
    return atoi(p);
}

static int parse_mute(FILE *f)
{
    char line[64];
    if (!fgets(line, sizeof(line), f)) {
        return 0;
    }
    return strstr(line, "yes") != NULL;
}

int pulse_get_sink_state(const char *sink, int *out_pct, int *out_muted)
{
    if (!pulse_available()) {
        return 0;
    }
    char args[128];
    snprintf(args, sizeof(args), "get-sink-volume %s", sink);
    FILE *f = pactl_run(args);
    if (!f) {
        return 0;
    }
    int pct = parse_volume_pct(f);
    pclose(f);
    if (pct < 0) {
        return 0;
    }

    snprintf(args, sizeof(args), "get-sink-mute %s", sink);
    f = pactl_run(args);
    int muted = 0;
    if (f) {
        muted = parse_mute(f);
        pclose(f);
    }

    *out_pct = pct;
    *out_muted = muted;
    return 1;
}

int pulse_get_source_state(const char *source, int *out_pct, int *out_muted)
{
    if (!pulse_available()) {
        return 0;
    }
    char args[128];
    snprintf(args, sizeof(args), "get-source-volume %s", source);
    FILE *f = pactl_run(args);
    if (!f) {
        return 0;
    }
    int pct = parse_volume_pct(f);
    pclose(f);
    if (pct < 0) {
        return 0;
    }

    snprintf(args, sizeof(args), "get-source-mute %s", source);
    f = pactl_run(args);
    int muted = 0;
    if (f) {
        muted = parse_mute(f);
        pclose(f);
    }

    *out_pct = pct;
    *out_muted = muted;
    return 1;
}

void pulse_set_sink_volume_relative(const char *sink, int delta_pct)
{
    if (!pulse_available()) {
        return;
    }
    char args[128];
    snprintf(args, sizeof(args), "set-sink-volume %s %+d%%", sink, delta_pct);
    pactl_run_fire(args);
}

void pulse_toggle_sink_mute(const char *sink)
{
    if (!pulse_available()) {
        return;
    }
    char args[128];
    snprintf(args, sizeof(args), "set-sink-mute %s toggle", sink);
    pactl_run_fire(args);
}
