/*
 * mpris.c - minimal MPRIS2 (org.mpris.MediaPlayer2.Player) client, used to
 * show media transport controls (play/pause/next/previous) in tasklist's
 * tooltip when the hovered window's PID matches an active player.
 *
 * libdbus-1 is loaded via dlopen() at runtime, never linked at build time
 * (the Makefile passes dbus-1's --cflags for <dbus/dbus.h>'s types, but
 * not --libs) -- a system missing libdbus-1.so.3 just runs with MPRIS
 * support silently unavailable instead of failing to start or crashing.
 * Every dbus_* call in this file goes through a function pointer resolved
 * by dlsym(); mpris_available() gates all of them.
 *
 * Player discovery/matching polls (mpris_poll(), ~1.5s, mirroring
 * tasklist's own poll rate) rather than subscribing to DBus signals: this
 * avoids needing to fold libdbus-1's fd(s) into xispanel's select() loop
 * (dbus_glue-style watch/timeout callbacks, flagged as the fiddliest part
 * of DBus integration in the original phased plan) for a feature that
 * doesn't need sub-second freshness. All DBus calls use a short blocking
 * timeout (dbus_connection_send_with_reply_and_block) -- acceptable on
 * the local session bus, called at most a few times per poll.
 */
#include "xispanel.h"

#include <dbus/dbus.h>

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#define MPRIS_POLL_MS 1500
#define MPRIS_CALL_TIMEOUT_MS 200
#define MPRIS_MAX_PLAYERS 8
#define MPRIS_PREFIX "org.mpris.MediaPlayer2."

typedef struct {
    char busname[128];
    unsigned long pid; /* 0 = unknown */
    int playing;       /* 1 if PlaybackStatus == "Playing" */
} MprisPlayer;

static MprisPlayer g_players[MPRIS_MAX_PLAYERS];
static int g_n_players = 0;
static uint64_t g_next_poll_ms = 0;

static void *g_libdbus = NULL;
static int g_load_attempted = 0;
static DBusConnection *g_conn = NULL;

/* ---- dlopen'd libdbus-1 symbols ---------------------------------- */
static void (*p_dbus_error_init)(DBusError *);
static void (*p_dbus_error_free)(DBusError *);
static dbus_bool_t (*p_dbus_error_is_set)(const DBusError *);
static DBusConnection *(*p_dbus_bus_get)(DBusBusType, DBusError *);
static DBusMessage *(*p_dbus_message_new_method_call)(const char *, const char *, const char *, const char *);
static void (*p_dbus_message_unref)(DBusMessage *);
static DBusMessage *(*p_dbus_connection_send_with_reply_and_block)(DBusConnection *, DBusMessage *, int, DBusError *);
static dbus_bool_t (*p_dbus_connection_send)(DBusConnection *, DBusMessage *, dbus_uint32_t *);
static dbus_bool_t (*p_dbus_connection_read_write)(DBusConnection *, int);
static dbus_bool_t (*p_dbus_message_iter_init)(DBusMessage *, DBusMessageIter *);
static dbus_bool_t (*p_dbus_message_iter_next)(DBusMessageIter *);
static int (*p_dbus_message_iter_get_arg_type)(DBusMessageIter *);
static void (*p_dbus_message_iter_recurse)(DBusMessageIter *, DBusMessageIter *);
static void (*p_dbus_message_iter_get_basic)(DBusMessageIter *, void *);
static void (*p_dbus_message_iter_init_append)(DBusMessage *, DBusMessageIter *);
static dbus_bool_t (*p_dbus_message_iter_append_basic)(DBusMessageIter *, int, const void *);

#define LOAD_SYM(name)                                                                                               \
    do {                                                                                                             \
        *(void **)(&p_##name) = dlsym(g_libdbus, #name);                                                             \
        if (!p_##name) {                                                                                             \
            fprintf(stderr, "xispanel: mpris: symbol '%s' missing from libdbus-1, disabling MPRIS\n", #name);        \
            return 0;                                                                                                \
        }                                                                                                            \
    } while (0)

static int mpris_load_symbols(void)
{
    LOAD_SYM(dbus_error_init);
    LOAD_SYM(dbus_error_free);
    LOAD_SYM(dbus_error_is_set);
    LOAD_SYM(dbus_bus_get);
    LOAD_SYM(dbus_message_new_method_call);
    LOAD_SYM(dbus_message_unref);
    LOAD_SYM(dbus_connection_send_with_reply_and_block);
    LOAD_SYM(dbus_connection_send);
    LOAD_SYM(dbus_connection_read_write);
    LOAD_SYM(dbus_message_iter_init);
    LOAD_SYM(dbus_message_iter_next);
    LOAD_SYM(dbus_message_iter_get_arg_type);
    LOAD_SYM(dbus_message_iter_recurse);
    LOAD_SYM(dbus_message_iter_get_basic);
    LOAD_SYM(dbus_message_iter_init_append);
    LOAD_SYM(dbus_message_iter_append_basic);
    return 1;
}

/* Tries to dlopen libdbus-1 and connect to the session bus, once. Every
 * public function below is a no-op (returning "nothing found") if this
 * never succeeds -- callers never need to check availability themselves. */
static int mpris_ensure_connected(void)
{
    if (g_conn) {
        return 1;
    }
    if (g_load_attempted) {
        return 0;
    }
    g_load_attempted = 1;

    g_libdbus = dlopen("libdbus-1.so.3", RTLD_NOW | RTLD_GLOBAL);
    if (!g_libdbus) {
        g_libdbus = dlopen("libdbus-1.so", RTLD_NOW | RTLD_GLOBAL);
    }
    if (!g_libdbus) {
        return 0; /* not installed -- MPRIS features just stay unavailable */
    }
    if (!mpris_load_symbols()) {
        dlclose(g_libdbus);
        g_libdbus = NULL;
        return 0;
    }

    DBusError err;
    p_dbus_error_init(&err);
    g_conn = p_dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (p_dbus_error_is_set(&err)) {
        fprintf(stderr, "xispanel: mpris: could not connect to session bus (%s), disabling MPRIS\n", err.message);
        p_dbus_error_free(&err);
    }
    if (!g_conn) {
        return 0;
    }
    return 1;
}

/* Blocking call with no arguments, returning the reply message (caller
 * unrefs) or NULL on error/timeout. */
static DBusMessage *mpris_call0(const char *dest, const char *path, const char *iface, const char *method)
{
    DBusMessage *msg = p_dbus_message_new_method_call(dest, path, iface, method);
    if (!msg) {
        return NULL;
    }
    DBusError err;
    p_dbus_error_init(&err);
    DBusMessage *reply = p_dbus_connection_send_with_reply_and_block(g_conn, msg, MPRIS_CALL_TIMEOUT_MS, &err);
    p_dbus_message_unref(msg);
    if (p_dbus_error_is_set(&err)) {
        p_dbus_error_free(&err);
        return NULL;
    }
    return reply;
}

/* Blocking call taking a single string argument. */
static DBusMessage *mpris_call1s(const char *dest, const char *path, const char *iface, const char *method,
                                  const char *arg)
{
    DBusMessage *msg = p_dbus_message_new_method_call(dest, path, iface, method);
    if (!msg) {
        return NULL;
    }
    DBusMessageIter it;
    p_dbus_message_iter_init_append(msg, &it);
    p_dbus_message_iter_append_basic(&it, DBUS_TYPE_STRING, &arg);
    DBusError err;
    p_dbus_error_init(&err);
    DBusMessage *reply = p_dbus_connection_send_with_reply_and_block(g_conn, msg, MPRIS_CALL_TIMEOUT_MS, &err);
    p_dbus_message_unref(msg);
    if (p_dbus_error_is_set(&err)) {
        p_dbus_error_free(&err);
        return NULL;
    }
    return reply;
}

/* Blocking call taking two string arguments (used for
 * org.freedesktop.DBus.Properties.Get(interface, property)). */
static DBusMessage *mpris_call2s(const char *dest, const char *path, const char *iface, const char *method,
                                  const char *arg1, const char *arg2)
{
    DBusMessage *msg = p_dbus_message_new_method_call(dest, path, iface, method);
    if (!msg) {
        return NULL;
    }
    DBusMessageIter it;
    p_dbus_message_iter_init_append(msg, &it);
    p_dbus_message_iter_append_basic(&it, DBUS_TYPE_STRING, &arg1);
    p_dbus_message_iter_append_basic(&it, DBUS_TYPE_STRING, &arg2);
    DBusError err;
    p_dbus_error_init(&err);
    DBusMessage *reply = p_dbus_connection_send_with_reply_and_block(g_conn, msg, MPRIS_CALL_TIMEOUT_MS, &err);
    p_dbus_message_unref(msg);
    if (p_dbus_error_is_set(&err)) {
        p_dbus_error_free(&err);
        return NULL;
    }
    return reply;
}

/* Fire-and-forget call with no arguments and no reply we care about (the
 * MPRIS transport methods return nothing meaningful). */
static void mpris_send0(const char *dest, const char *path, const char *iface, const char *method)
{
    DBusMessage *msg = p_dbus_message_new_method_call(dest, path, iface, method);
    if (!msg) {
        return;
    }
    p_dbus_connection_send(g_conn, msg, NULL);
    p_dbus_message_unref(msg);
}

static unsigned long mpris_get_pid_for_busname(const char *busname)
{
    DBusMessage *reply =
        mpris_call1s("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                     "GetConnectionUnixProcessID", busname);
    if (!reply) {
        return 0;
    }
    DBusMessageIter it;
    unsigned long pid = 0;
    if (p_dbus_message_iter_init(reply, &it) && p_dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_UINT32) {
        dbus_uint32_t v;
        p_dbus_message_iter_get_basic(&it, &v);
        pid = v;
    }
    p_dbus_message_unref(reply);
    return pid;
}

static int mpris_get_playback_status(const char *busname, int *out_playing)
{
    DBusMessage *reply = mpris_call2s(busname, "/org/mpris/MediaPlayer2", "org.freedesktop.DBus.Properties", "Get",
                                       "org.mpris.MediaPlayer2.Player", "PlaybackStatus");
    if (!reply) {
        return 0;
    }
    DBusMessageIter it, variant;
    int ok = 0;
    if (p_dbus_message_iter_init(reply, &it) && p_dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_VARIANT) {
        p_dbus_message_iter_recurse(&it, &variant);
        if (p_dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_STRING) {
            const char *status = NULL;
            p_dbus_message_iter_get_basic(&variant, &status);
            *out_playing = status && strcmp(status, "Playing") == 0;
            ok = 1;
        }
    }
    p_dbus_message_unref(reply);
    return ok;
}

/* Refreshes g_players[] from the bus: every org.mpris.MediaPlayer2.* name,
 * its owning PID, and current PlaybackStatus. Called at most once every
 * MPRIS_POLL_MS from the main loop, same polling philosophy as
 * tasklist's own _NET_CLIENT_LIST refresh. */
void mpris_poll(uint64_t now)
{
    if (now < g_next_poll_ms) {
        return;
    }
    g_next_poll_ms = now + MPRIS_POLL_MS;

    if (!mpris_ensure_connected()) {
        g_n_players = 0;
        return;
    }
    p_dbus_connection_read_write(g_conn, 0);

    DBusMessage *reply =
        mpris_call0("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ListNames");
    if (!reply) {
        g_n_players = 0;
        return;
    }

    int n = 0;
    DBusMessageIter it, arr;
    if (p_dbus_message_iter_init(reply, &it) && p_dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_ARRAY) {
        p_dbus_message_iter_recurse(&it, &arr);
        while (p_dbus_message_iter_get_arg_type(&arr) == DBUS_TYPE_STRING && n < MPRIS_MAX_PLAYERS) {
            const char *name = NULL;
            p_dbus_message_iter_get_basic(&arr, &name);
            if (name && strncmp(name, MPRIS_PREFIX, strlen(MPRIS_PREFIX)) == 0) {
                snprintf(g_players[n].busname, sizeof(g_players[n].busname), "%s", name);
                g_players[n].pid = mpris_get_pid_for_busname(name);
                int playing = 0;
                mpris_get_playback_status(name, &playing);
                g_players[n].playing = playing;
                n++;
            }
            if (!p_dbus_message_iter_next(&arr)) {
                break;
            }
        }
    }
    p_dbus_message_unref(reply);
    g_n_players = n;
}

int mpris_find_for_pid(unsigned long pid, char *out_busname, size_t bufsz, int *out_playing)
{
    if (pid == 0) {
        return 0;
    }
    for (int i = 0; i < g_n_players; i++) {
        if (g_players[i].pid == pid) {
            snprintf(out_busname, bufsz, "%s", g_players[i].busname);
            *out_playing = g_players[i].playing;
            return 1;
        }
    }
    return 0;
}

void mpris_play_pause(const char *busname)
{
    if (!mpris_ensure_connected()) {
        return;
    }
    mpris_send0(busname, "/org/mpris/MediaPlayer2", "org.mpris.MediaPlayer2.Player", "PlayPause");
}

void mpris_next(const char *busname)
{
    if (!mpris_ensure_connected()) {
        return;
    }
    mpris_send0(busname, "/org/mpris/MediaPlayer2", "org.mpris.MediaPlayer2.Player", "Next");
}

void mpris_previous(const char *busname)
{
    if (!mpris_ensure_connected()) {
        return;
    }
    mpris_send0(busname, "/org/mpris/MediaPlayer2", "org.mpris.MediaPlayer2.Player", "Previous");
}
