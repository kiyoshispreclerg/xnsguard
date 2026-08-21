/*
 * sni.c - minimal StatusNotifierItem/StatusNotifierWatcher system tray
 * backend, same dlopen'd-libdbus-1 philosophy as mpris.c (optional at
 * runtime, never linked -- see mpris.c's header comment for why).
 *
 * Unlike mpris.c (a pure DBus *client*), a tray needs xispanel to also act
 * as a DBus *service*: other processes' tray icons call
 * RegisterStatusNotifierItem on us. Rather than pulling libdbus-1's
 * watch/timeout objects into xispanel's select() loop (the "fiddliest
 * part" flagged in the original phased plan), this polls too: every
 * sni_poll() tick we drain any pending incoming messages with
 * dbus_connection_pop_message() (non-blocking, after a zero-timeout
 * dbus_connection_read_write()) and handle whatever's there by hand --
 * no dbus_connection_register_object_path()/vtable machinery needed for
 * the tiny number of methods (RegisterStatusNotifierItem, a couple of
 * Properties.Get/GetAll queries, Introspect) other processes actually call
 * on us.
 *
 * Two watcher bus names exist in the wild for what is otherwise the exact
 * same protocol: "org.freedesktop.StatusNotifierWatcher" (the name the
 * spec actually documents) and "org.kde.StatusNotifierWatcher" (the
 * original pre-freedesktop.org name, which is what KDE's kded5/kded6
 * still registers today -- and since nearly every tray item's own client
 * library checks the KDE name either first or exclusively, it's the one
 * that matters in practice on a real KDE/Plasma session, not the
 * freedesktop.org one). Startup checks both via GetNameOwner and attaches
 * to whichever already has an owner (KDE's name wins if, implausibly,
 * both do); if *neither* does, xispanel becomes the watcher under *both*
 * names at once (DO_NOT_QUEUE on each), so it works as the sole tray
 * host regardless of which name a given item's library happens to probe.
 * Always also requests "org.freedesktop.StatusNotifierHost-<pid>", the
 * conventional way a host announces itself, though not every item
 * actually checks for one.
 *
 * Title is re-fetched every ~1.5s poll (cheap, small string). IconPixmap
 * is *not* re-fetched every poll -- a bare match rule on
 * "type='signal',interface='org.kde.StatusNotifierItem'" (still no
 * per-watch/timeout plumbing, just messages that show up in the same
 * pop_message() drain as everything else) is enough to notice when some
 * item announced a NewIcon/NewAttentionIcon/NewOverlayIcon/NewStatus/
 * NewTitle/NewToolTip change, and only then is the (potentially tens-of-
 * KB) IconPixmap property actually re-fetched, plus a much slower
 * SNI_ICON_REFRESH_MS safety net for items that don't emit those signals
 * reliably. Re-fetching that payload on every 1.5s poll regardless of
 * whether anything changed was a real, measured CPU cost.
 */
#include "xispanel.h"

#include <dbus/dbus.h>

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SNI_POLL_MS 150
/* The poll tick is now only a cheap dispatch opportunity.  All actual
 * tray state changes are driven by D-Bus signals; 50 ms bounds wakeup
 * latency without doing Properties.Get calls while the tray is idle. */
/* Safety-net fallback only -- IconPixmap is normally re-fetched right
 * after a NewIcon/NewStatus/etc. signal is observed (see
 * sni_mark_pending_signal()), not on a fixed schedule. This just catches
 * items whose client library doesn't emit those signals reliably. */
#define SNI_ICON_REFRESH_MS 60000
#define SNI_LIVENESS_SWEEP_MS 60000
/* Floor between two IconPixmap re-fetches for the *same* item even when
 * its own change signals keep firing back to back -- some real clients
 * (confirmed live: syncthingtray during active sync, qps as a live
 * process-stats tray icon) legitimately re-announce NewIcon/NewToolTip
 * every ~1s, and re-issuing a synchronous, up-to-SNI_CALL_TIMEOUT_MS-
 * blocking DBus call that often is real, measured CPU cost -- see
 * sni_poll()'s doc comment. A signal that arrives before the floor has
 * elapsed isn't dropped, just deferred to right when the floor opens (see
 * sni_request_icon_refresh()), so a genuine one-off icon change still
 * shows up within this window rather than waiting out the full
 * SNI_ICON_REFRESH_MS safety net. */
#define SNI_ICON_DEBOUNCE_MS 1000
#define SNI_CALL_TIMEOUT_MS 200
#define SNI_MAX_ITEMS 24
#define SNI_WATCHER_PATH "/StatusNotifierWatcher"
#define SNI_ITEM_IFACE "org.kde.StatusNotifierItem"

static const char *SNI_WATCHER_NAMES[] = {
    "org.kde.StatusNotifierWatcher",
    "org.freedesktop.StatusNotifierWatcher",
};
#define SNI_N_WATCHER_NAMES 2

typedef struct {
    char busname[128];
    char path[128];
    char title[128];
    cairo_surface_t *icon;
    /* When the next IconPixmap fetch is due -- normally now+SNI_ICON_
     * REFRESH_MS (the slow safety net), but sni_mark_pending_signal() can
     * pull this *earlier* (down to last_icon_fetch_ms+SNI_ICON_DEBOUNCE_MS)
     * when this specific item announces a change, so genuine changes still
     * show up promptly without needing a separate "pending" flag -- a
     * single field drives both schedules. 0 forces an immediate fetch for
     * a freshly-registered item. */
    uint64_t next_icon_poll_ms;
    uint64_t last_icon_fetch_ms; /* 0 = never fetched yet */
    int title_dirty;             /* fetch Title/IconName on the next dispatch */
} SniItem;

static SniItem g_items[SNI_MAX_ITEMS];
static int g_n_items = 0;
static uint64_t g_next_poll_ms = 0;
static uint64_t g_next_liveness_ms = 0;
static int g_initial_sync_done = 0;
static int g_is_watcher = 0;
static int g_host_registered = 0;
/* Which of SNI_WATCHER_NAMES[] to actually talk to when we're not the
 * watcher ourselves -- whichever one GetNameOwner found an owner for at
 * startup. Both interface *and* bus name are this same string (the
 * protocol reuses the bus name as its own interface name). */
static const char *g_watcher_name = NULL;
/* See xispanel.h's doc comment. 0 = unknown yet (no shrink applied) --
 * tray.c syncs this in on_tick() before any icon this poll gets fetched. */
static int g_icon_target_size = 0;

void sni_set_icon_target_size(int px)
{
    g_icon_target_size = px;
}

static void *g_libdbus = NULL;
static int g_load_attempted = 0;
static DBusConnection *g_conn = NULL;

/* ---- dlopen'd libdbus-1 symbols ---------------------------------- */
static void (*p_dbus_error_init)(DBusError *);
static void (*p_dbus_error_free)(DBusError *);
static dbus_bool_t (*p_dbus_error_is_set)(const DBusError *);
static DBusConnection *(*p_dbus_bus_get)(DBusBusType, DBusError *);
static int (*p_dbus_bus_request_name)(DBusConnection *, const char *, unsigned int, DBusError *);
static dbus_bool_t (*p_dbus_bus_name_has_owner)(DBusConnection *, const char *, DBusError *);
static void (*p_dbus_bus_add_match)(DBusConnection *, const char *, DBusError *);
static DBusMessage *(*p_dbus_message_new_method_call)(const char *, const char *, const char *, const char *);
static DBusMessage *(*p_dbus_message_new_method_return)(DBusMessage *);
static DBusMessage *(*p_dbus_message_new_error)(DBusMessage *, const char *, const char *);
static void (*p_dbus_message_unref)(DBusMessage *);
static DBusMessage *(*p_dbus_connection_send_with_reply_and_block)(DBusConnection *, DBusMessage *, int, DBusError *);
static dbus_bool_t (*p_dbus_connection_send)(DBusConnection *, DBusMessage *, dbus_uint32_t *);
static dbus_bool_t (*p_dbus_connection_read_write)(DBusConnection *, int);
static DBusMessage *(*p_dbus_connection_pop_message)(DBusConnection *);
static dbus_bool_t (*p_dbus_message_iter_init)(DBusMessage *, DBusMessageIter *);
static dbus_bool_t (*p_dbus_message_iter_next)(DBusMessageIter *);
static int (*p_dbus_message_iter_get_arg_type)(DBusMessageIter *);
static void (*p_dbus_message_iter_recurse)(DBusMessageIter *, DBusMessageIter *);
static void (*p_dbus_message_iter_get_basic)(DBusMessageIter *, void *);
static void (*p_dbus_message_iter_init_append)(DBusMessage *, DBusMessageIter *);
static dbus_bool_t (*p_dbus_message_iter_append_basic)(DBusMessageIter *, int, const void *);
static dbus_bool_t (*p_dbus_message_iter_open_container)(DBusMessageIter *, int, const char *, DBusMessageIter *);
static dbus_bool_t (*p_dbus_message_iter_close_container)(DBusMessageIter *, DBusMessageIter *);
static int (*p_dbus_message_get_type)(DBusMessage *);
static const char *(*p_dbus_message_get_interface)(DBusMessage *);
static const char *(*p_dbus_message_get_member)(DBusMessage *);
static const char *(*p_dbus_message_get_path)(DBusMessage *);
static const char *(*p_dbus_message_get_sender)(DBusMessage *);
static dbus_bool_t (*p_dbus_message_get_no_reply)(DBusMessage *);

#define LOAD_SYM(name)                                                                                               \
    do {                                                                                                             \
        *(void **)(&p_##name) = dlsym(g_libdbus, #name);                                                            \
        if (!p_##name) {                                                                                             \
            fprintf(stderr, "xispanel: sni: symbol '%s' missing from libdbus-1, disabling tray\n", #name);           \
            return 0;                                                                                                \
        }                                                                                                            \
    } while (0)

static int sni_load_symbols(void)
{
    LOAD_SYM(dbus_error_init);
    LOAD_SYM(dbus_error_free);
    LOAD_SYM(dbus_error_is_set);
    LOAD_SYM(dbus_bus_get);
    LOAD_SYM(dbus_bus_request_name);
    LOAD_SYM(dbus_bus_name_has_owner);
    LOAD_SYM(dbus_bus_add_match);
    LOAD_SYM(dbus_message_new_method_call);
    LOAD_SYM(dbus_message_new_method_return);
    LOAD_SYM(dbus_message_new_error);
    LOAD_SYM(dbus_message_unref);
    LOAD_SYM(dbus_connection_send_with_reply_and_block);
    LOAD_SYM(dbus_connection_send);
    LOAD_SYM(dbus_connection_read_write);
    LOAD_SYM(dbus_connection_pop_message);
    LOAD_SYM(dbus_message_iter_init);
    LOAD_SYM(dbus_message_iter_next);
    LOAD_SYM(dbus_message_iter_get_arg_type);
    LOAD_SYM(dbus_message_iter_recurse);
    LOAD_SYM(dbus_message_iter_get_basic);
    LOAD_SYM(dbus_message_iter_init_append);
    LOAD_SYM(dbus_message_iter_append_basic);
    LOAD_SYM(dbus_message_iter_open_container);
    LOAD_SYM(dbus_message_iter_close_container);
    LOAD_SYM(dbus_message_get_type);
    LOAD_SYM(dbus_message_get_interface);
    LOAD_SYM(dbus_message_get_member);
    LOAD_SYM(dbus_message_get_path);
    LOAD_SYM(dbus_message_get_sender);
    LOAD_SYM(dbus_message_get_no_reply);
    return 1;
}

static int sni_ensure_connected(void)
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
        return 0;
    }
    if (!sni_load_symbols()) {
        dlclose(g_libdbus);
        g_libdbus = NULL;
        return 0;
    }

    DBusError err;
    p_dbus_error_init(&err);
    g_conn = p_dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (p_dbus_error_is_set(&err)) {
        fprintf(stderr, "xispanel: sni: could not connect to session bus (%s), disabling tray\n", err.message);
        p_dbus_error_free(&err);
    }
    if (!g_conn) {
        return 0;
    }

    /* Find whichever of the two watcher names (see header comment) is
     * already owned by someone else first, before trying to claim
     * anything ourselves. */
    for (int i = 0; i < SNI_N_WATCHER_NAMES && !g_watcher_name; i++) {
        DBusError herr;
        p_dbus_error_init(&herr);
        dbus_bool_t owned = p_dbus_bus_name_has_owner(g_conn, SNI_WATCHER_NAMES[i], &herr);
        p_dbus_error_free(&herr);
        if (owned) {
            g_watcher_name = SNI_WATCHER_NAMES[i];
        }
    }

    if (g_watcher_name) {
        fprintf(stderr, "xispanel: sni: found existing tray watcher %s, attaching as a second host\n",
                g_watcher_name);
    } else {
        /* Nobody's the watcher yet -- claim *both* well-known names
         * (DBUS_NAME_FLAG_DO_NOT_QUEUE = 4: fail immediately instead of
         * queuing behind anyone who races us for it) so xispanel answers
         * to whichever one a given item's client library happens to
         * probe. */
        int got_any = 0;
        for (int i = 0; i < SNI_N_WATCHER_NAMES; i++) {
            DBusError err2;
            p_dbus_error_init(&err2);
            int ret = p_dbus_bus_request_name(g_conn, SNI_WATCHER_NAMES[i], 4, &err2);
            p_dbus_error_free(&err2);
            /* DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER == 1 */
            if (ret == 1) {
                got_any = 1;
            }
        }
        g_is_watcher = got_any;
        if (g_is_watcher) {
            fprintf(stderr,
                    "xispanel: sni: no other tray watcher found, xispanel is now the StatusNotifierWatcher\n");
        } else {
            fprintf(stderr, "xispanel: sni: no tray watcher found and could not become one, tray will stay empty\n");
        }
    }

    /* Subscribe to every item's change signals (NewIcon/NewAttentionIcon/
     * NewOverlayIcon/NewStatus/NewTitle/NewToolTip) so sni_poll() can skip
     * re-fetching IconPixmap on every tick and instead only do it when
     * something actually announced a change -- see sni_poll()'s header
     * comment. No sender filter: items' bus names aren't known in advance
     * (and a well-known name like "org.fcitx...StatusNotifierItem-..."
     * doesn't match the unique ":1.NN" name signals actually arrive from
     * anyway), so this catches signals from any item and sni_handle_incoming()
     * treats "some item changed" as "recheck all known items" -- cheap,
     * since it only fires on real changes rather than every poll. */
    DBusError merr;
    p_dbus_error_init(&merr);
    p_dbus_bus_add_match(g_conn, "type='signal',interface='" SNI_ITEM_IFACE "'", &merr);
    p_dbus_error_free(&merr);

    /* Watcher membership is event-driven too.  The initial
     * RegisteredStatusNotifierItems snapshot is fetched exactly once by
     * sni_poll(); afterwards these signals keep g_items[] synchronized. */
    for (int wi = 0; wi < SNI_N_WATCHER_NAMES; wi++) {
        DBusError werr;
        char rule[256];
        p_dbus_error_init(&werr);
        snprintf(rule, sizeof(rule), "type='signal',interface='%s'", SNI_WATCHER_NAMES[wi]);
        p_dbus_bus_add_match(g_conn, rule, &werr);
        p_dbus_error_free(&werr);
    }

    char hostname[64];
    snprintf(hostname, sizeof(hostname), "org.freedesktop.StatusNotifierHost-%d", (int)getpid());
    DBusError err3;
    p_dbus_error_init(&err3);
    int hret = p_dbus_bus_request_name(g_conn, hostname, 4, &err3);
    p_dbus_error_free(&err3);
    g_host_registered = (hret == 1 || hret == 4 /* ALREADY_OWNER */);

    return 1;
}

static DBusMessage *sni_call2s(const char *dest, const char *path, const char *iface, const char *method,
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
    DBusMessage *reply = p_dbus_connection_send_with_reply_and_block(g_conn, msg, SNI_CALL_TIMEOUT_MS, &err);
    p_dbus_message_unref(msg);
    if (p_dbus_error_is_set(&err)) {
        p_dbus_error_free(&err);
        return NULL;
    }
    return reply;
}

/* Fire-and-forget call taking two int32 args -- Activate(x,y)/ContextMenu(x,y)/
 * SecondaryActivate(x,y), whose replies (if any) nothing here cares about. */
static void sni_send2i(const char *dest, const char *path, const char *iface, const char *method, int x, int y)
{
    DBusMessage *msg = p_dbus_message_new_method_call(dest, path, iface, method);
    if (!msg) {
        return;
    }
    DBusMessageIter it;
    p_dbus_message_iter_init_append(msg, &it);
    p_dbus_message_iter_append_basic(&it, DBUS_TYPE_INT32, &x);
    p_dbus_message_iter_append_basic(&it, DBUS_TYPE_INT32, &y);
    p_dbus_connection_send(g_conn, msg, NULL);
    p_dbus_message_unref(msg);
}

/* Reads a Properties.Get reply's single top-level variant<string>, into
 * buf. Returns 1 if found. Deliberately using targeted Get (not GetAll)
 * for Title/IconName: GetAll also drags along ToolTip and IconPixmap,
 * which can be tens of KB of pixel data -- wasteful for a value we
 * re-fetch every poll (see sni_poll()'s header comment). */
static int extract_get_string(DBusMessage *reply, char *buf, size_t bufsz)
{
    DBusMessageIter it, variant;
    if (!p_dbus_message_iter_init(reply, &it) || p_dbus_message_iter_get_arg_type(&it) != DBUS_TYPE_VARIANT) {
        return 0;
    }
    p_dbus_message_iter_recurse(&it, &variant);
    if (p_dbus_message_iter_get_arg_type(&variant) != DBUS_TYPE_STRING) {
        return 0;
    }
    const char *val = NULL;
    p_dbus_message_iter_get_basic(&variant, &val);
    snprintf(buf, bufsz, "%s", val ? val : "");
    return 1;
}

/* Same shape as extract_get_string() but for a Properties.Get on an
 * object-path-typed property (e.g. StatusNotifierItem's "Menu") -- same
 * `const char *` marshalling as a string, just a different DBus type tag. */
static int extract_get_objpath(DBusMessage *reply, char *buf, size_t bufsz)
{
    DBusMessageIter it, variant;
    if (!p_dbus_message_iter_init(reply, &it) || p_dbus_message_iter_get_arg_type(&it) != DBUS_TYPE_VARIANT) {
        return 0;
    }
    p_dbus_message_iter_recurse(&it, &variant);
    if (p_dbus_message_iter_get_arg_type(&variant) != DBUS_TYPE_OBJECT_PATH) {
        return 0;
    }
    const char *val = NULL;
    p_dbus_message_iter_get_basic(&variant, &val);
    snprintf(buf, bufsz, "%s", val ? val : "");
    return 1;
}

/* Same shape as extract_get_string() but for a targeted Properties.Get on
 * IconPixmap: variant<"a(iiay)">, an array of (width,height,ARGB32-
 * network-byte-order pixel bytes) structs. Picks the largest available and
 * returns a premultiplied cairo surface, or NULL if absent/empty. */
static cairo_surface_t *extract_get_icon_pixmap(DBusMessage *reply)
{
    DBusMessageIter it, variant, icons, icon_s, byte_arr;
    if (!p_dbus_message_iter_init(reply, &it) || p_dbus_message_iter_get_arg_type(&it) != DBUS_TYPE_VARIANT) {
        return NULL;
    }
    p_dbus_message_iter_recurse(&it, &variant);
    if (p_dbus_message_iter_get_arg_type(&variant) != DBUS_TYPE_ARRAY) {
        return NULL;
    }
    p_dbus_message_iter_recurse(&variant, &icons);

    int best_w = 0, best_h = 0;
    DBusMessageIter best_bytes;
    int have_best = 0;
    while (p_dbus_message_iter_get_arg_type(&icons) == DBUS_TYPE_STRUCT) {
        p_dbus_message_iter_recurse(&icons, &icon_s);
        dbus_int32_t iw = 0, ih = 0;
        if (p_dbus_message_iter_get_arg_type(&icon_s) == DBUS_TYPE_INT32) {
            p_dbus_message_iter_get_basic(&icon_s, &iw);
        }
        p_dbus_message_iter_next(&icon_s);
        if (p_dbus_message_iter_get_arg_type(&icon_s) == DBUS_TYPE_INT32) {
            p_dbus_message_iter_get_basic(&icon_s, &ih);
        }
        p_dbus_message_iter_next(&icon_s);
        if (iw > 0 && ih > 0 && iw <= 512 && ih <= 512 && p_dbus_message_iter_get_arg_type(&icon_s) == DBUS_TYPE_ARRAY &&
            iw >= best_w) {
            p_dbus_message_iter_recurse(&icon_s, &byte_arr);
            best_w = iw;
            best_h = ih;
            best_bytes = byte_arr;
            have_best = 1;
        }
        if (!p_dbus_message_iter_next(&icons)) {
            break;
        }
    }
    if (!have_best) {
        return NULL;
    }

    cairo_surface_t *surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, best_w, best_h);
    if (cairo_surface_status(surf) != CAIRO_STATUS_SUCCESS) {
        cairo_surface_destroy(surf);
        return NULL;
    }
    unsigned char *dst = cairo_image_surface_get_data(surf);
    int stride = cairo_image_surface_get_stride(surf);
    long total_px = (long)best_w * best_h;
    for (long px = 0; px < total_px && p_dbus_message_iter_get_arg_type(&best_bytes) == DBUS_TYPE_BYTE; px++) {
        unsigned char bytes[4] = {0, 0, 0, 0};
        for (int i = 0; i < 4; i++) {
            if (p_dbus_message_iter_get_arg_type(&best_bytes) != DBUS_TYPE_BYTE) {
                break;
            }
            unsigned char b;
            p_dbus_message_iter_get_basic(&best_bytes, &b);
            bytes[i] = b;
            p_dbus_message_iter_next(&best_bytes);
        }
        /* Network byte order ARGB32: byte0=A,1=R,2=G,3=B -- straight
         * alpha, needs premultiplying for Cairo like _NET_WM_ICON does. */
        unsigned char a = bytes[0], r = bytes[1], g = bytes[2], b = bytes[3];
        r = (unsigned char)((r * a) / 255);
        g = (unsigned char)((g * a) / 255);
        b = (unsigned char)((b * a) / 255);
        int x = (int)(px % best_w);
        int y = (int)(px / best_w);
        uint32_t *row = (uint32_t *)(void *)(dst + y * stride);
        row[x] = ((uint32_t)a << 24) | ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
    }
    cairo_surface_mark_dirty(surf);
    return surf;
}

static int sni_find(const char *busname, const char *path)
{
    for (int i = 0; i < g_n_items; i++) {
        if (strcmp(g_items[i].busname, busname) == 0 && strcmp(g_items[i].path, path) == 0) {
            return i;
        }
    }
    return -1;
}

static void sni_register_item(const char *arg)
{
    char busname[128], path[128];
    const char *slash = strchr(arg, '/');
    if (slash && slash != arg) {
        size_t blen = (size_t)(slash - arg);
        if (blen >= sizeof(busname)) {
            blen = sizeof(busname) - 1;
        }
        memcpy(busname, arg, blen);
        busname[blen] = 0;
        snprintf(path, sizeof(path), "%s", slash);
    } else {
        snprintf(busname, sizeof(busname), "%s", arg);
        snprintf(path, sizeof(path), "/StatusNotifierItem");
    }
    if (sni_find(busname, path) >= 0 || g_n_items >= SNI_MAX_ITEMS) {
        return;
    }
    SniItem *it = &g_items[g_n_items++];
    memset(it, 0, sizeof(*it));
    snprintf(it->busname, sizeof(it->busname), "%s", busname);
    snprintf(it->path, sizeof(it->path), "%s", path);
    it->title_dirty = 1;
    it->next_icon_poll_ms = 0;
    fprintf(stderr, "xispanel: sni: tray item registered: %s%s\n", busname, path);
}

/* Pulls `it`'s next IconPixmap fetch earlier in response to a change
 * signal -- down to right when SNI_ICON_DEBOUNCE_MS has elapsed since its
 * last *actual* fetch, never sooner, so a burst of signals from one chatty
 * item (confirmed live: syncthingtray during active sync, qps as a live
 * process-stats tray icon, both re-signal roughly once a second) collapses
 * into one fetch per debounce window instead of one per signal. A quiet
 * item's first signal in a while still fetches essentially immediately
 * (last_icon_fetch_ms is far enough in the past that the floor is already
 * behind `now`). Only ever moves the deadline earlier, never later --
 * doesn't touch it if a fetch was already due sooner than what this signal
 * would request. */
static void sni_request_icon_refresh(SniItem *it, uint64_t now)
{
    uint64_t earliest = it->last_icon_fetch_ms ? it->last_icon_fetch_ms + SNI_ICON_DEBOUNCE_MS : 0;
    uint64_t want = now > earliest ? now : earliest;
    if (want < it->next_icon_poll_ms) {
        it->next_icon_poll_ms = want;
    }
}

/* Attributes a change signal to the specific item it applies to -- matched
 * by comparing the signal's actual sender (always a unique :1.N connection
 * name) against each tracked item's `busname`, which *is* that same
 * unique name for any item that registered with its own connection name
 * instead of a well-known one (see sni_register_item()'s doc comment --
 * increasingly the common case in practice; confirmed live against both
 * syncthingtray and qps). Falls back to requesting a refresh for every
 * item if nothing matched (a well-known-name-registered item's signal
 * sender won't equal its registered busname) -- same as this code's old
 * always-refresh-everyone behavior, just no longer the common case. */
static void sni_mark_pending_signal(const char *sender)
{
    if (!sender || !sender[0]) {
        return;
    }
    uint64_t now = now_ms();
    int matched = 0;
    for (int i = 0; i < g_n_items; i++) {
        if (strcmp(g_items[i].busname, sender) == 0) {
            sni_request_icon_refresh(&g_items[i], now);
            matched = 1;
        }
    }
    if (!matched) {
        for (int i = 0; i < g_n_items; i++) {
            sni_request_icon_refresh(&g_items[i], now);
        }
    }
}

/* Handles whatever incoming messages are waiting for us: our NewIcon/
 * NewStatus/etc. match rule (see sni_ensure_connected()) delivers signals
 * regardless of watcher role, so this always drains the queue -- not just
 * when g_is_watcher -- attributing each one to the item(s) it applies to
 * (see sni_mark_pending_signal()) for sni_poll() to pick up. Method calls
 * (RegisterStatusNotifierItem, the odd Properties.Get(All)
 * / Introspect probe) are only ever sent to us when we *are* the watcher,
 * so that handling stays gated. Every method call that expects a reply
 * gets *some* reply, even if just an error -- an unanswered one is the one
 * thing that can visibly misbehave a well-written DBus client. */
static void sni_unregister_item_arg(const char *arg)
{
    if (!arg || !arg[0]) {
        return;
    }

    char busname[128], path[128];
    const char *slash = strchr(arg, '/');
    if (slash && slash != arg) {
        size_t blen = (size_t)(slash - arg);
        if (blen >= sizeof(busname)) {
            blen = sizeof(busname) - 1;
        }
        memcpy(busname, arg, blen);
        busname[blen] = 0;
        snprintf(path, sizeof(path), "%s", slash);
    } else {
        snprintf(busname, sizeof(busname), "%s", arg);
        snprintf(path, sizeof(path), "/StatusNotifierItem");
    }

    for (int i = 0; i < g_n_items; i++) {
        if (strcmp(g_items[i].busname, busname) == 0 && strcmp(g_items[i].path, path) == 0) {
            if (g_items[i].icon) {
                cairo_surface_destroy(g_items[i].icon);
            }
            memmove(&g_items[i], &g_items[i + 1],
                    (size_t)(g_n_items - i - 1) * sizeof(g_items[0]));
            g_n_items--;
            fprintf(stderr, "xispanel: sni: tray item unregistered: %s%s\n", busname, path);
            return;
        }
    }
}

static int sni_signal_string_arg(DBusMessage *msg, char *buf, size_t bufsz)
{
    DBusMessageIter it;
    if (!p_dbus_message_iter_init(msg, &it) ||
        p_dbus_message_iter_get_arg_type(&it) != DBUS_TYPE_STRING) {
        return 0;
    }
    const char *arg = NULL;
    p_dbus_message_iter_get_basic(&it, &arg);
    snprintf(buf, bufsz, "%s", arg ? arg : "");
    return buf[0] != 0;
}

static void sni_handle_incoming(void)
{
    p_dbus_connection_read_write(g_conn, 0);
    DBusMessage *msg;
    while ((msg = p_dbus_connection_pop_message(g_conn)) != NULL) {
        int mtype = p_dbus_message_get_type(msg);
        if (mtype == DBUS_MESSAGE_TYPE_SIGNAL) {
            const char *siface = p_dbus_message_get_interface(msg);
            const char *smember = p_dbus_message_get_member(msg);

            if (siface && strcmp(siface, SNI_ITEM_IFACE) == 0) {
                /* Item signals are the normal fast path: no timer-driven
                 * property refresh is necessary.  A quiet item gets an
                 * immediate refresh; repeated signals are still collapsed
                 * by SNI_ICON_DEBOUNCE_MS. */
                sni_mark_pending_signal(p_dbus_message_get_sender(msg));
                if (smember && strcmp(smember, "NewTitle") == 0) {
                    const char *sender = p_dbus_message_get_sender(msg);
                    int title_matched = 0;
                    for (int i = 0; i < g_n_items; i++) {
                        if (sender && strcmp(g_items[i].busname, sender) == 0) {
                            g_items[i].title_dirty = 1;
                            title_matched = 1;
                        }
                    }
                    /* A client may have registered using a well-known name,
                     * while the signal sender is its unique :1.N name.  In
                     * that ambiguous case refresh all titles rather than
                     * missing a genuine NewTitle event. */
                    if (!title_matched) {
                        for (int i = 0; i < g_n_items; i++) {
                            g_items[i].title_dirty = 1;
                        }
                    }
                }
            } else if (siface &&
                       (strcmp(siface, SNI_WATCHER_NAMES[0]) == 0 ||
                        strcmp(siface, SNI_WATCHER_NAMES[1]) == 0) &&
                       smember) {
                char arg[256] = "";
                if (strcmp(smember, "StatusNotifierItemRegistered") == 0) {
                    if (sni_signal_string_arg(msg, arg, sizeof(arg))) {
                        sni_register_item(arg);
                    }
                } else if (strcmp(smember, "StatusNotifierItemUnregistered") == 0) {
                    if (sni_signal_string_arg(msg, arg, sizeof(arg))) {
                        sni_unregister_item_arg(arg);
                    }
                }
            }
            p_dbus_message_unref(msg);
            continue;
        }
        if (!g_is_watcher || mtype != DBUS_MESSAGE_TYPE_METHOD_CALL) {
            p_dbus_message_unref(msg);
            continue;
        }
        const char *iface = p_dbus_message_get_interface(msg);
        const char *member = p_dbus_message_get_member(msg);
        const char *sender = p_dbus_message_get_sender(msg);
        DBusMessage *reply = NULL;

        int iface_is_watcher = iface && (strcmp(iface, SNI_WATCHER_NAMES[0]) == 0 ||
                                          strcmp(iface, SNI_WATCHER_NAMES[1]) == 0);
        if (iface_is_watcher && member && strcmp(member, "RegisterStatusNotifierItem") == 0) {
            DBusMessageIter it;
            const char *arg = NULL;
            if (p_dbus_message_iter_init(msg, &it) && p_dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_STRING) {
                p_dbus_message_iter_get_basic(&it, &arg);
            }
            /* Per spec the argument is usually just the well-known bus
             * name (path defaults to /StatusNotifierItem); some senders
             * pass their own unique :1.N name instead, which is fine too
             * since we only ever address items via GetConnection*
             * anyway -- we just use whatever sender gave us. Fall back to
             * the message sender's own unique name if the argument is
             * empty (seen from at least one real client). */
            sni_register_item(arg && arg[0] ? arg : (sender ? sender : ""));
            reply = p_dbus_message_new_method_return(msg);
        } else if (iface && member && strcmp(iface, "org.freedesktop.DBus.Properties") == 0 &&
                   (strcmp(member, "Get") == 0 || strcmp(member, "GetAll") == 0)) {
            /* Minimal stub: reply with an empty result rather than an
             * error, since a handful of items do query the watcher's
             * IsStatusNotifierHostRegistered/ProtocolVersion before
             * registering. Real values aren't worth the complexity here
             * -- xispanel is always ready to host by the time it's
             * running. */
            reply = p_dbus_message_new_method_return(msg);
            if (strcmp(member, "Get") == 0) {
                DBusMessageIter it, variant;
                p_dbus_message_iter_init_append(reply, &it);
                p_dbus_message_iter_open_container(&it, DBUS_TYPE_VARIANT, "b", &variant);
                dbus_bool_t v = TRUE;
                p_dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &v);
                p_dbus_message_iter_close_container(&it, &variant);
            }
        } else if (iface && member && strcmp(iface, "org.freedesktop.DBus.Introspectable") == 0 &&
                   strcmp(member, "Introspect") == 0) {
            reply = p_dbus_message_new_method_return(msg);
            DBusMessageIter it;
            const char *xml = "<node/>";
            p_dbus_message_iter_init_append(reply, &it);
            p_dbus_message_iter_append_basic(&it, DBUS_TYPE_STRING, &xml);
        } else if (!p_dbus_message_get_no_reply(msg)) {
            reply = p_dbus_message_new_error(msg, "org.freedesktop.DBus.Error.UnknownMethod", "not implemented");
        }

        if (reply) {
            p_dbus_connection_send(g_conn, reply, NULL);
            p_dbus_message_unref(reply);
        }
        p_dbus_message_unref(msg);
    }
}

/* Refreshes g_items[] from whichever watcher owns g_watcher_name (be it
 * us or another process), then re-fetches each item's Title (always) and
 * IconPixmap (only on a change signal or the SNI_ICON_REFRESH_MS safety
 * net -- see below). Also drains+handles incoming requests, answering
 * them if we're the watcher. Called at most once every SNI_POLL_MS from
 * the main loop. */
/* Cheap FNV-1a signature over exactly what the tray widget draws (item
 * count, each title's bytes, each icon surface's identity -- a re-fetched
 * icon is always a freshly-allocated surface, so a pointer compare
 * catches icon changes too). Compared against the previous poll's value
 * so sni_poll() can tell the main loop whether the tray needs a repaint
 * at all, instead of the old "repaint every tick unconditionally". */
static unsigned long sni_display_sig(void)
{
    unsigned long h = 1469598103934665603UL; /* FNV offset basis */
    h = (h ^ (unsigned)g_n_items) * 1099511628211UL;
    for (int i = 0; i < g_n_items; i++) {
        for (const char *s = g_items[i].title; *s; s++) {
            h = (h ^ (unsigned char)*s) * 1099511628211UL;
        }
        h = (h ^ 0xff) * 1099511628211UL; /* title terminator, so "ab"+"c" != "a"+"bc" */
        uintptr_t ip = (uintptr_t)g_items[i].icon;
        for (unsigned k = 0; k < sizeof(ip); k++) {
            h = (h ^ (unsigned char)(ip >> (k * 8))) * 1099511628211UL;
        }
    }
    return h;
}

static unsigned long g_last_display_sig = 0;

/* 1 if the tray's drawn appearance changed since the last call. */
static int sni_take_sig_change(void)
{
    unsigned long sig = sni_display_sig();
    if (sig == g_last_display_sig) {
        return 0;
    }
    g_last_display_sig = sig;
    return 1;
}

int sni_poll(uint64_t now)
{
    /* This function remains API-compatible with the existing xispanel main
     * loop.  The important change is that it is no longer a 1.5s polling
     * loop: the 50ms tick only dispatches already-arrived D-Bus messages.
     * Properties are fetched only after a registration/change signal (plus
     * a very slow liveness safety net). */
    if (now < g_next_poll_ms) {
        return 0;
    }
    g_next_poll_ms = now + SNI_POLL_MS;

    if (!sni_ensure_connected()) {
        g_n_items = 0;
        return sni_take_sig_change();
    }

    sni_handle_incoming();

    /* If we attached to an existing watcher, enumerate its current items
     * exactly once at startup.  Subsequent membership changes arrive via
     * StatusNotifierItemRegistered/Unregistered signals. */
    if (!g_initial_sync_done && !g_is_watcher && g_watcher_name) {
        g_initial_sync_done = 1;
        DBusMessage *reply = sni_call2s(g_watcher_name, SNI_WATCHER_PATH,
                                         "org.freedesktop.DBus.Properties", "Get",
                                         g_watcher_name, "RegisteredStatusNotifierItems");
        if (reply) {
            DBusMessageIter it, variant, arr;
            if (p_dbus_message_iter_init(reply, &it) &&
                p_dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_VARIANT) {
                p_dbus_message_iter_recurse(&it, &variant);
                if (p_dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_ARRAY) {
                    p_dbus_message_iter_recurse(&variant, &arr);
                    while (p_dbus_message_iter_get_arg_type(&arr) == DBUS_TYPE_STRING &&
                           g_n_items < SNI_MAX_ITEMS) {
                        const char *item = NULL;
                        p_dbus_message_iter_get_basic(&arr, &item);
                        if (item) {
                            sni_register_item(item);
                        }
                        if (!p_dbus_message_iter_next(&arr)) {
                            break;
                        }
                    }
                }
            }
            p_dbus_message_unref(reply);
        }
    }

    /* Fetch only properties that are actually dirty.  Registration and
     * NewTitle make title_dirty true; icon/status signals pull the icon
     * deadline forward.  There is deliberately no Properties.Get on every
     * tick anymore. */
    int changed = 0;
    for (int i = 0; i < g_n_items; i++) {
        SniItem *it = &g_items[i];

        if (it->title_dirty) {
            char title[128] = "";
            DBusMessage *treply =
                sni_call2s(it->busname, it->path,
                           "org.freedesktop.DBus.Properties", "Get",
                           SNI_ITEM_IFACE, "Title");
            if (!treply) {
                continue; /* liveness is handled by the slow sweep below */
            }
            extract_get_string(treply, title, sizeof(title));
            p_dbus_message_unref(treply);

            if (!title[0]) {
                DBusMessage *nreply =
                    sni_call2s(it->busname, it->path,
                               "org.freedesktop.DBus.Properties", "Get",
                               SNI_ITEM_IFACE, "IconName");
                if (nreply) {
                    extract_get_string(nreply, title, sizeof(title));
                    p_dbus_message_unref(nreply);
                }
            }
            if (strcmp(it->title, title) != 0) {
                snprintf(it->title, sizeof(it->title), "%s", title);
                changed = 1;
            }
            it->title_dirty = 0;
        }

        if (now >= it->next_icon_poll_ms) {
            it->next_icon_poll_ms = now + SNI_ICON_REFRESH_MS;
            it->last_icon_fetch_ms = now;

            DBusMessage *ireply =
                sni_call2s(it->busname, it->path,
                           "org.freedesktop.DBus.Properties", "Get",
                           SNI_ITEM_IFACE, "IconPixmap");
            cairo_surface_t *icon = NULL;
            if (ireply) {
                icon = shrink_icon_surface(extract_get_icon_pixmap(ireply), g_icon_target_size);
                p_dbus_message_unref(ireply);
            }
            if (!icon) {
                DBusMessage *nreply =
                    sni_call2s(it->busname, it->path,
                               "org.freedesktop.DBus.Properties", "Get",
                               SNI_ITEM_IFACE, "IconName");
                if (nreply) {
                    char iconname[128] = "";
                    extract_get_string(nreply, iconname, sizeof(iconname));
                    p_dbus_message_unref(nreply);
                    icon = resolve_icon_theme_name(iconname, g_icon_target_size);
                }
            }
            if (icon) {
                if (it->icon) {
                    cairo_surface_destroy(it->icon);
                }
                it->icon = icon;
                changed = 1;
            }
        }
    }

    /* Very slow safety net for clients/watchers that fail to emit the normal
     * registration/unregistration signals.  This is intentionally rare and
     * is not part of the normal update path. */
    if (now >= g_next_liveness_ms) {
        g_next_liveness_ms = now + SNI_LIVENESS_SWEEP_MS;
        for (int i = 0; i < g_n_items; ) {
            SniItem *it = &g_items[i];
            DBusMessage *reply =
                sni_call2s(it->busname, it->path,
                           "org.freedesktop.DBus.Properties", "Get",
                           SNI_ITEM_IFACE, "Title");
            if (reply) {
                p_dbus_message_unref(reply);
                i++;
                continue;
            }
            if (it->icon) {
                cairo_surface_destroy(it->icon);
            }
            memmove(it, it + 1, (size_t)(g_n_items - i - 1) * sizeof(*it));
            g_n_items--;
            changed = 1;
        }
    }

    (void)changed; /* sni_take_sig_change() below remains the single repaint gate */
    return sni_take_sig_change();
}

int sni_count(void)
{
    return g_n_items;
}

const char *sni_title(int idx)
{
    if (idx < 0 || idx >= g_n_items) {
        return "";
    }
    return g_items[idx].title;
}

cairo_surface_t *sni_icon(int idx)
{
    if (idx < 0 || idx >= g_n_items) {
        return NULL;
    }
    return g_items[idx].icon;
}

void sni_activate(int idx, int x, int y)
{
    if (idx < 0 || idx >= g_n_items || !sni_ensure_connected()) {
        return;
    }
    sni_send2i(g_items[idx].busname, g_items[idx].path, SNI_ITEM_IFACE, "Activate", x, y);
}

void sni_secondary_activate(int idx, int x, int y)
{
    if (idx < 0 || idx >= g_n_items || !sni_ensure_connected()) {
        return;
    }
    sni_send2i(g_items[idx].busname, g_items[idx].path, SNI_ITEM_IFACE, "SecondaryActivate", x, y);
}

void sni_context_menu(int idx, int x, int y)
{
    if (idx < 0 || idx >= g_n_items || !sni_ensure_connected()) {
        return;
    }
    sni_send2i(g_items[idx].busname, g_items[idx].path, SNI_ITEM_IFACE, "ContextMenu", x, y);
}

/* ---- DBusMenu client, for tray items whose Menu property points at a
 * com.canonical.dbusmenu object -----------------------------------------
 *
 * StatusNotifierItem's ContextMenu(x,y) is only a fallback for items that
 * *don't* have a proper menu: per spec, when the "Menu" property is set to
 * a real object path, hosts are expected to fetch and render *that* menu
 * themselves rather than calling ContextMenu() (which such items often
 * don't even implement -- confirmed against fcitx5's own SNI item: its
 * ContextMenu isn't in its introspection at all, only Activate/Scroll/
 * SecondaryActivate, while its Menu property points at a real object
 * exposing the input-method switcher). The actual GetLayout/Event protocol
 * work lives in dbusmenu.c (shared with the globalmenu widget); this is
 * just the SNI-specific glue -- checking the Menu property and feeding
 * its busname/path to dbusmenu_fetch(). */
static char g_dbusmenu_busname[128];
static char g_dbusmenu_path[128];
static int g_dbusmenu_ids[DBUSMENU_MAX_ITEMS];
static int g_dbusmenu_depth[DBUSMENU_MAX_ITEMS];
static MenuItem g_dbusmenu_items[DBUSMENU_MAX_ITEMS];
static int g_dbusmenu_n = 0;

static void sni_dbusmenu_select(Panel *panel, PanelWidget *widget, void *ctx, int index)
{
    (void)panel;
    (void)widget;
    (void)ctx;
    if (index < 0 || index >= g_dbusmenu_n) {
        return;
    }
    dbusmenu_send_event(g_dbusmenu_busname, g_dbusmenu_path, g_dbusmenu_ids[index]);
}

/* Opens the hovered item's DBusMenu as a cascading popup (real nested
 * submenu frames -- see menu.c's panel_menu_open_tree()), if it has one.
 * Returns 1 if it did (and a menu was opened, even if fetching the
 * layout failed after the property check -- callers shouldn't also fall
 * back to ContextMenu() in that case, since a Menu property being set at
 * all means the item doesn't expect ContextMenu() to be called), 0 if the
 * item has no Menu property (empty or "/", the spec's "no menu"
 * convention) so the caller should fall back to ContextMenu()/Activate()
 * instead. */
int sni_menu_open(int idx, Panel *panel, PanelWidget *widget, int anchor_x, int anchor_w)
{
    if (idx < 0 || idx >= g_n_items || !sni_ensure_connected()) {
        return 0;
    }
    const char *busname = g_items[idx].busname;
    const char *path = g_items[idx].path;

    DBusMessage *mreply = sni_call2s(busname, path, "org.freedesktop.DBus.Properties", "Get", SNI_ITEM_IFACE, "Menu");
    if (!mreply) {
        return 0;
    }
    char menu_path[128] = "";
    extract_get_objpath(mreply, menu_path, sizeof(menu_path));
    p_dbus_message_unref(mreply);
    if (!menu_path[0] || !strcmp(menu_path, "/")) {
        return 0;
    }

    dbusmenu_free_item_icons(g_dbusmenu_items, g_dbusmenu_n);
    int n = dbusmenu_fetch(busname, menu_path, 0, -1, g_dbusmenu_items, g_dbusmenu_ids, g_dbusmenu_depth,
                            DBUSMENU_MAX_ITEMS);
    if (n <= 0) {
        g_dbusmenu_n = 0;
        return 1; /* has a Menu property, just couldn't fetch/parse it right now -- still don't fall back */
    }
    g_dbusmenu_n = n;
    snprintf(g_dbusmenu_busname, sizeof(g_dbusmenu_busname), "%s", busname);
    snprintf(g_dbusmenu_path, sizeof(g_dbusmenu_path), "%s", menu_path);
    panel_menu_open_tree(panel, widget, anchor_x, anchor_w, g_dbusmenu_items, g_dbusmenu_depth, g_dbusmenu_n, NULL,
                          sni_dbusmenu_select, NULL, NULL);
    return 1;
}
