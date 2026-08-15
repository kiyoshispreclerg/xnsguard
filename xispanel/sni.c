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
 * Icon fetching polls each registered item's IconPixmap property (~1.5s,
 * same tradeoff as mpris.c) instead of subscribing to NewIcon/NewStatus
 * signals -- acceptable staleness for a tray icon, much less plumbing.
 */
#include "xispanel.h"

#include <dbus/dbus.h>

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SNI_POLL_MS 1500
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
} SniItem;

static SniItem g_items[SNI_MAX_ITEMS];
static int g_n_items = 0;
static uint64_t g_next_poll_ms = 0;
static int g_is_watcher = 0;
static int g_host_registered = 0;
/* Which of SNI_WATCHER_NAMES[] to actually talk to when we're not the
 * watcher ourselves -- whichever one GetNameOwner found an owner for at
 * startup. Both interface *and* bus name are this same string (the
 * protocol reuses the bus name as its own interface name). */
static const char *g_watcher_name = NULL;

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

    char hostname[64];
    snprintf(hostname, sizeof(hostname), "org.freedesktop.StatusNotifierHost-%d", (int)getpid());
    DBusError err3;
    p_dbus_error_init(&err3);
    int hret = p_dbus_bus_request_name(g_conn, hostname, 4, &err3);
    p_dbus_error_free(&err3);
    g_host_registered = (hret == 1 || hret == 4 /* ALREADY_OWNER */);

    return 1;
}

static DBusMessage *sni_call1s(const char *dest, const char *path, const char *iface, const char *method,
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
    DBusMessage *reply = p_dbus_connection_send_with_reply_and_block(g_conn, msg, SNI_CALL_TIMEOUT_MS, &err);
    p_dbus_message_unref(msg);
    if (p_dbus_error_is_set(&err)) {
        p_dbus_error_free(&err);
        return NULL;
    }
    return reply;
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

/* Reads one string or variant<string> property value out of a GetAll
 * reply's "a{sv}" dict for `want_key`, into buf. Returns 1 if found. */
static int extract_string_prop(DBusMessage *reply, const char *want_key, char *buf, size_t bufsz)
{
    DBusMessageIter it, arr, entry, variant;
    if (!p_dbus_message_iter_init(reply, &it) || p_dbus_message_iter_get_arg_type(&it) != DBUS_TYPE_ARRAY) {
        return 0;
    }
    p_dbus_message_iter_recurse(&it, &arr);
    while (p_dbus_message_iter_get_arg_type(&arr) == DBUS_TYPE_DICT_ENTRY) {
        p_dbus_message_iter_recurse(&arr, &entry);
        const char *key = NULL;
        if (p_dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
            p_dbus_message_iter_get_basic(&entry, &key);
        }
        p_dbus_message_iter_next(&entry);
        if (key && strcmp(key, want_key) == 0 && p_dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_VARIANT) {
            p_dbus_message_iter_recurse(&entry, &variant);
            if (p_dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_STRING) {
                const char *val = NULL;
                p_dbus_message_iter_get_basic(&variant, &val);
                snprintf(buf, bufsz, "%s", val ? val : "");
                return 1;
            }
        }
        if (!p_dbus_message_iter_next(&arr)) {
            break;
        }
    }
    return 0;
}

/* Same shape as extract_string_prop() but for IconPixmap's "a(iiay)" value:
 * an array of (width,height,ARGB32-network-byte-order pixel bytes) structs.
 * Picks the largest available and returns a premultiplied cairo surface,
 * or NULL if the property is absent/empty. */
static cairo_surface_t *extract_icon_pixmap(DBusMessage *reply)
{
    DBusMessageIter it, arr, entry, variant, icons, icon_s, byte_arr;
    if (!p_dbus_message_iter_init(reply, &it) || p_dbus_message_iter_get_arg_type(&it) != DBUS_TYPE_ARRAY) {
        return NULL;
    }
    p_dbus_message_iter_recurse(&it, &arr);
    int found_variant = 0;
    while (p_dbus_message_iter_get_arg_type(&arr) == DBUS_TYPE_DICT_ENTRY) {
        p_dbus_message_iter_recurse(&arr, &entry);
        const char *key = NULL;
        if (p_dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
            p_dbus_message_iter_get_basic(&entry, &key);
        }
        p_dbus_message_iter_next(&entry);
        if (key && strcmp(key, "IconPixmap") == 0 && p_dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_VARIANT) {
            p_dbus_message_iter_recurse(&entry, &variant);
            found_variant = 1;
            break;
        }
        if (!p_dbus_message_iter_next(&arr)) {
            break;
        }
    }
    if (!found_variant || p_dbus_message_iter_get_arg_type(&variant) != DBUS_TYPE_ARRAY) {
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
    fprintf(stderr, "xispanel: sni: tray item registered: %s%s\n", busname, path);
}

/* Handles whatever incoming messages are waiting for us, if we're acting
 * as the watcher: RegisterStatusNotifierItem (the only method real tray
 * items actually call on us), plus best-effort Properties.Get(All) and
 * Introspect so a strict client doesn't just hang/log errors. Every
 * method call gets *some* reply if one was expected, even if just an
 * error -- an unanswered method call is the one thing that can visibly
 * misbehave a well-written DBus client. */
static void sni_handle_incoming(void)
{
    if (!g_is_watcher) {
        return;
    }
    p_dbus_connection_read_write(g_conn, 0);
    DBusMessage *msg;
    while ((msg = p_dbus_connection_pop_message(g_conn)) != NULL) {
        if (p_dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_METHOD_CALL) {
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
 * us or another process), then re-fetches each item's Title/IconPixmap.
 * Also drains+handles incoming requests if we're the watcher. Called at
 * most once every SNI_POLL_MS from the main loop. */
void sni_poll(uint64_t now)
{
    if (now < g_next_poll_ms) {
        return;
    }
    g_next_poll_ms = now + SNI_POLL_MS;

    if (!sni_ensure_connected()) {
        g_n_items = 0;
        return;
    }

    sni_handle_incoming();

    if (!g_is_watcher && g_watcher_name) {
        /* We're not the watcher -- read its RegisteredStatusNotifierItems
         * property instead of tracking registrations ourselves. */
        DBusMessage *reply = sni_call2s(g_watcher_name, SNI_WATCHER_PATH, "org.freedesktop.DBus.Properties", "Get",
                                         g_watcher_name, "RegisteredStatusNotifierItems");
        if (reply) {
            DBusMessageIter it, variant, arr;
            if (p_dbus_message_iter_init(reply, &it) && p_dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_VARIANT) {
                p_dbus_message_iter_recurse(&it, &variant);
                if (p_dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_ARRAY) {
                    p_dbus_message_iter_recurse(&variant, &arr);
                    /* Deliberately *not* resetting g_n_items to 0 here:
                     * sni_register_item() already dedups against the
                     * current list via sni_find(), so re-parsing the same
                     * mostly-unchanged array every poll only appends
                     * genuinely new items instead of re-logging/
                     * re-adding everything every ~1.5s. Items that drop
                     * out of the watcher's list get pruned naturally by
                     * the GetAll-failure loop below once their bus name
                     * actually stops answering. */
                    while (p_dbus_message_iter_get_arg_type(&arr) == DBUS_TYPE_STRING && g_n_items < SNI_MAX_ITEMS) {
                        const char *s = NULL;
                        p_dbus_message_iter_get_basic(&arr, &s);
                        if (s) {
                            sni_register_item(s);
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

    /* Refresh Title + icon for every currently-tracked item, dropping any
     * that stopped answering (process exited without us seeing it leave
     * the bus). */
    int n_alive = 0;
    SniItem alive[SNI_MAX_ITEMS];
    for (int i = 0; i < g_n_items; i++) {
        SniItem *it = &g_items[i];
        DBusMessage *reply =
            sni_call1s(it->busname, it->path, "org.freedesktop.DBus.Properties", "GetAll", SNI_ITEM_IFACE);
        if (!reply) {
            if (it->icon) {
                cairo_surface_destroy(it->icon);
            }
            continue;
        }
        char title[128];
        title[0] = 0;
        extract_string_prop(reply, "Title", title, sizeof(title));
        if (!title[0]) {
            extract_string_prop(reply, "IconName", title, sizeof(title));
        }
        cairo_surface_t *icon = extract_icon_pixmap(reply);
        p_dbus_message_unref(reply);

        SniItem *dst = &alive[n_alive++];
        *dst = *it;
        snprintf(dst->title, sizeof(dst->title), "%s", title);
        if (icon) {
            if (dst->icon) {
                cairo_surface_destroy(dst->icon);
            }
            dst->icon = icon;
        }
    }
    memcpy(g_items, alive, sizeof(SniItem) * (size_t)n_alive);
    g_n_items = n_alive;
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
