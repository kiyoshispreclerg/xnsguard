/*
 * notifd.c - minimal org.freedesktop.Notifications server, same dlopen'd-
 * libdbus-1 philosophy as mpris.c/sni.c (optional at runtime, never
 * linked -- see mpris.c's header comment for why).
 *
 * Unlike sni.c's StatusNotifierWatcher (which has a real multi-host
 * model -- xispanel can attach as a "second host" alongside an existing
 * tray), the Notifications spec has exactly one owner: whichever process
 * holds the well-known bus name is the only one that will ever receive a
 * Notify() call. So this checks NameHasOwner once at startup (same
 * technique sni.c uses for its own watcher names) and, if something else
 * already owns it, stays permanently dormant rather than trying to
 * coexist -- there's no fallback "read the real owner's state" path the
 * way sni.c has for an already-claimed tray watcher, since notifications
 * aren't a property xispanel could poll from the real owner even if it
 * wanted to.
 *
 * Same non-blocking poll-and-drain integration as sni.c: no libdbus-1
 * watch/timeout objects pulled into xispanel's select() loop, just
 * dbus_connection_read_write(0) + dbus_connection_pop_message() every
 * notifd_poll() tick, with method calls answered by hand (no
 * dbus_connection_register_object_path()/vtable machinery needed for
 * the handful of methods a real sender actually calls: Notify,
 * CloseNotification, GetCapabilities, GetServerInformation).
 *
 * Storage (the capped ring buffer) lives here, not in any widget -- see
 * the NotifEntry API doc comment in xispanel.h. NotificationClosed
 * (the signal senders can listen for to know a notification went away)
 * is deliberately not emitted -- a real compliance gap, but nothing
 * inside xispanel depends on it, and no widget here supports the
 * closable-with-actions notifications where a well-behaved sender would
 * actually care.
 */
#include "xispanel.h"

#include <dbus/dbus.h>

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#define NOTIFD_POLL_MS 500
#define NOTIFD_MAX 50
#define NOTIFD_NAME "org.freedesktop.Notifications"
#define NOTIFD_PATH "/org/freedesktop/Notifications"
#define NOTIFD_IFACE "org.freedesktop.Notifications"
#define NOTIFD_DEFAULT_EXPIRE_MS 5000

static NotifEntry g_ring[NOTIFD_MAX];
static int g_head = 0; /* index of the oldest held entry */
static int g_count = 0;
static unsigned int g_next_id = 1;
static NotifArrivedFn g_arrived_fn = NULL;
/* Overridable via notifd_set_default_expire_ms() (widgets/notif.c's
 * timeout= config) -- only applies to a Notify() call that didn't request
 * its own expire_timeout (the < 0 "server picks a default" case per the
 * spec), never overrides a sender's explicit request. */
static int g_default_expire_ms = NOTIFD_DEFAULT_EXPIRE_MS;

static void *g_libdbus = NULL;
static int g_load_attempted = 0;
static DBusConnection *g_conn = NULL;
static int g_is_owner = 0;
static uint64_t g_next_poll_ms = 0;

/* ---- dlopen'd libdbus-1 symbols ---------------------------------- */
static void (*p_dbus_error_init)(DBusError *);
static void (*p_dbus_error_free)(DBusError *);
static dbus_bool_t (*p_dbus_error_is_set)(const DBusError *);
static DBusConnection *(*p_dbus_bus_get_private)(DBusBusType, DBusError *);
static int (*p_dbus_bus_request_name)(DBusConnection *, const char *, unsigned int, DBusError *);
static dbus_bool_t (*p_dbus_bus_name_has_owner)(DBusConnection *, const char *, DBusError *);
static DBusMessage *(*p_dbus_message_new_method_return)(DBusMessage *);
static DBusMessage *(*p_dbus_message_new_error)(DBusMessage *, const char *, const char *);
static void (*p_dbus_message_unref)(DBusMessage *);
static dbus_bool_t (*p_dbus_connection_send)(DBusConnection *, DBusMessage *, dbus_uint32_t *);
static dbus_bool_t (*p_dbus_connection_read_write)(DBusConnection *, int);
static DBusMessage *(*p_dbus_connection_pop_message)(DBusConnection *);
static dbus_bool_t (*p_dbus_message_iter_init)(DBusMessage *, DBusMessageIter *);
static dbus_bool_t (*p_dbus_message_iter_next)(DBusMessageIter *);
static int (*p_dbus_message_iter_get_arg_type)(DBusMessageIter *);
static void (*p_dbus_message_iter_get_basic)(DBusMessageIter *, void *);
static void (*p_dbus_message_iter_init_append)(DBusMessage *, DBusMessageIter *);
static dbus_bool_t (*p_dbus_message_iter_append_basic)(DBusMessageIter *, int, const void *);
static dbus_bool_t (*p_dbus_message_iter_open_container)(DBusMessageIter *, int, const char *, DBusMessageIter *);
static dbus_bool_t (*p_dbus_message_iter_close_container)(DBusMessageIter *, DBusMessageIter *);
static int (*p_dbus_message_get_type)(DBusMessage *);
static const char *(*p_dbus_message_get_interface)(DBusMessage *);
static const char *(*p_dbus_message_get_member)(DBusMessage *);
static dbus_bool_t (*p_dbus_message_get_no_reply)(DBusMessage *);

#define LOAD_SYM(name)                                                                                               \
    do {                                                                                                             \
        *(void **)(&p_##name) = dlsym(g_libdbus, #name);                                                            \
        if (!p_##name) {                                                                                             \
            fprintf(stderr, "xispanel: notifd: symbol '%s' missing from libdbus-1, disabling notifications\n",      \
                    #name);                                                                                          \
            return 0;                                                                                                \
        }                                                                                                            \
    } while (0)

static int notifd_load_symbols(void)
{
    LOAD_SYM(dbus_error_init);
    LOAD_SYM(dbus_error_free);
    LOAD_SYM(dbus_error_is_set);
    LOAD_SYM(dbus_bus_get_private);
    LOAD_SYM(dbus_bus_request_name);
    LOAD_SYM(dbus_bus_name_has_owner);
    LOAD_SYM(dbus_message_new_method_return);
    LOAD_SYM(dbus_message_new_error);
    LOAD_SYM(dbus_message_unref);
    LOAD_SYM(dbus_connection_send);
    LOAD_SYM(dbus_connection_read_write);
    LOAD_SYM(dbus_connection_pop_message);
    LOAD_SYM(dbus_message_iter_init);
    LOAD_SYM(dbus_message_iter_next);
    LOAD_SYM(dbus_message_iter_get_arg_type);
    LOAD_SYM(dbus_message_iter_get_basic);
    LOAD_SYM(dbus_message_iter_init_append);
    LOAD_SYM(dbus_message_iter_append_basic);
    LOAD_SYM(dbus_message_iter_open_container);
    LOAD_SYM(dbus_message_iter_close_container);
    LOAD_SYM(dbus_message_get_type);
    LOAD_SYM(dbus_message_get_interface);
    LOAD_SYM(dbus_message_get_member);
    LOAD_SYM(dbus_message_get_no_reply);
    return 1;
}

static int notifd_ensure_connected(void)
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
    if (!notifd_load_symbols()) {
        dlclose(g_libdbus);
        g_libdbus = NULL;
        return 0;
    }

    /* A *private* connection (not the shared per-process one dbus_bus_get()
     * hands out) is essential here, not just tidy: mpris.c/sni.c/
     * dbusmenu.c all share that one connection's message queue, and
     * sni.c's own poll loop unconditionally pop_message()s and error-
     * replies to any method call it doesn't recognize once xispanel is
     * the tray watcher -- on a shared connection it would silently steal
     * (and reject) every incoming Notify() before notifd_poll() ever got
     * a chance to see it. Confirmed live: a real Notify() call timed out
     * with no reply until this was switched to a private connection. */
    DBusError err;
    p_dbus_error_init(&err);
    g_conn = p_dbus_bus_get_private(DBUS_BUS_SESSION, &err);
    if (p_dbus_error_is_set(&err)) {
        fprintf(stderr, "xispanel: notifd: could not connect to session bus (%s), disabling notifications\n",
                err.message);
        p_dbus_error_free(&err);
    }
    if (!g_conn) {
        return 0;
    }

    DBusError herr;
    p_dbus_error_init(&herr);
    dbus_bool_t owned = p_dbus_bus_name_has_owner(g_conn, NOTIFD_NAME, &herr);
    p_dbus_error_free(&herr);
    if (owned) {
        fprintf(stderr, "xispanel: notifd: %s is already owned by another process -- xispanel will not "
                        "receive notifications\n",
                NOTIFD_NAME);
        return 1; /* connected, but permanently not the owner -- notifd_poll() just idles */
    }

    DBusError rerr;
    p_dbus_error_init(&rerr);
    /* DBUS_NAME_FLAG_DO_NOT_QUEUE = 4, same flag sni.c uses -- fail
     * immediately instead of queuing behind a racing claimant. */
    int ret = p_dbus_bus_request_name(g_conn, NOTIFD_NAME, 4, &rerr);
    p_dbus_error_free(&rerr);
    g_is_owner = (ret == 1); /* DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER */
    if (g_is_owner) {
        fprintf(stderr, "xispanel: notifd: registered as %s\n", NOTIFD_NAME);
    } else {
        fprintf(stderr, "xispanel: notifd: could not claim %s, notifications disabled\n", NOTIFD_NAME);
    }
    return 1;
}

/* Loads app_icon per the spec's own rules: an absolute path, a
 * "file://" URI, or a themed icon name to resolve against the freedesktop
 * icon theme grid (see resolve_icon_theme_name() in ewmh.c) -- same
 * three forms sni.c already handles for a tray item's IconName/
 * IconPixmap fallback. NULL if empty or nothing resolved. */
/* Matches toast.c's TOAST_ICON -- the only place a notification's icon is
 * ever drawn, at a fixed size regardless of which panel/output shows the
 * toast. Shrinking to it here (rather than caching whatever an icon
 * theme/PNG happens to be) keeps the ring buffer's held icons cheap even
 * when all NOTIFD_MAX ring entries are holding one. */
#define NOTIFD_ICON_TARGET_PX 40

static cairo_surface_t *resolve_notif_icon(const char *app_icon)
{
    if (!app_icon || !app_icon[0]) {
        return NULL;
    }
    if (app_icon[0] == '/') {
        return load_icon_argb(app_icon, NOTIFD_ICON_TARGET_PX);
    }
    if (!strncmp(app_icon, "file://", 7)) {
        return load_icon_argb(app_icon + 7, NOTIFD_ICON_TARGET_PX);
    }
    return resolve_icon_theme_name(app_icon, NOTIFD_ICON_TARGET_PX);
}

static void ring_append(const char *app_name, const char *app_icon, const char *summary, const char *body,
                         int expire_timeout_ms)
{
    NotifEntry *dst;
    if (g_count < NOTIFD_MAX) {
        dst = &g_ring[(g_head + g_count) % NOTIFD_MAX];
        g_count++;
    } else {
        /* Full -- evict the oldest, freeing its icon before overwrite. */
        dst = &g_ring[g_head];
        if (dst->icon) {
            cairo_surface_destroy(dst->icon);
        }
        g_head = (g_head + 1) % NOTIFD_MAX;
        dst = &g_ring[(g_head + NOTIFD_MAX - 1) % NOTIFD_MAX];
    }
    memset(dst, 0, sizeof(*dst));
    dst->id = g_next_id++;
    snprintf(dst->app_name, sizeof(dst->app_name), "%s", app_name);
    snprintf(dst->summary, sizeof(dst->summary), "%s", summary);
    snprintf(dst->body, sizeof(dst->body), "%s", body);
    dst->icon = resolve_notif_icon(app_icon);
    dst->read = 0;
    dst->received_ms = now_ms();

    fprintf(stderr, "xispanel: notifd: notification received (id=%u app=%s summary=%s)\n", dst->id,
            dst->app_name[0] ? dst->app_name : "?", dst->summary);

    if (g_arrived_fn) {
        g_arrived_fn(dst, expire_timeout_ms);
    }
}

/* Parses Notify()'s args in order, skipping (via a bare iter_next(), no
 * recursing needed) the ones nothing here uses -- replaces_id, actions[],
 * hints (a{sv}) -- since libdbus-1's iterator can step over a whole
 * compound argument without the caller decoding it. Returns the new
 * entry's id (>=1), or 0 if the message was malformed. */
static unsigned int handle_notify(DBusMessage *msg)
{
    DBusMessageIter it;
    if (!p_dbus_message_iter_init(msg, &it)) {
        return 0;
    }
    char app_name[NOTIFD_APP_NAME_MAX] = "";
    char app_icon[256] = "";
    char summary[NOTIFD_SUMMARY_MAX] = "";
    char body[NOTIFD_BODY_MAX] = "";
    dbus_int32_t expire_timeout = -1;

    if (p_dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_STRING) {
        const char *s = NULL;
        p_dbus_message_iter_get_basic(&it, &s);
        snprintf(app_name, sizeof(app_name), "%s", s ? s : "");
    }
    if (!p_dbus_message_iter_next(&it)) { /* replaces_id, ignored -- v1 never replaces, always appends */
        goto done;
    }
    if (!p_dbus_message_iter_next(&it)) {
        goto done;
    }
    if (p_dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_STRING) {
        const char *s = NULL;
        p_dbus_message_iter_get_basic(&it, &s);
        snprintf(app_icon, sizeof(app_icon), "%s", s ? s : "");
    }
    if (!p_dbus_message_iter_next(&it)) {
        goto done;
    }
    if (p_dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_STRING) {
        const char *s = NULL;
        p_dbus_message_iter_get_basic(&it, &s);
        snprintf(summary, sizeof(summary), "%s", s ? s : "");
    }
    if (!p_dbus_message_iter_next(&it)) {
        goto done;
    }
    if (p_dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_STRING) {
        const char *s = NULL;
        p_dbus_message_iter_get_basic(&it, &s);
        snprintf(body, sizeof(body), "%s", s ? s : "");
    }
    if (!p_dbus_message_iter_next(&it)) { /* actions[] */
        goto done;
    }
    if (!p_dbus_message_iter_next(&it)) { /* hints a{sv} */
        goto done;
    }
    if (p_dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_INT32) {
        p_dbus_message_iter_get_basic(&it, &expire_timeout);
    }
done:
    if (!summary[0] && !body[0]) {
        return 0; /* nothing worth showing */
    }
    int expire_ms = expire_timeout >= 0 ? expire_timeout : g_default_expire_ms;
    unsigned int id_before = g_next_id;
    ring_append(app_name, app_icon, summary, body, expire_ms);
    return id_before;
}

static void handle_close_notification(DBusMessage *msg)
{
    DBusMessageIter it;
    if (!p_dbus_message_iter_init(msg, &it) || p_dbus_message_iter_get_arg_type(&it) != DBUS_TYPE_UINT32) {
        return;
    }
    dbus_uint32_t id = 0;
    p_dbus_message_iter_get_basic(&it, &id);
    notifd_mark_read(id);
}

static void notifd_handle_incoming(void)
{
    p_dbus_connection_read_write(g_conn, 0);
    DBusMessage *msg;
    while ((msg = p_dbus_connection_pop_message(g_conn)) != NULL) {
        if (p_dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_METHOD_CALL) {
            p_dbus_message_unref(msg);
            continue;
        }
        const char *iface = p_dbus_message_get_interface(msg);
        const char *member = p_dbus_message_get_member(msg);
        DBusMessage *reply = NULL;

        if (iface && member && !strcmp(iface, NOTIFD_IFACE) && !strcmp(member, "Notify")) {
            unsigned int id = handle_notify(msg);
            reply = p_dbus_message_new_method_return(msg);
            DBusMessageIter rit;
            p_dbus_message_iter_init_append(reply, &rit);
            dbus_uint32_t out_id = id;
            p_dbus_message_iter_append_basic(&rit, DBUS_TYPE_UINT32, &out_id);
        } else if (iface && member && !strcmp(iface, NOTIFD_IFACE) && !strcmp(member, "CloseNotification")) {
            handle_close_notification(msg);
            reply = p_dbus_message_new_method_return(msg);
        } else if (iface && member && !strcmp(iface, NOTIFD_IFACE) && !strcmp(member, "GetCapabilities")) {
            reply = p_dbus_message_new_method_return(msg);
            DBusMessageIter rit, arr;
            p_dbus_message_iter_init_append(reply, &rit);
            p_dbus_message_iter_open_container(&rit, DBUS_TYPE_ARRAY, "s", &arr);
            const char *cap = "body";
            p_dbus_message_iter_append_basic(&arr, DBUS_TYPE_STRING, &cap);
            p_dbus_message_iter_close_container(&rit, &arr);
        } else if (iface && member && !strcmp(iface, NOTIFD_IFACE) && !strcmp(member, "GetServerInformation")) {
            reply = p_dbus_message_new_method_return(msg);
            DBusMessageIter rit;
            p_dbus_message_iter_init_append(reply, &rit);
            const char *name = "xispanel", *vendor = "xnsguard", *version = "1.0", *spec = "1.2";
            p_dbus_message_iter_append_basic(&rit, DBUS_TYPE_STRING, &name);
            p_dbus_message_iter_append_basic(&rit, DBUS_TYPE_STRING, &vendor);
            p_dbus_message_iter_append_basic(&rit, DBUS_TYPE_STRING, &version);
            p_dbus_message_iter_append_basic(&rit, DBUS_TYPE_STRING, &spec);
        } else if (iface && member && !strcmp(iface, "org.freedesktop.DBus.Introspectable") &&
                   !strcmp(member, "Introspect")) {
            reply = p_dbus_message_new_method_return(msg);
            DBusMessageIter rit;
            const char *xml = "<node/>";
            p_dbus_message_iter_init_append(reply, &rit);
            p_dbus_message_iter_append_basic(&rit, DBUS_TYPE_STRING, &xml);
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

void notifd_poll(uint64_t now)
{
    if (now < g_next_poll_ms) {
        return;
    }
    g_next_poll_ms = now + NOTIFD_POLL_MS;

    if (!notifd_ensure_connected() || !g_is_owner) {
        return;
    }
    notifd_handle_incoming();
}

int notifd_count(void)
{
    return g_count;
}

const NotifEntry *notifd_get(int idx)
{
    if (idx < 0 || idx >= g_count) {
        return NULL;
    }
    return &g_ring[(g_head + idx) % NOTIFD_MAX];
}

int notifd_unread_count(void)
{
    int n = 0;
    for (int i = 0; i < g_count; i++) {
        if (!g_ring[(g_head + i) % NOTIFD_MAX].read) {
            n++;
        }
    }
    return n;
}

void notifd_mark_read(unsigned int id)
{
    for (int i = 0; i < g_count; i++) {
        NotifEntry *e = &g_ring[(g_head + i) % NOTIFD_MAX];
        if (e->id == id) {
            e->read = 1;
            return;
        }
    }
}

void notifd_set_arrived_callback(NotifArrivedFn fn)
{
    g_arrived_fn = fn;
}

void notifd_set_default_expire_ms(int ms)
{
    if (ms > 0) {
        g_default_expire_ms = ms;
    }
}
