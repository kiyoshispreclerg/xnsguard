/*
 * dbusmenu.c - generic com.canonical.dbusmenu client (GetLayout + Event).
 *
 * Extracted out of sni.c (where it originally lived to render a tray
 * item's Menu property) so the globalmenu widget can reuse the exact same
 * fetch/flatten/click logic against a window's
 * _KDE_NET_WM_APPMENU_SERVICE_NAME/_OBJECT_PATH instead -- both are just
 * "a busname+objectpath pointing at a com.canonical.dbusmenu object",
 * this file doesn't know or care where that pair came from.
 *
 * Same dlopen'd-libdbus-1-independently philosophy as mpris.c/sni.c: its
 * own dlopen(), own symbol table, own session-bus connection, never
 * linked at build time. Deliberately does *not* share a DBusConnection
 * with sni.c/mpris.c -- keeps this file usable on its own (e.g. from
 * globalmenu.c) without depending on sni.c's watcher/host bookkeeping,
 * at the cost of one extra (cheap, libdbus internally dedupes) session
 * bus connection when both happen to be active at once.
 *
 * GetLayout(parent_id, depth, []) with depth=-1 returns the *entire*
 * subtree under parent_id in one call, so no follow-up round-trips are
 * needed for nested submenus. dbusmenu_fetch() flattens whatever subtree
 * it's asked for into parallel out_items[]/out_ids[]/out_depth[] arrays,
 * out_depth[i] recording item i's nesting depth relative to parent_id
 * (not baked into the label) -- menu.c's panel_menu_open_tree() consumes
 * that shape directly to render real cascading submenu popups (one frame
 * per depth level, opened beside the previous). Callers that just want a
 * single flat display with visual indentation instead (sni.c's tray Menu
 * popup) bake it into the label themselves from out_depth before calling
 * the plain panel_menu_open(). Callers pick parent_id/depth for their own
 * shape of fetch -- e.g. sni.c wants the whole tree at once (parent_id=0,
 * depth=-1), while globalmenu.c wants just the top-level item labels for
 * its menu bar (parent_id=0, depth=1) and, once one of those is clicked
 * (or hovered, in menu.c's cascade), that single item's own full subtree
 * (parent_id=<its id>, depth=-1). */
#include "xispanel.h"

#include <dbus/dbus.h>

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#define DBUSMENU_IFACE "com.canonical.dbusmenu"
#define DBUSMENU_CALL_TIMEOUT_MS 200

static void *g_libdbus = NULL;
static int g_load_attempted = 0;
static DBusConnection *g_conn = NULL;

static void (*p_dbus_error_init)(DBusError *);
static void (*p_dbus_error_free)(DBusError *);
static dbus_bool_t (*p_dbus_error_is_set)(const DBusError *);
static DBusConnection *(*p_dbus_bus_get)(DBusBusType, DBusError *);
static DBusMessage *(*p_dbus_message_new_method_call)(const char *, const char *, const char *, const char *);
static void (*p_dbus_message_unref)(DBusMessage *);
static DBusMessage *(*p_dbus_connection_send_with_reply_and_block)(DBusConnection *, DBusMessage *, int, DBusError *);
static dbus_bool_t (*p_dbus_connection_send)(DBusConnection *, DBusMessage *, dbus_uint32_t *);
static dbus_bool_t (*p_dbus_message_iter_init)(DBusMessage *, DBusMessageIter *);
static dbus_bool_t (*p_dbus_message_iter_next)(DBusMessageIter *);
static int (*p_dbus_message_iter_get_arg_type)(DBusMessageIter *);
static void (*p_dbus_message_iter_recurse)(DBusMessageIter *, DBusMessageIter *);
static void (*p_dbus_message_iter_get_basic)(DBusMessageIter *, void *);
static void (*p_dbus_message_iter_init_append)(DBusMessage *, DBusMessageIter *);
static dbus_bool_t (*p_dbus_message_iter_append_basic)(DBusMessageIter *, int, const void *);
static dbus_bool_t (*p_dbus_message_iter_open_container)(DBusMessageIter *, int, const char *, DBusMessageIter *);
static dbus_bool_t (*p_dbus_message_iter_close_container)(DBusMessageIter *, DBusMessageIter *);

#define LOAD_SYM(name)                                                                                               \
    do {                                                                                                             \
        *(void **)(&p_##name) = dlsym(g_libdbus, #name);                                                            \
        if (!p_##name) {                                                                                             \
            fprintf(stderr, "xispanel: dbusmenu: symbol '%s' missing from libdbus-1, disabling\n", #name);          \
            return 0;                                                                                                \
        }                                                                                                            \
    } while (0)

static int dbusmenu_load_symbols(void)
{
    LOAD_SYM(dbus_error_init);
    LOAD_SYM(dbus_error_free);
    LOAD_SYM(dbus_error_is_set);
    LOAD_SYM(dbus_bus_get);
    LOAD_SYM(dbus_message_new_method_call);
    LOAD_SYM(dbus_message_unref);
    LOAD_SYM(dbus_connection_send_with_reply_and_block);
    LOAD_SYM(dbus_connection_send);
    LOAD_SYM(dbus_message_iter_init);
    LOAD_SYM(dbus_message_iter_next);
    LOAD_SYM(dbus_message_iter_get_arg_type);
    LOAD_SYM(dbus_message_iter_recurse);
    LOAD_SYM(dbus_message_iter_get_basic);
    LOAD_SYM(dbus_message_iter_init_append);
    LOAD_SYM(dbus_message_iter_append_basic);
    LOAD_SYM(dbus_message_iter_open_container);
    LOAD_SYM(dbus_message_iter_close_container);
    return 1;
}

static int dbusmenu_ensure_connected(void)
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
    if (!dbusmenu_load_symbols()) {
        dlclose(g_libdbus);
        g_libdbus = NULL;
        return 0;
    }

    DBusError err;
    p_dbus_error_init(&err);
    g_conn = p_dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (p_dbus_error_is_set(&err)) {
        fprintf(stderr, "xispanel: dbusmenu: could not connect to session bus (%s)\n", err.message);
        p_dbus_error_free(&err);
    }
    return g_conn != NULL;
}

/* Recursively flattens one (ia{sv}av) node (already positioned at a
 * DBUS_TYPE_VARIANT wrapping that struct) into out_items[]/out_ids[]/
 * out_depth[], recording each item's nesting depth (relative to the
 * subtree's own root) rather than baking it into the label -- callers
 * that want a flat indented display add that themselves. Skips invisible
 * items and their entire subtree; disabled items are still listed
 * (greyed out) so the layout doesn't visibly shift. */
static void dbusmenu_parse_node(DBusMessageIter *variant_iter, int depth, MenuItem *out_items, int *out_ids,
                                 int *out_depth, int max_items, int *n)
{
    if (*n >= max_items) {
        return;
    }
    /* Two recurses, not one: the first lands *at* the (ia{sv}av) struct the
     * variant wraps (its arg type, not inside its fields yet); the second
     * actually enters that struct to reach its fields (id, then props,
     * then children). Missing this second step is a real, easy-to-miss
     * bug: every field-type check below silently fails, so id stays 0 and
     * label stays empty for every real menu item, while the *count* of
     * items still comes out right (the caller's loop only walks the
     * variants themselves, unaffected by this). */
    DBusMessageIter node_struct, node;
    p_dbus_message_iter_recurse(variant_iter, &node_struct);
    p_dbus_message_iter_recurse(&node_struct, &node);

    int32_t id = 0;
    if (p_dbus_message_iter_get_arg_type(&node) == DBUS_TYPE_INT32) {
        p_dbus_message_iter_get_basic(&node, &id);
    }
    p_dbus_message_iter_next(&node);

    char label[64] = "";
    int is_separator = 0, enabled = 1, visible = 1;
    if (p_dbus_message_iter_get_arg_type(&node) == DBUS_TYPE_ARRAY) {
        DBusMessageIter props;
        p_dbus_message_iter_recurse(&node, &props);
        while (p_dbus_message_iter_get_arg_type(&props) == DBUS_TYPE_DICT_ENTRY) {
            DBusMessageIter entry;
            p_dbus_message_iter_recurse(&props, &entry);
            const char *key = NULL;
            if (p_dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
                p_dbus_message_iter_get_basic(&entry, &key);
            }
            p_dbus_message_iter_next(&entry);
            if (key && p_dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_VARIANT) {
                DBusMessageIter val;
                p_dbus_message_iter_recurse(&entry, &val);
                int vt = p_dbus_message_iter_get_arg_type(&val);
                if (!strcmp(key, "label") && vt == DBUS_TYPE_STRING) {
                    const char *s = NULL;
                    p_dbus_message_iter_get_basic(&val, &s);
                    /* DBusMenu labels use "_" for mnemonics (like GTK) --
                     * strip it, xispanel has no keyboard-mnemonic support
                     * to hook it up to anyway. */
                    if (s) {
                        size_t o = 0;
                        for (size_t j = 0; s[j] && o + 1 < sizeof(label); j++) {
                            if (s[j] != '_') {
                                label[o++] = s[j];
                            }
                        }
                        label[o] = 0;
                    }
                } else if (!strcmp(key, "type") && vt == DBUS_TYPE_STRING) {
                    const char *s = NULL;
                    p_dbus_message_iter_get_basic(&val, &s);
                    if (s && !strcmp(s, "separator")) {
                        is_separator = 1;
                    }
                } else if (!strcmp(key, "enabled") && vt == DBUS_TYPE_BOOLEAN) {
                    dbus_bool_t b = TRUE;
                    p_dbus_message_iter_get_basic(&val, &b);
                    enabled = b;
                } else if (!strcmp(key, "visible") && vt == DBUS_TYPE_BOOLEAN) {
                    dbus_bool_t b = TRUE;
                    p_dbus_message_iter_get_basic(&val, &b);
                    visible = b;
                }
            }
            if (!p_dbus_message_iter_next(&props)) {
                break;
            }
        }
        p_dbus_message_iter_next(&node);
    }

    if (visible) {
        MenuItem *mi = &out_items[*n];
        memset(mi, 0, sizeof(*mi));
        mi->is_separator = is_separator;
        mi->enabled = enabled;
        if (!is_separator) {
            snprintf(mi->label, sizeof(mi->label), "%s", label);
        }
        out_ids[*n] = id;
        out_depth[*n] = depth;
        (*n)++;
    }

    /* Third field: av (array of variant), each wrapping a child node --
     * present (possibly empty) whether or not this item has visible
     * children; recurse only if actually visible, matching the skip above. */
    if (visible && p_dbus_message_iter_get_arg_type(&node) == DBUS_TYPE_ARRAY) {
        DBusMessageIter children;
        p_dbus_message_iter_recurse(&node, &children);
        while (p_dbus_message_iter_get_arg_type(&children) == DBUS_TYPE_VARIANT && *n < max_items) {
            dbusmenu_parse_node(&children, depth + 1, out_items, out_ids, out_depth, max_items, n);
            if (!p_dbus_message_iter_next(&children)) {
                break;
            }
        }
    }
}

int dbusmenu_fetch(const char *busname, const char *path, int32_t parent_id, int32_t depth, MenuItem *out_items,
                    int *out_ids, int *out_depth, int max_items)
{
    if (!dbusmenu_ensure_connected()) {
        return -1;
    }

    DBusMessage *msg = p_dbus_message_new_method_call(busname, path, DBUSMENU_IFACE, "GetLayout");
    if (!msg) {
        return -1;
    }
    DBusMessageIter it, str_arr;
    p_dbus_message_iter_init_append(msg, &it);
    p_dbus_message_iter_append_basic(&it, DBUS_TYPE_INT32, &parent_id);
    p_dbus_message_iter_append_basic(&it, DBUS_TYPE_INT32, &depth);
    p_dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "s", &str_arr);
    p_dbus_message_iter_close_container(&it, &str_arr);
    DBusError err;
    p_dbus_error_init(&err);
    DBusMessage *reply = p_dbus_connection_send_with_reply_and_block(g_conn, msg, DBUSMENU_CALL_TIMEOUT_MS, &err);
    p_dbus_message_unref(msg);
    if (p_dbus_error_is_set(&err)) {
        p_dbus_error_free(&err);
        return -1;
    }
    if (!reply) {
        return -1;
    }

    int n = 0;
    DBusMessageIter rit;
    if (p_dbus_message_iter_init(reply, &rit) && p_dbus_message_iter_get_arg_type(&rit) == DBUS_TYPE_UINT32) {
        p_dbus_message_iter_next(&rit); /* skip revision */
        if (p_dbus_message_iter_get_arg_type(&rit) == DBUS_TYPE_STRUCT) {
            /* dbusmenu_parse_node() expects a variant-wrapped struct (that's
             * the shape every *child* comes in); the top-level reply's
             * struct isn't itself variant-wrapped, but its own children
             * (what we actually want to list -- the root item is just an
             * unlabeled container) are, via the same av field every node
             * has. Walk into the root struct by hand once to reach them. */
            DBusMessageIter root;
            p_dbus_message_iter_recurse(&rit, &root); /* now at field 1: id */
            p_dbus_message_iter_next(&root); /* now at field 2: props dict (a{sv}) */
            if (p_dbus_message_iter_get_arg_type(&root) == DBUS_TYPE_ARRAY) {
                p_dbus_message_iter_next(&root); /* now at field 3: children (av) */
            }
            if (p_dbus_message_iter_get_arg_type(&root) == DBUS_TYPE_ARRAY) {
                DBusMessageIter children;
                p_dbus_message_iter_recurse(&root, &children);
                while (p_dbus_message_iter_get_arg_type(&children) == DBUS_TYPE_VARIANT && n < max_items) {
                    dbusmenu_parse_node(&children, 0, out_items, out_ids, out_depth, max_items, &n);
                    if (!p_dbus_message_iter_next(&children)) {
                        break;
                    }
                }
            }
        }
    }
    p_dbus_message_unref(reply);
    return n;
}

/* Fire-and-forget DBusMenu Event(id, "clicked", <int32 0>, timestamp) --
 * nothing here waits for or cares about a reply. */
void dbusmenu_send_event(const char *busname, const char *path, int32_t id)
{
    if (!dbusmenu_ensure_connected()) {
        return;
    }
    DBusMessage *msg = p_dbus_message_new_method_call(busname, path, DBUSMENU_IFACE, "Event");
    if (!msg) {
        return;
    }
    DBusMessageIter it, variant;
    p_dbus_message_iter_init_append(msg, &it);
    p_dbus_message_iter_append_basic(&it, DBUS_TYPE_INT32, &id);
    const char *event_id = "clicked";
    p_dbus_message_iter_append_basic(&it, DBUS_TYPE_STRING, &event_id);
    p_dbus_message_iter_open_container(&it, DBUS_TYPE_VARIANT, "i", &variant);
    int32_t dummy = 0;
    p_dbus_message_iter_append_basic(&variant, DBUS_TYPE_INT32, &dummy);
    p_dbus_message_iter_close_container(&it, &variant);
    dbus_uint32_t timestamp = 0;
    p_dbus_message_iter_append_basic(&it, DBUS_TYPE_UINT32, &timestamp);
    p_dbus_connection_send(g_conn, msg, NULL);
    p_dbus_message_unref(msg);
}
