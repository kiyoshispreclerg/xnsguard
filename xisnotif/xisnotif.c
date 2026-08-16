/*
 * xisnotif - GTK2 notification-history viewer, companion to xispanel's
 * tray bell icon.
 *
 * Division of labor (see xispanel/PROTOCOL.md once this is fleshed out):
 * xispanel itself implements the org.freedesktop.Notifications DBus
 * service, the tray bell icon (with an unread-count badge, same style as
 * its existing StatusNotifierItem tray icons), and *transient* popup
 * banners for incoming notifications (reusing the clickable-popup-with-
 * buttons mechanism already built for tooltip.c's MPRIS controls -- a
 * notification action button is the same shape of problem). None of that
 * needs a second process or a heavier toolkit.
 *
 * What genuinely doesn't fit xispanel's "no toolkit, minimal deps"
 * philosophy is a scrollable *history* view -- balloons of past
 * notifications with text/icon/timestamp, read/unread state, per-item
 * close, grouping by app -- real list-widget UI that would mean
 * reimplementing a scrolling/selection/hit-testing framework in raw
 * Cairo. GTK2 already has one. So: xispanel keeps a bounded in-memory
 * ring buffer of recent notifications and exposes it over its existing
 * control socket (same "already have the plumbing" reasoning xisconf
 * uses to drive xisback/xisguard); xisnotif is a thin GTK2 client that
 * queries that socket and renders the list -- clicking an entry there
 * runs whatever action the notification offered, same as clicking a
 * button in xispanel's own transient popup would have.
 *
 * Not implemented yet -- this is a skeleton (see the project's session
 * notes): confirms GTK2 initializes and a window appears, nothing else.
 * TODO once real work starts here:
 *   - Connect to $XDG_RUNTIME_DIR/xispanel-ctl.sock, query notification
 *     history (new IPC command on the xispanel side first).
 *   - Render as a scrollable list (GtkTreeView or a plain VBox of rows).
 *   - Match xispanel's own bg/fg panel theme colors, if practical, so it
 *     doesn't look like a foreign app bolted on.
 *   - Font: read the same live-system-font detection xispanel.c already
 *     does (kdeglobals [General] font=, gtk-3.0 settings.ini fallback)
 *     rather than trusting GTK2's own (usually GTK3-theme-less) default.
 *   - Colors following the KDE Plasma color scheme: GTK2 has no direct
 *     equivalent of Qt's palette system, and the old bridges (oxygen-gtk,
 *     qt5ct's GTK2 hook) are largely unmaintained today. The more
 *     realistic path is generating a small .gtkrc-2.0 snippet from
 *     kdeglobals's [Colors:Window]/[Colors:Button] sections (mirroring
 *     xispanel.c's own detect_system_colors()) and pointing
 *     GTK2_RC_FILES at it before gtk_init() -- not done yet, needs its
 *     own investigation pass.
 */
#include <gtk/gtk.h>

int main(int argc, char **argv)
{
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "xisnotif");
    gtk_window_set_default_size(GTK_WINDOW(window), 360, 480);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *label = gtk_label_new("xisnotif -- notification history (skeleton, not implemented yet)");
    gtk_container_add(GTK_CONTAINER(window), label);

    gtk_widget_show_all(window);
    gtk_main();
    return 0;
}
