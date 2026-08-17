/*
 * xisserve - GTK2 application launcher (kickoff/krunner-style), companion
 * to xispanel's `xisserve` widget (see ../xispanel/widgets/xisserve.c --
 * already implemented and shipping; `launcher` stays the simple
 * pin-a-shortcut widget, no search/no .desktop parsing).
 *
 * Named after volleyball's serve (the play that starts the point) --
 * xisstart was the other name floated (Windows-Start-menu callback) but
 * xisserve won: consistent with xisback/xisguard/xisconf/xisnotif's
 * "xis-" prefix without directly aping another desktop's naming.
 *
 * Planned shape (not implemented yet, this is a skeleton): a krunner-like
 * popup -- type to search installed applications (.desktop parsing,
 * XDG_DATA_DIRS + ~/.local/share/applications, same territory the
 * original xispanel phased plan scoped as "launcher phase") and, later,
 * something in the spirit of Ubuntu Unity's HUD (search actions *within*
 * the currently focused app, not just launch new ones) -- the user's
 * existing krunner_appmenu.py script (a working KRunner plugin that reads
 * a focused Qt/KF5 window's exported appmenu via
 * _KDE_NET_WM_APPMENU_SERVICE_NAME/_OBJECT_PATH and matches DBusMenu
 * entries against the typed query) is the reference implementation for
 * that half -- xispanel's own globalmenu widget (widgets/globalmenu.c)
 * and dbusmenu.c already do the DBus side of that same lookup in C, so
 * this can reuse the same mechanism rather than reinventing it.
 *
 * Positioning: xispanel's `xisserve` widget (../xispanel/widgets/
 * xisserve.c, already implemented and shipping) invokes this with its
 * own on-screen anchor coordinates, panel edge/output geometry, and
 * theme (argv, not embedding/reparenting -- reparenting would make
 * xispanel an XEmbed-style host for a second toolkit, real complexity
 * for a component that renders as a floating popup on top of everything
 * anyway, not literally inside the panel). See PROTOCOL.md for the
 * exact flag set (--anchor-x/-y/-w/-h, --edge, --output-x/-y/-w/-h,
 * --bg/--fg, --font/--font-size) and the singleton/toggle behavior this
 * binary is expected to implement -- xisserve creates its own
 * override-redirect-equivalent GTK popup window at that position.
 *
 * Not implemented yet -- this is a skeleton: confirms GTK2 initializes
 * and a window appears, nothing else. TODO once real work starts here:
 *   - Parse the argv flags PROTOCOL.md documents, position the window
 *     accordingly instead of letting the WM place it.
 *   - flock-based singleton (same pattern as xisback/xisguard) plus
 *     whatever IPC relays a second invocation's argv into the first
 *     instance as a reposition+toggle -- see PROTOCOL.md's "Singleton /
 *     toggle behavior" section.
 *   - .desktop entry parsing + XDG icon theme resolution, incremental
 *     search-as-you-type.
 *   - DBusMenu-based in-app action search (see the HUD note above).
 *   - Same open question as xisnotif re: matching the KDE Plasma color
 *     scheme and system font in GTK2 -- see xisnotif/README.md, applies
 *     here identically (the --bg/--fg/--font/--font-size flags cover
 *     the panel's own theme; the color-*scheme* question is about GTK2
 *     widget chrome beyond just those four values).
 */
#include <gtk/gtk.h>

int main(int argc, char **argv)
{
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "xisserve");
    gtk_window_set_default_size(GTK_WINDOW(window), 480, 320);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *label = gtk_label_new("xisserve -- application launcher (skeleton, not implemented yet)");
    gtk_container_add(GTK_CONTAINER(window), label);

    gtk_widget_show_all(window);
    gtk_main();
    return 0;
}
