/*
 * xisserve - GTK2 application launcher (kickoff/krunner-style), companion
 * to xispanel's `launcher` widget stub (see ../xispanel/widgets/launcher.c
 * -- pins individual shortcuts today, no search/no .desktop parsing).
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
 * Positioning: xispanel's `launcher` widget will invoke this with its own
 * on-screen anchor coordinates (argv, not embedding/reparenting -- see
 * the session notes this was discussed in: reparenting would make
 * xispanel an XEmbed-style host for a second toolkit, real complexity for
 * a component that renders as a floating popup on top of everything
 * anyway, not literally inside the panel). xisserve creates its own
 * override-redirect-equivalent GTK popup window at that position.
 *
 * Not implemented yet -- this is a skeleton: confirms GTK2 initializes
 * and a window appears, nothing else. TODO once real work starts here:
 *   - Accept --anchor-x/--anchor-y (or similar) argv, position the
 *     window there instead of letting the WM place it.
 *   - .desktop entry parsing + XDG icon theme resolution, incremental
 *     search-as-you-type.
 *   - DBusMenu-based in-app action search (see the HUD note above).
 *   - Same open question as xisnotif re: matching the KDE Plasma color
 *     scheme and system font in GTK2 -- see xisnotif/README.md, applies
 *     here identically.
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
