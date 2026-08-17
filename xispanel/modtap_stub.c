/*
 * modtap_stub.c - build-time fallback when libXtst's Record extension
 * headers aren't available (see modtap.c and the Makefile's HAVE_XTST
 * check). Bare-modifier hotkey= specs are simply logged and ignored.
 */
#include "xispanel.h"

#include <stdio.h>

int modtap_init(void)
{
    return 0;
}

int modtap_available(void)
{
    return 0;
}

int modtap_register(unsigned int modmask, PanelWidget *w, HotkeyFn fn)
{
    (void)modmask;
    (void)w;
    (void)fn;
    fprintf(stderr, "xispanel: hotkey: bare-modifier hotkeys need libXtst (Record extension) at build time, "
                    "which xispanel was built without -- ignoring\n");
    return 0;
}

void modtap_unregister_widget(PanelWidget *w)
{
    (void)w;
}

int modtap_fd(void)
{
    return -1;
}

void modtap_process(void)
{
}
