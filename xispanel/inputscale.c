/*
 * inputscale.c - X-INPUT-SCALE client query (see
 * /home/kiyoshi/Downloads/kiyoshi-forks/xserver/doc/
 * x11-per-output-scaling-extension.md for the full spec -- this project's
 * own experimental server extension, not upstream/xorgproto).
 *
 * Lets a compositor confine the cursor, per CRTC, to a sub-rectangle of
 * that CRTC's physical scanout box -- the "logical"/usable area it's
 * actually drawing sharp HiDPI content into on that output, when that
 * area is smaller than the raw physical pixel count. xispanel only ever
 * *reads* this (XISGetCrtcConfine) -- it has no business setting
 * confinement itself, that's a compositor's job. Used by
 * resolve_output_geometry() (xispanel.c) so a panel sizes itself to the
 * output's actual usable desktop-space box instead of its raw physical
 * CRTC size whenever the two differ.
 *
 * No client-side binding exists for this protocol yet (it's still a
 * draft, per the server doc) -- this speaks the wire requests directly
 * over XCB, the same way the server tree's own
 * Xext/inputscale/test/xis-smoke-test.c does, since mixing a single
 * hand-rolled extension request into an otherwise Xlib-only codebase is
 * far simpler via XCB's generic xcb_send_request() than via Xlib's own
 * (unexported) extension-request plumbing. XGetXCBConnection() shares
 * xispanel's *existing* Xlib connection rather than opening a second one
 * -- both libraries can safely interleave requests on it.
 *
 * XISConfineNotify (live change events, added to the protocol
 * 2026-08-22): a first attempt shared xispanel's own Xlib connection via
 * XGetXCBConnection() + XSetEventQueueOwner() + XESetWireToEvent(), and
 * made xispanel spin at 100% CPU on startup -- mixing Xlib/XCB queue
 * ownership on that connection was hazardous in a way not fully
 * root-caused (see reference_xis_extensions.md in project memory).
 * Sidestepped entirely here with a **second, dedicated xcb_connect()**
 * used for nothing but this one event: no Xlib involvement at all on
 * this connection, so there's no queue-ownership interaction to get
 * wrong. Its fd is added to xispanel.c's own select() set exactly like
 * modtap's; inputscale_poll_change() drains it with plain
 * xcb_poll_for_event(). The original shared-connection g_xcb (via
 * XGetXCBConnection(), used by inputscale_get_confine() below) is
 * untouched and still fine -- that one only ever does synchronous
 * request/reply, which was never the problem. */
#include "xispanel.h"

#include <X11/Xlib-xcb.h>
#include <xcb/xcb.h>
#include <xcb/xcbext.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#define XIS_EXTENSION_NAME "X-INPUT-SCALE"
#define X_XISGetCrtcConfine 2
#define X_XISSelectInput 4
#define XISConfineNotify 0
#define XISConfineNotifyMask (1 << XISConfineNotify)

static xcb_connection_t *g_xcb;
static uint8_t g_xis_opcode; /* 0 = extension absent */

/* Dedicated event connection -- see this file's doc comment. */
static xcb_connection_t *g_xis_event_conn;
static int g_xis_event_number; /* 0 = events unavailable (extension or event support absent on this server build) */

static unsigned send_ext_on(xcb_connection_t *conn, uint8_t major, const void *req, size_t len, int isvoid)
{
    struct iovec parts[4];
    xcb_protocol_request_t r = {.count = 2, .ext = NULL, .opcode = major, .isvoid = isvoid};
    parts[2].iov_base = (void *)req;
    parts[2].iov_len = len;
    parts[3].iov_base = NULL;
    parts[3].iov_len = (size_t)(-(ssize_t)len & 3);
    return xcb_send_request(conn, 0, parts + 2, &r);
}

void inputscale_init(void)
{
    g_xcb = XGetXCBConnection(g_dpy);
    if (!g_xcb) {
        return;
    }
    xcb_query_extension_cookie_t qc =
        xcb_query_extension(g_xcb, (uint16_t)strlen(XIS_EXTENSION_NAME), XIS_EXTENSION_NAME);
    xcb_query_extension_reply_t *qr = xcb_query_extension_reply(g_xcb, qc, NULL);
    if (!qr || !qr->present) {
        free(qr);
        return;
    }
    g_xis_opcode = qr->major_opcode;
    free(qr);
    fprintf(stderr, "xispanel: X-INPUT-SCALE extension detected (per-output cursor confinement)\n");

    g_xis_event_conn = xcb_connect(NULL, NULL);
    if (!g_xis_event_conn || xcb_connection_has_error(g_xis_event_conn)) {
        fprintf(stderr, "xispanel: could not open a dedicated connection for X-INPUT-SCALE events -- falling back "
                        "to polling\n");
        g_xis_event_conn = NULL;
        return;
    }
    xcb_query_extension_cookie_t qc2 =
        xcb_query_extension(g_xis_event_conn, (uint16_t)strlen(XIS_EXTENSION_NAME), XIS_EXTENSION_NAME);
    xcb_query_extension_reply_t *qr2 = xcb_query_extension_reply(g_xis_event_conn, qc2, NULL);
    /* first_event < 64 (0 in practice) means this server build hasn't
     * allocated a real event number for the extension yet -- event 0 is
     * reserved (the wire discriminator for "this is an X error"), so
     * never select on it. */
    if (qr2 && qr2->present && qr2->first_event >= 64) {
        g_xis_event_number = qr2->first_event + XISConfineNotify;
        struct {
            uint8_t reqType, xisReqType;
            uint16_t length;
            uint32_t window;
            uint32_t eventMask;
        } req = {0};
        req.xisReqType = X_XISSelectInput;
        req.window = (uint32_t)g_root;
        req.eventMask = XISConfineNotifyMask;
        send_ext_on(g_xis_event_conn, qr2->major_opcode, &req, sizeof(req), 1);
        xcb_flush(g_xis_event_conn);
        fprintf(stderr, "xispanel: X-INPUT-SCALE live confinement-change events enabled\n");
    } else {
        fprintf(stderr, "xispanel: X-INPUT-SCALE server build has no event support yet -- falling back to polling\n");
        xcb_disconnect(g_xis_event_conn);
        g_xis_event_conn = NULL;
    }
    free(qr2);
}

int inputscale_fd(void)
{
    return g_xis_event_conn ? xcb_get_file_descriptor(g_xis_event_conn) : -1;
}

/* Drains every pending event on the dedicated event connection -- returns
 * 1 if at least one was an XISConfineNotify (any CRTC; the caller just
 * re-checks every panel's own output geometry, same reaction as the
 * polling fallback, rather than mapping a specific crtc back to a
 * specific output name here). Must actually drain (not just peek) so the
 * fd doesn't stay readable and spin select() -- the exact category of bug
 * that made the first attempt spin at 100% CPU. */
int inputscale_poll_change(void)
{
    if (!g_xis_event_conn) {
        return 0;
    }
    int changed = 0;
    xcb_generic_event_t *ev;
    while ((ev = xcb_poll_for_event(g_xis_event_conn)) != NULL) {
        if ((ev->response_type & 0x7f) == g_xis_event_number) {
            changed = 1;
        }
        free(ev);
    }
    return changed;
}

/* Mirrors xis-smoke-test.c's send_ext()/reply_ext() -- see that file for
 * why the iovec is built starting at parts+2 (xcb_send_request()'s own
 * bookkeeping owns parts[0]/[1] when ext == NULL). */
static void *xis_request_reply(const void *req, size_t len)
{
    struct iovec parts[4];
    xcb_protocol_request_t r = {.count = 2, .ext = NULL, .opcode = g_xis_opcode, .isvoid = 0};
    parts[2].iov_base = (void *)req;
    parts[2].iov_len = len;
    parts[3].iov_base = NULL;
    parts[3].iov_len = (size_t)(-(ssize_t)len & 3);
    unsigned seq = xcb_send_request(g_xcb, 0, parts + 2, &r);
    xcb_generic_error_t *err = NULL;
    void *rep = xcb_wait_for_reply(g_xcb, seq, &err);
    if (err) {
        free(err);
        free(rep);
        return NULL;
    }
    return rep;
}

int inputscale_get_confine(unsigned long crtc, int *out_x, int *out_y, int *out_w, int *out_h)
{
    if (!g_xis_opcode) {
        return 0;
    }
    struct {
        uint8_t reqType, xisReqType;
        uint16_t length;
        uint32_t crtc;
    } req = {0};
    req.xisReqType = X_XISGetCrtcConfine;
    req.crtc = (uint32_t)crtc;
    uint8_t *rep = xis_request_reply(&req, sizeof(req));
    if (!rep) {
        return 0;
    }
    /* Reply layout per inputscaleproto.h's xXISGetCrtcConfineReply: byte 1
     * = active, bytes 8-9/10-11/12-13/14-15 = x/y/width/height. */
    int active = rep[1];
    if (active) {
        int16_t *xy = (int16_t *)(void *)(rep + 8);
        uint16_t *wh = (uint16_t *)(void *)(rep + 12);
        if (out_x) {
            *out_x = xy[0];
        }
        if (out_y) {
            *out_y = xy[1];
        }
        if (out_w) {
            *out_w = wh[0];
        }
        if (out_h) {
            *out_h = wh[1];
        }
    }
    free(rep);
    return active;
}
