/*
 * xisback_inputscale.c - X-INPUT-SCALE client query and live confinement-
 * change events. Adapted from xispanel/inputscale.c (see that file's doc
 * comment for the full story, including why XISConfineNotify uses its own
 * dedicated xcb_connect() instead of piggybacking on xisback's existing
 * Xlib connection) -- same wire protocol, this project's own experimental
 * server extension, not upstream/xorgproto:
 * /home/kiyoshi/Downloads/kiyoshi-forks/xserver/doc/
 * x11-per-output-scaling-extension.md
 *
 * Lets a compositor confine an output's usable desktop-space area, per
 * CRTC, to a sub-rectangle of that CRTC's raw physical scanout box (the
 * "logical" area it's actually drawing sharp HiDPI content into, when
 * that's smaller than the physical pixel count). xisback only ever reads
 * this (XISGetCrtcConfine) -- setting confinement is a compositor's job.
 * Used by resolve_output_geometry() in xisback.c so a per-output wallpaper
 * layer sizes itself to the output's actual usable box instead of its raw
 * CRTC size whenever the two differ, and re-renders live when that box
 * changes (a compositor toggling/resizing confinement doesn't itself
 * change the CRTC, so RRScreenChangeNotify never fires for it -- this is
 * the only way to find out short of polling).
 */
#include <X11/Xlib.h>
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

void xis_init(Display *dpy, Window root)
{
    g_xcb = XGetXCBConnection(dpy);
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
    fprintf(stderr, "xisback: X-INPUT-SCALE extension detected (per-output confinement)\n");

    g_xis_event_conn = xcb_connect(NULL, NULL);
    if (!g_xis_event_conn || xcb_connection_has_error(g_xis_event_conn)) {
        fprintf(stderr, "xisback: could not open a dedicated connection for X-INPUT-SCALE events -- "
                        "confinement changes will only be picked up on the next RandR change\n");
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
        req.window = (uint32_t)root;
        req.eventMask = XISConfineNotifyMask;
        send_ext_on(g_xis_event_conn, qr2->major_opcode, &req, sizeof(req), 1);
        xcb_flush(g_xis_event_conn);
        fprintf(stderr, "xisback: X-INPUT-SCALE live confinement-change events enabled\n");
    } else {
        fprintf(stderr, "xisback: X-INPUT-SCALE server build has no event support yet -- confinement changes "
                        "will only be picked up on the next RandR change\n");
        xcb_disconnect(g_xis_event_conn);
        g_xis_event_conn = NULL;
    }
    free(qr2);
}

int xis_fd(void)
{
    return g_xis_event_conn ? xcb_get_file_descriptor(g_xis_event_conn) : -1;
}

/* Drains every pending event on the dedicated event connection -- returns
 * 1 if at least one was an XISConfineNotify (any CRTC; the caller just
 * re-resolves every layer's geometry, same reaction either way, rather
 * than mapping a specific CRTC back to a specific layer here). Must
 * actually drain (not just peek) so the fd doesn't stay readable and spin
 * select(). */
int xis_poll_change(void)
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

int xis_get_confine(unsigned long crtc, int *out_x, int *out_y, int *out_w, int *out_h)
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
