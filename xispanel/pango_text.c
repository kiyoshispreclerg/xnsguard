/*
 * pango_text.c - Pango-backed text drawing, exploratory replacement for
 * the raw cairo_show_text()/cairo_text_extents() "toy font API" the rest
 * of the codebase still uses.
 *
 * Why: Cairo's toy font API renders through a single FreeType face with
 * no font-fallback of its own -- a codepoint missing from the system's
 * configured font (e.g. any CJK glyph in a decorative Latin font) just
 * doesn't draw. It also has no concept of ellipsizing itself; this
 * codebase's own trim_to_width() (ewmh.c) reimplements that by hand, one
 * removed codepoint at a time. Pango does per-glyph font substitution
 * (via the same Fontconfig database already linked) and has ellipsizing
 * built into PangoLayout, so migrating a call site to this replaces both
 * a manual truncation loop *and* the missing-glyph problem at once.
 *
 * Experiment (see branch xispanel-plus-pango): pulls Pango, and
 * transitively GLib, into xispanel's own process for the first time -- a
 * real departure from the "no toolkit" design this project otherwise
 * keeps to -- so this stays on its own branch until it's proven both
 * correct and not a regression (CPU/memory) before merging.
 */
#include "xispanel.h"

#include <pango/pangocairo.h>

static PangoFontDescription *g_desc = NULL;

void pango_text_init(const char *family)
{
    if (g_desc) {
        pango_font_description_free(g_desc);
    }
    g_desc = pango_font_description_new();
    pango_font_description_set_family(g_desc, family && family[0] ? family : "sans-serif");
}

/* Shared setup for both the measuring and drawing entry points below --
 * a PangoLayout carrying `text` at `size_px`, ellipsized to max_width_px
 * if positive. Caller owns the returned layout (g_object_unref() it). */
static PangoLayout *build_layout(cairo_t *cr, const char *text, double size_px, double max_width_px)
{
    pango_font_description_set_absolute_size(g_desc, size_px * PANGO_SCALE);
    PangoLayout *layout = pango_cairo_create_layout(cr);
    pango_layout_set_font_description(layout, g_desc);
    pango_layout_set_single_paragraph_mode(layout, TRUE);
    if (max_width_px > 0) {
        pango_layout_set_width(layout, (int)(max_width_px * PANGO_SCALE));
        pango_layout_set_ellipsize(layout, PANGO_ELLIPSIZE_END);
    }
    pango_layout_set_text(layout, text, -1);
    return layout;
}

/* Measures `text` as it would be rendered at `size_px` -- including
 * ellipsizing to max_width_px first, if positive -- without drawing
 * anything. Used ahead of a draw call when the caller needs the final
 * (possibly-ellipsized) pixel size to position the text itself (e.g.
 * centering), since that isn't known until the layout is built. `cr`
 * only supplies font-rendering options (antialiasing etc.); a throwaway
 * probe surface's cr works fine, same as this codebase's existing
 * probe_cr pattern for cairo_text_extents(). */
void pango_text_extents_ellipsized(cairo_t *cr, const char *text, double size_px, double max_width_px, double *out_w,
                                    double *out_h)
{
    PangoLayout *layout = build_layout(cr, text, size_px, max_width_px);
    int lw, lh;
    pango_layout_get_pixel_size(layout, &lw, &lh);
    if (out_w) {
        *out_w = lw;
    }
    if (out_h) {
        *out_h = lh;
    }
    g_object_unref(layout);
}

/* Draws `text` (any valid UTF-8, no manual truncation needed -- Pango
 * handles glyph fallback and, when max_width_px > 0, ellipsizing on its
 * own) at `x`, vertically centered within [top_y, top_y+box_h). Reports
 * the rendered pixel width via *out_w (NULL if not needed, e.g. when the
 * caller doesn't need to know how much room the text actually used, or
 * already got it from pango_text_extents_ellipsized() to position `x`
 * itself for centering). */
void pango_show_text_boxed(cairo_t *cr, double x, double top_y, double box_h, double max_width_px, double size_px,
                            const char *text, double *out_w)
{
    PangoLayout *layout = build_layout(cr, text, size_px, max_width_px);
    int lw, lh;
    pango_layout_get_pixel_size(layout, &lw, &lh);
    if (out_w) {
        *out_w = lw;
    }
    cairo_move_to(cr, x, top_y + (box_h - lh) / 2.0);
    pango_cairo_show_layout(cr, layout);
    g_object_unref(layout);
}
