/*
 * Copyright (C) 1999-2002, 2016 Free Software Foundation, Inc.
 * This file is part of the GNU LIBICONV Library.
 *
 * The GNU LIBICONV Library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * The GNU LIBICONV Library is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with the GNU LIBICONV Library; see the file COPYING.LIB.
 * If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * CP737
 */

static const unsigned short cp737_2uni[128] = {
    /* 0x80 */
    0x0391,
    0x0392,
    0x0393,
    0x0394,
    0x0395,
    0x0396,
    0x0397,
    0x0398,
    0x0399,
    0x039a,
    0x039b,
    0x039c,
    0x039d,
    0x039e,
    0x039f,
    0x03a0,
    /* 0x90 */
    0x03a1,
    0x03a3,
    0x03a4,
    0x03a5,
    0x03a6,
    0x03a7,
    0x03a8,
    0x03a9,
    0x03b1,
    0x03b2,
    0x03b3,
    0x03b4,
    0x03b5,
    0x03b6,
    0x03b7,
    0x03b8,
    /* 0xa0 */
    0x03b9,
    0x03ba,
    0x03bb,
    0x03bc,
    0x03bd,
    0x03be,
    0x03bf,
    0x03c0,
    0x03c1,
    0x03c3,
    0x03c2,
    0x03c4,
    0x03c5,
    0x03c6,
    0x03c7,
    0x03c8,
    /* 0xb0 */
    0x2591,
    0x2592,
    0x2593,
    0x2502,
    0x2524,
    0x2561,
    0x2562,
    0x2556,
    0x2555,
    0x2563,
    0x2551,
    0x2557,
    0x255d,
    0x255c,
    0x255b,
    0x2510,
    /* 0xc0 */
    0x2514,
    0x2534,
    0x252c,
    0x251c,
    0x2500,
    0x253c,
    0x255e,
    0x255f,
    0x255a,
    0x2554,
    0x2569,
    0x2566,
    0x2560,
    0x2550,
    0x256c,
    0x2567,
    /* 0xd0 */
    0x2568,
    0x2564,
    0x2565,
    0x2559,
    0x2558,
    0x2552,
    0x2553,
    0x256b,
    0x256a,
    0x2518,
    0x250c,
    0x2588,
    0x2584,
    0x258c,
    0x2590,
    0x2580,
    /* 0xe0 */
    0x03c9,
    0x03ac,
    0x03ad,
    0x03ae,
    0x03ca,
    0x03af,
    0x03cc,
    0x03cd,
    0x03cb,
    0x03ce,
    0x0386,
    0x0388,
    0x0389,
    0x038a,
    0x038c,
    0x038e,
    /* 0xf0 */
    0x038f,
    0x00b1,
    0x2265,
    0x2264,
    0x03aa,
    0x03ab,
    0x00f7,
    0x2248,
    0x00b0,
    0x2219,
    0x00b7,
    0x221a,
    0x207f,
    0x00b2,
    0x25a0,
    0x00a0,
};

static int cp737_mbtowc(conv_t conv, ucs4_t *pwc, const unsigned char *s, size_t n)
{
    unsigned char c = *s;
    if (c < 0x80)
        *pwc = (ucs4_t)c;
    else
        *pwc = (ucs4_t)cp737_2uni[c - 0x80];
    return 1;
}

static const unsigned char cp737_page00[24] = {
    0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0xa0-0xa7 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0xa8-0xaf */
    0xf8, 0xf1, 0xfd, 0x00, 0x00, 0x00, 0x00, 0xfa, /* 0xb0-0xb7 */
};
static const unsigned char cp737_page03[80] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xea, 0x00, /* 0x80-0x87 */
    0xeb, 0xec, 0xed, 0x00, 0xee, 0x00, 0xef, 0xf0, /* 0x88-0x8f */
    0x00, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, /* 0x90-0x97 */
    0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, /* 0x98-0x9f */
    0x8f, 0x90, 0x00, 0x91, 0x92, 0x93, 0x94, 0x95, /* 0xa0-0xa7 */
    0x96, 0x97, 0xf4, 0xf5, 0xe1, 0xe2, 0xe3, 0xe5, /* 0xa8-0xaf */
    0x00, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, /* 0xb0-0xb7 */
    0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, /* 0xb8-0xbf */
    0xa7, 0xa8, 0xaa, 0xa9, 0xab, 0xac, 0xad, 0xae, /* 0xc0-0xc7 */
    0xaf, 0xe0, 0xe4, 0xe8, 0xe6, 0xe7, 0xe9, 0x00, /* 0xc8-0xcf */
};
static const unsigned char cp737_page22[80] = {
    0x00, 0xf9, 0xfb, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x18-0x1f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x20-0x27 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x28-0x2f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x30-0x37 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x38-0x3f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x40-0x47 */
    0xf7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x48-0x4f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x50-0x57 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x58-0x5f */
    0x00, 0x00, 0x00, 0x00, 0xf3, 0xf2, 0x00, 0x00, /* 0x60-0x67 */
};
static const unsigned char cp737_page25[168] = {
    0xc4, 0x00, 0xb3, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x00-0x07 */
    0x00, 0x00, 0x00, 0x00, 0xda, 0x00, 0x00, 0x00, /* 0x08-0x0f */
    0xbf, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, /* 0x10-0x17 */
    0xd9, 0x00, 0x00, 0x00, 0xc3, 0x00, 0x00, 0x00, /* 0x18-0x1f */
    0x00, 0x00, 0x00, 0x00, 0xb4, 0x00, 0x00, 0x00, /* 0x20-0x27 */
    0x00, 0x00, 0x00, 0x00, 0xc2, 0x00, 0x00, 0x00, /* 0x28-0x2f */
    0x00, 0x00, 0x00, 0x00, 0xc1, 0x00, 0x00, 0x00, /* 0x30-0x37 */
    0x00, 0x00, 0x00, 0x00, 0xc5, 0x00, 0x00, 0x00, /* 0x38-0x3f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x40-0x47 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x48-0x4f */
    0xcd, 0xba, 0xd5, 0xd6, 0xc9, 0xb8, 0xb7, 0xbb, /* 0x50-0x57 */
    0xd4, 0xd3, 0xc8, 0xbe, 0xbd, 0xbc, 0xc6, 0xc7, /* 0x58-0x5f */
    0xcc, 0xb5, 0xb6, 0xb9, 0xd1, 0xd2, 0xcb, 0xcf, /* 0x60-0x67 */
    0xd0, 0xca, 0xd8, 0xd7, 0xce, 0x00, 0x00, 0x00, /* 0x68-0x6f */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x70-0x77 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x78-0x7f */
    0xdf, 0x00, 0x00, 0x00, 0xdc, 0x00, 0x00, 0x00, /* 0x80-0x87 */
    0xdb, 0x00, 0x00, 0x00, 0xdd, 0x00, 0x00, 0x00, /* 0x88-0x8f */
    0xde, 0xb0, 0xb1, 0xb2, 0x00, 0x00, 0x00, 0x00, /* 0x90-0x97 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x98-0x9f */
    0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0xa0-0xa7 */
};

static int cp737_wctomb(conv_t conv, unsigned char *r, ucs4_t wc, size_t n)
{
    unsigned char c = 0;
    if (wc < 0x0080) {
        *r = wc;
        return 1;
    } else if (wc >= 0x00a0 && wc < 0x00b8)
        c = cp737_page00[wc - 0x00a0];
    else if (wc == 0x00f7)
        c = 0xf6;
    else if (wc >= 0x0380 && wc < 0x03d0)
        c = cp737_page03[wc - 0x0380];
    else if (wc == 0x207f)
        c = 0xfc;
    else if (wc >= 0x2218 && wc < 0x2268)
        c = cp737_page22[wc - 0x2218];
    else if (wc >= 0x2500 && wc < 0x25a8)
        c = cp737_page25[wc - 0x2500];
    if (c != 0) {
        *r = c;
        return 1;
    }
    return RET_ILUNI;
}
