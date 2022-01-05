/*
 * tsha512/256 - A register only implementation for SHA2-512/256
 *
 * Copyright (c) 2021-2022 Orson Teodoro <orsonteodoro@hotmail.com>.  All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef MAIN_TSHA512T256
#define MAIN_TSHA512T256

//#define USE_ASM
#define ALG_PLAIN
//#define ALG_ASM

#define MESSAGE_SIZE_BYTES 128
#define MESSAGE_SIZE_WORDS MESSAGE_SIZE_BYTES/8
#define W_SIZE_WORDS 16 /* 16 message words for viewport.  The viewport is the
			/* number of words required to calculate both message
			   expansion and compression at the same time and to
			   contain the entire message block. */

#define W_SIZE_BYTES W_SIZE_WORDS*8
#define DIGEST_SIZE_BITS 256
#define DIGEST_SIZE_BYTES DIGEST_SIZE_BITS/8
#define DIGEST_SIZE_WORDS DIGEST_SIZE_BITS/8/8
#define L_SIZE_BYTES 16
#define WORD_SIZE_BITS 64
#define WORD_SIZE_BYTES WORD_SIZE_BITS/8
#define N_LETTERS 8

#define SHA256T_FSM_INPUT		0
#define SHA256T_FSM_INPUT_UPDATE	1
#define SHA256T_FSM_APPEND_1BIT		2
#define SHA256T_FSM_APPEND_0_PADDING	3
#define SHA256T_FSM_APPEND_LENGTH	4
#define SHA256T_FSM_COMPLETE		5
#define SHA256T_FSM_ERROR		255

typedef unsigned char u8;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long int u64;
typedef long long int s64;
typedef unsigned __int128 u128;

#include "tsha512t256-x86_64.h"

#ifdef ALG_PLAIN

u64 K[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };

u64 H_0[] = {
	0x22312194fc2bf72c,
	0x9f555fa3c84c64c2,
	0x2393b86b6f53b151,
	0x963877195940eabd,
	0x96283ee2a88effe3,
	0xbe5e1e2553863992,
	0x2b0199fc2c85b8aa,
	0x0eb72ddc81c52ca2
};

/* Faster than byteswap because of loop overhead and duplicate loops */
/* char[0] MSB when printing le u64 */
/* char[7] LSB when printing le u64 */
u64 seq[] = {
	 7,  6,  5,  4,  3,  2,  1,  0,
	15, 14, 13, 12, 11, 10,  9,  8,
	23, 22, 21, 20, 19, 18, 17, 16,
	31, 30, 29, 28, 27, 26, 25, 24,
	39, 38, 37, 36, 35, 34, 33, 32,
	47, 46, 45, 44, 43, 42, 41, 40,
	55, 54, 53, 52, 51, 50, 49, 48,
	63, 62, 61, 60, 59, 58, 57, 56,
	71, 70, 69, 68, 67, 66, 65, 64,
	79, 78, 77, 76, 75, 74, 73, 72,
	87, 86, 85, 84, 83, 82, 81, 80,
	95, 94, 93, 92, 91, 90, 89, 88,
	103, 102, 101, 100, 99, 98, 97, 96,
	111, 110, 109, 108, 107, 106, 105, 104,
	119, 118, 117, 116, 115, 114, 113, 112,
	127, 126, 125, 124, 123, 122, 121, 120
};
/* End of sub-array index position: 56 57 58 59 60 61 62 63 */
/* 63 is lsb and 56 is msb */
u64 seq2[] = {
	120, 121, 122, 123, 124, 125, 126, 127,   /* 127 is msb, 120 is mid */
	112, 113, 114, 115, 116, 117, 118, 119   /* 119 is mid. 112 is msb */
};

#endif // ALG_PLAIN


/* For OOP */
struct tsha512 {
	u64 __attribute__ ((aligned (16))) digest[N_LETTERS*WORD_SIZE_BYTES];
	u64 msglen;
	u64 i_message;
	u32 event;

#ifdef DEBUG
	u64 a;
	u64 b;
	u64 c;
	u64 d;
	u64 e;
	u64 f;
	u64 g;
	u64 h;
	u8 __attribute__ ((aligned (16))) m0[16];
	u8 __attribute__ ((aligned (16))) m1[16];
	u8 __attribute__ ((aligned (16))) m2[16];
	u8 __attribute__ ((aligned (16))) m3[16];
	u8 __attribute__ ((aligned (16))) m4[16];
	u8 __attribute__ ((aligned (16))) m5[16];
	u8 __attribute__ ((aligned (16))) m6[16];
	u8 __attribute__ ((aligned (16))) m7[16];
	u8 __attribute__ ((aligned (16))) m8[16];
	u8 __attribute__ ((aligned (16))) m9[16];
	u8 __attribute__ ((aligned (16))) m10[16];
	u8 __attribute__ ((aligned (16))) m11[16];
	u8 __attribute__ ((aligned (16))) m12[16];
	u8 __attribute__ ((aligned (16))) m13[16];
	u8 __attribute__ ((aligned (16))) m14[16];
	u8 __attribute__ ((aligned (16))) m15[16];
#endif // DEBUG

#ifdef ALG_PLAIN
#  ifndef USE_ASM
	u64 A[N_LETTERS];
	u8 W8[W_SIZE_BYTES];
	u64 sig0, sig1;
	u64 Ch, Maj, SIG0, SIG1, T1, T2;
#  endif // USE_ASM
#endif // ALG_PLAIN
};

#endif // MAIN_TSHA512T256
