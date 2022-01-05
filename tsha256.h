/*
 * tsha256 - A register based Secure Hashing Algorithm 2 implementation
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

#ifndef TSHA256
#define TSHA256

#define MESSAGE_SIZE_BYTES 64
#define MESSAGE_SIZE_WORDS MESSAGE_SIZE_BYTES/4
#define W_SIZE_WORDS 64 /* 48 message expansion words + 16 message words */
#define W_SIZE_BYTES W_SIZE_WORDS*4
#define DIGEST_SIZE_BITS 256
#define DIGEST_SIZE_BYTES DIGEST_SIZE_BITS/8
#define DIGEST_SIZE_WORDS DIGEST_SIZE_BITS/8/4
#define L_SIZE_BYTES 8
#define WORD_SIZE_BITS 32
#define WORD_SIZE_BYTES WORD_SIZE_BITS/8
#define N_LETTERS 8

#define TSHA256_FSM_INPUT		0
#define TSHA256_FSM_INPUT_UPDATE	1
#define TSHA256_FSM_APPEND_1BIT		2
#define TSHA256_FSM_APPEND_0_PADDING	3
#define TSHA256_FSM_APPEND_LENGTH	4
#define TSHA256_FSM_COMPLETE		5
#define TSHA256_FSM_ERROR		255

typedef unsigned char u8;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long int u64;
typedef long long int s64;
typedef unsigned __int128 u128;

#include "tsha256-x86_64.h"

/* For OOP */
struct tsha256 {
	u32 __attribute__ ((aligned (16))) digest[DIGEST_SIZE_WORDS]; /* todo resize in assembly module */
	u64 msglen;
	u32 i_message;
	u32 event;

#ifdef DEBUG
	u32 a;
	u32 b;
	u32 c;
	u32 d;
	u32 e;
	u32 f;
	u32 g;
	u32 h;
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
	u32 A[N_LETTERS];
	u8 W8[W_SIZE_BYTES];
	u32 sig0, sig1;
	u32 Ch, Maj, SIG0, SIG1, T1, T2;
#  endif // !USE_ASM
#endif // ALG_PLAIN
};

#ifdef ALG_PLAIN
u32 H_0[] = {
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
};

/* Faster than byteswap because of loop overhead and duplicate loops */
/* char[0] MSB when printing le u64 */
/* char[7] LSB when printing le u64 */
u32 seq[] = {
	3,  2,   1,  0,
	7,  6,   5,  4,
	11, 10,  9,  8,
	15, 14, 13, 12,
	19, 18, 17, 16,
	23, 22, 21, 20,
	27, 26, 25, 24,
	31, 30, 29, 28,
	35, 34, 33, 32,
	39, 38, 37, 36,
	43, 42, 41, 40,
	47, 46, 45, 44,
	51, 50, 49, 48,
	55, 54, 53, 52,
	59, 58, 57, 56,
	63, 62, 61, 60
};
/* End of sub-array index position: 56 57 58 59 60 61 62 63 */
/* 63 is lsb and 56 is msb */
u32 seq2[] = {
	60, 61, 62, 63, /* 63 is lsb.  60 is mid. */
	56, 57, 58, 59  /* 59 is mid.  56 is msb. */
};
#endif // ALG_PLAIN

#endif // TSHA256
