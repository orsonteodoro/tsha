/*
 * tsha-sha256r - A plain 512/256-bit Secure Hashing Algorithm 2 implementation (reference)
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

/*
   This implementation uses a finite state machine (FSM) to process
   each 512-block in one pass so that it doesn't dynamically
   preallocate a larger duplicate concat message array which will expose a
   password in a DMA attack.

   Created to understand the algorithm better primarly for the next version.
*/

/* This version is just converted from the 256 version */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

typedef unsigned char u8;
typedef int s32;
typedef long long int s64;
typedef unsigned long long int u64;
typedef long long int s64;
typedef unsigned __int128 u128;

#define LSIZE_BYTES 16
#define LSIZE_BITS 128
#define WSIZE_BYTES 8
#define WSIZE_BITS 64

#define NROUNDS 80
#define MSIZE_BYTES 128 // 16 * WSIZE_BYTES:8
#define NW 80

#define DIGEST_SIZE_BITS 512
#define DIGEST_SIZE_BYTES 64
#define DIGEST_SIZE_BYTES_TRUNCATED 32
#define DIGEST_SIZE_WORDS 8
#define DIGEST_SIZE_WORDS_TRUNCATED 4

#define SHA512T256_FSM_INPUT		0
#define SHA512T256_FSM_INPUT_UPDATE	1
#define SHA512T256_FSM_APPEND_1BIT	2
#define SHA512T256_FSM_APPEND_0_PADDING	3
#define SHA512T256_FSM_APPEND_LENGTH	4
#define SHA512T256_FSM_COMPLETE		5
#define SHA512T256_FSM_ERROR		255


/* For OOP */
struct tsha512 {
	u64 digest[DIGEST_SIZE_WORDS];
	u64 msglen;
	u64 i_message;
	u64 event;

#ifdef DEBUG
	u64 a;
	u64 b;
	u64 c;
	u64 d;
	u64 e;
	u64 f;
	u64 g;
	u64 h;

	u8 m0[16];  /* addr = 80 ; keep address aligned at 16 */
	u8 m1[16];
	u8 m2[16];
	u8 m3[16];
	u8 m4[16];
	u8 m5[16];
	u8 m6[16];
	u8 m7[16];
	u8 m8[16];
	u8 m9[16];
	u8 m10[16];
	u8 m11[16];
	u8 m12[16];
	u8 m13[16];
	u8 m14[16];
	u8 m15[16];
#endif

	u64 A[DIGEST_SIZE_WORDS];
	u8 W8[NW*WSIZE_BYTES]; /* 80 words * 8 bytes each = 640 bytes */
	u64 sig0, sig1;
	u64 Ch, Maj, SIG0, SIG1, T1, T2;
};

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

/* rotate right */
u64 ROTR(const u64 v, const u64 amt)
{
	return v >> amt | v << (WSIZE_BITS - amt);
}

#ifdef DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...)
#endif

u64 *plain_sha512t256_get_hashcode(struct tsha512 *state)
{
	return state->digest;
}

void plain_sha512t256_reset(struct tsha512 *state)
{
	memset(state, 0, sizeof(struct tsha512));

	dprintf("Init digest\n");
	memcpy(state->digest, H_0, DIGEST_SIZE_WORDS * WSIZE_BYTES);
}

void plain_sha512t256_close(struct tsha512 *state)
{
	/* Securely wipe sensitive data.  Especially if password is used as the
	   message.							      */
	memset(state, 0, sizeof(struct tsha512));
}

/* returns:
	<0 - error
	n - bytes read							      */
s32 plain_sha512t256_getch(struct tsha512 *state, u8 c)
{
	s32 ret = 0;


	if (state == NULL)
	{
		ret = -EINVAL;
		goto GETCH_DONE;
	}

	if (state->event != SHA512T256_FSM_INPUT)
		goto GETCH_DONE;

	if (state->i_message < MSIZE_BYTES) {
		state->W8[seq[state->i_message]] = c;
		state->i_message++;
		state->msglen++;
		ret = 1;
	} else {
		state->event = SHA512T256_FSM_INPUT_UPDATE;
	}

GETCH_DONE:
	return ret;
}

s32 _plain_sha512t256_complete_message_block(struct tsha512 *state) {
	u64 i; /* H index */
	u64 j; /* Expanded message index */
	u64 *W64;

	dprintf("Called _plain_sha512t256_complete_message_block\n");

	W64 = (u64*)state->W8;

#	define a state->A[0]
#	define b state->A[1]
#	define c state->A[2]
#	define d state->A[3]
#	define e state->A[4]
#	define f state->A[5]
#	define g state->A[6]
#	define h state->A[7]

#	define H0 state->digest[0]
#	define H1 state->digest[1]
#	define H2 state->digest[2]
#	define H3 state->digest[3]
#	define H4 state->digest[4]
#	define H5 state->digest[5]
#	define H6 state->digest[6]
#	define H7 state->digest[7]

#ifdef DEBUG
	dprintf("Message contents of W64:\n");
	for (j = 0; j < 16 ; j++)
	{
		if (j % 8 == 0)
			dprintf("\n");
		dprintf("%016llx ", W64[j]);
	}
	dprintf("\n");
#endif

	dprintf("Expanding message blocks\n");
	for (j = 16; j < NROUNDS; j++) {
		state->sig0 =	  ROTR(W64[j-15], 1)
				^ ROTR(W64[j-15], 8)
				^ (W64[j-15]  >>  7);
		state->sig1 = 	  ROTR(W64[j-2], 19)
				^ ROTR(W64[j-2], 61)
				^   (W64[j-2] >> 6);
		W64[j] = W64[j-16]
					+ state->sig0
					+ W64[j-7]
					+ state->sig1;
		if (j % 4 == 0)
			dprintf("\n");
		dprintf("%016llx ", W64[j]);
	}
	dprintf("\n");

	// init state
	a = H0; b = H1; c = H2; d = H3;
	e = H4; f = H5; g = H6; h = H7;

	for (j = 0; j < NROUNDS; j++)
	{
		state->Ch = (e & f) ^ ((~e) & g);
		state->Maj = (a & b) ^ (a & c) ^ (b & c);
		state->SIG0 = ROTR(a,28) ^ ROTR(a,34) ^ ROTR(a,39);
		state->SIG1 = ROTR(e,14) ^ ROTR(e,18) ^ ROTR(e,41);
		state->T1   =     h
				+ state->SIG1
				+ state->Ch
				+ K[j]
				+ W64[j];
		state->T2   = state->SIG0 + state->Maj;
		dprintf( "j-1=%lld Ch=%016llx Maj=%016llx SIG0=%016llx SIG1=%016llx T1=%016llx"
			" T2=%016llx h=%016llx K=%016llx W64=%016llx\n",
			j-1, state->Ch, state->Maj, state->SIG0,
			state->SIG1, state->T1, state->T2, h, K[j],
			W64[j]);

		dprintf("Hex values %lld:\n", j-1);
		dprintf("%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
			a, b, c, d, e, f, g, h);

		h = g;
		g = f;
		f = e;
		e = d + state->T1;
		d = c;
		c = b;
		b = a;
		a = state->T1 + state->T2;
	}

	dprintf("Updating intermediate hash values\n");
	H0 = a + H0; H1 = b + H1; H2 = c + H2; H3 = d + H3;
	H4 = e + H4; H5 = f + H5; H6 = g + H6; H7 = h + H7;

	dprintf("hex values %lld:\n", j-1);
	dprintf("%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n", a, b, c, d, e, f, g, h);

#ifdef DEBUG
	dprintf("\nDigest as in hex little endian:\n");
	for (i = 0; i < DIGEST_SIZE_WORDS; i++)
		dprintf("%016llx", state->digest[i]);
		dprintf("\n");
#endif

	dprintf("Called _plain_sha512t256_complete_message_block done\n");

	// process next
	state->i_message = 0;
	memset(state->W8, 0, MSIZE_BYTES);
}

void plain_sha512t256_update(struct tsha512 *state, u64 finish)
{
	dprintf("Called plain_sha512t256_update\n");


	if (finish == 1 || state->i_message >= MSIZE_BYTES)
	{
		dprintf("Message is ready.\n");
	}
	else
	{
		dprintf("Message is NOT ready.\n");
		return;
	}


	if (state->event == SHA512T256_FSM_INPUT)
	{
		dprintf("state->event == SHA512T256_FSM_INPUT\n");
		if (finish == 1)
		{
			dprintf("Finished reading\n");
			state->event = SHA512T256_FSM_INPUT_UPDATE;
		}
	}
	else if (state->event == SHA512T256_FSM_INPUT_UPDATE)
	{
		dprintf("state->event == SHA512T256_FSM_INPUT_UPDATE\n");
		if (finish == 1)
		{
			state->event = SHA512T256_FSM_APPEND_1BIT;
		}
		else
		{
			dprintf("Processing a message block before 1 bit.\n");
			_plain_sha512t256_complete_message_block(state);
			state->event = SHA512T256_FSM_INPUT;
		}
	}
	else if (state->event == SHA512T256_FSM_APPEND_1BIT)
	{
		dprintf("state->event == SHA512T256_FSM_APPEND_1BIT\n");
		if (state->i_message < MSIZE_BYTES) {
			dprintf("Added 0x80\n");
			state->W8[seq[state->i_message]] = (u8)0x80;
			state->i_message++;
			state->event = SHA512T256_FSM_APPEND_0_PADDING;
		} else {
			dprintf("1 bit does not fix.  Forcing update.\n");

			// Process this then add to the beginning.
			_plain_sha512t256_complete_message_block(state);

			dprintf("Added 0x80\n");
			state->W8[seq[state->i_message]] = (u8)0x80;
			state->i_message++;
			state->event = SHA512T256_FSM_APPEND_0_PADDING;
		}
	}
	else if (state->event == SHA512T256_FSM_APPEND_0_PADDING)
	{
		dprintf("state->event == SHA512T256_FSM_APPEND_0_PADDING\n");
		if (state->i_message < MSIZE_BYTES - LSIZE_BYTES) {
			dprintf("Filling padding to and including i=MSIZE_BYTES:128-LSIZE_BYTES:16-1=111\n");
			state->event = SHA512T256_FSM_APPEND_LENGTH;
		} else {
			dprintf("L does not fix.  Forcing update.\n");

			// Process this then add to the beginning.
			_plain_sha512t256_complete_message_block(state);

			state->event = SHA512T256_FSM_APPEND_0_PADDING;
		}
	}
	else if (state->event == SHA512T256_FSM_APPEND_LENGTH) {
		dprintf("state->event == SHA512T256_FSM_APPEND_LENGTH\n");
		if (state->i_message < MSIZE_BYTES - LSIZE_BYTES) {
			/* space check: 112 = MSIZE_BYTES:128 - LSIZE_BYTES:16 */
			dprintf("Message length:\n");
			/* gets message length */
			u8 len8[LSIZE_BYTES];
			u128 *len128 = (u128*)len8;
			u64 i;

			/* msglen doesn't require inc */

			*len128 = state->msglen*8;
			dprintf("%016llx%016llx\n", (u64)((*len128)>>64), (u64)(*len128));

			for (i = 0; i < LSIZE_BYTES; i++){
				dprintf("Printing %lld %d\n", i,
					len8[i]);
				state->W8[seq2[i]] = len8[i];
			}
			dprintf("Hash is ready\n");
			_plain_sha512t256_complete_message_block(state);

			dprintf("state->event == SHA512T256_FSM_COMPLETE\n");
			state->event = SHA512T256_FSM_COMPLETE;
		} else {
			dprintf("Expected state->i_message < MSIZE_BYTES - LSIZE_BYTES\n");
			state->event = SHA512T256_FSM_ERROR;
		}
	} else {
		state->event = SHA512T256_FSM_ERROR;
	}

	return;
}

s32 run_tests() {
	u64 digest[DIGEST_SIZE_WORDS];
	s32 ret;
	u64 failed = 0;
	struct tsha512 __attribute__ ((aligned (16))) state;

#	define NTESTS 3

	struct TEST_CASES
	{
		const u8 *description;
		const u8 *message;
		u64 bytes;
		u64 *expected_digest;
	} test_cases[NTESTS];


	test_cases[0].description = "Empty string test";
	test_cases[0].message = "";
	test_cases[0].bytes = 0;
	u64 t0[8] = {0xc672b8d1ef56ed28, 0xab87c3622c511406,
		     0x9bdd3ad7b8f97374, 0x98d0c01ecef0967a};
	test_cases[0].expected_digest = t0;

	test_cases[1].description = "1 block, 3 char message test";
	test_cases[1].message = "abc";
	test_cases[1].bytes = 3;
	u64 t1[8] = {0x53048e2681941ef9, 0x9b2e29b76b4c7dab,
		     0xe4c2d0c634fc6d46, 0xe0e2f13107e7af23};
	test_cases[1].expected_digest = t1;

	test_cases[2].description = "2 block, 112 char message test";
	test_cases[2].message =
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghij"
		"klmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrst"
		"nopqrstu";
	test_cases[2].bytes = 112;
	u64 t2[8] = { 0x3928e184fb8690f8, 0x40da3988121d31be,
		      0x65cb9d3ef83ee614, 0x6feac861e19b563a};
	test_cases[2].expected_digest = t2;

	for (u64 i_test = 0 ; i_test < NTESTS ; i_test++)
	{
		dprintf("#### start test ####\n");
		const u8 *description = test_cases[i_test].description;
		const u8 *message = test_cases[i_test].message;
		const u64 *expected_digest = test_cases[i_test].expected_digest;
		const u64 bytes = test_cases[i_test].bytes;
		s32 i;

		dprintf("%s\n",description);

		plain_sha512t256_reset(&state);

		i = 0;
		while (i < bytes)
		{
			s32 bytes_read = 0;
			bytes_read = plain_sha512t256_getch(&state, message[i]);

			if (bytes_read < 0)
			{
				plain_sha512t256_close(&state);
				ret = -EINVAL;
				goto DONE_RT;
			}

			i += bytes_read;

			if (state.event == SHA512T256_FSM_INPUT_UPDATE)
				plain_sha512t256_update(&state, 0);
		}
		do {
			plain_sha512t256_update(&state, 1);
		} while (state.event != SHA512T256_FSM_COMPLETE
			&& state.event != SHA512T256_FSM_ERROR);
		u64 *hashcode = plain_sha512t256_get_hashcode(&state);
		memcpy(digest, hashcode, DIGEST_SIZE_BYTES);
		plain_sha512t256_close(&state);

		dprintf("Message as hex:\n");
		for (i = 0; i < bytes; i++)
			dprintf("%02x", message[i]);
		dprintf("\n");

		dprintf("Message as in characters: (len = %lld)\n", bytes);
		for (i = 0; i < bytes; i++)
			dprintf("%c", message[i]);
		dprintf("\n");

		dprintf("Digest as hex:\n");
		// only the 1st 4 since truncated
		for (i = 0; i < DIGEST_SIZE_WORDS_TRUNCATED; i++)
			dprintf("%016llx", digest[i]);
		dprintf("\n");

		dprintf("Expected digest as hex:\n");
		// only the 1st 4 since truncated
		for (i = 0; i < DIGEST_SIZE_WORDS_TRUNCATED; i++)
			dprintf("%016llx", expected_digest[i]);
		dprintf("\n");

		dprintf("\n");
		s32 result = memcmp(expected_digest, digest, DIGEST_SIZE_BYTES_TRUNCATED);
		if (result == 0)
			dprintf("Pass\n");
		else
			dprintf("Failed\n");
		dprintf("---\n");
		failed |= result;
		dprintf("#### end test ####\n");
	}

DONE_RT:

	return failed;
}

s32 get_hash_argv(s32 argc, char *argv[])
{
	struct tsha512 __attribute__ ((aligned (16))) state;

	s32 ret;
	s64 i;
	s64 bytes;
	u64 digest[DIGEST_SIZE_WORDS];

	if (argc)
	if (argc == 2) {
		bytes = strlen(argv[1]);
		plain_sha512t256_reset(&state);
		i = 0;
		while (i < bytes)
		{
			s64 bytes_read = 0;
			bytes_read = plain_sha512t256_getch(&state, argv[1][i]);
			if (bytes_read < 0)
			{
				plain_sha512t256_close(&state);
				ret = -EINVAL;
				goto DONE_ARGV;
			}

			i += bytes_read;

			if (state.event == SHA512T256_FSM_INPUT_UPDATE)
				plain_sha512t256_update(&state,0);
		}
		do {
			plain_sha512t256_update(&state,1);
		} while (state.event != SHA512T256_FSM_COMPLETE
			&& state.event != SHA512T256_FSM_ERROR);
		u64 *hashcode = plain_sha512t256_get_hashcode(&state);
		memcpy(digest, hashcode, DIGEST_SIZE_BYTES);
		plain_sha512t256_close(&state);
		for (i = 0; i < DIGEST_SIZE_WORDS ; i++)
			dprintf("%016llx", digest[i]);
	}

DONE_ARGV:

	return ret;
}

s32 main(s32 argc, char *argv[])
{
#ifdef DEBUG
	return run_tests();
#else
	get_hash_argv(argc, argv);
#endif
}
