/*
 * tsha256r - A plain 256-bit Secure Hashing Algorithm 2 implementation (register)
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

/* Completion Time < 24 hours for working version 1. */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef int s32;
typedef unsigned long long int u64;
typedef unsigned __int128 u128;

#define LSIZE_BYTES 8
#define LSIZE_BITS 64
#define WSIZE_BYTES 4
#define WSIZE_BITS 32

#define NROUNDS 64
#define MSIZE_BYTES 64 // 16 * WSIZE_BYTES:4
#define NW 64

#define DIGEST_SIZE_BITS 256
#define DIGEST_SIZE_BYTES 32
#define DIGEST_SIZE_WORDS 8

#define SHA256B_FSM_INPUT		0
#define SHA256B_FSM_INPUT_UPDATE	1
#define SHA256B_FSM_APPEND_1BIT		2
#define SHA256B_FSM_APPEND_0_PADDING	3
#define SHA256B_FSM_APPEND_LENGTH	4
#define SHA256B_FSM_COMPLETE		5
#define SHA256B_FSM_ERROR		255


/* For OOP */
struct tsha256 {
	u32 digest[DIGEST_SIZE_WORDS];
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

	u32 A[DIGEST_SIZE_WORDS];
	u8 W8[NW*WSIZE_BYTES]; /* 64 words * 4 bytes each = 256 bytes */
	u32 sig0, sig1;
	u32 Ch, Maj, SIG0, SIG1, T1, T2;
};

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

u32 K[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786,	0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147,	0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b,	0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a,	0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// char[0] MSB when printing le u64
// char[7] LSB when printing le u64
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
// End of sub-array index position: 56 57 58 59 60 61 62 63
u32 seq2[] = {
	60, 61, 62, 63,
	56, 57, 58, 59
};


/* rotate right */
#if defined(__GNUC__) || defined(__clang__)
#define ROTR(v, amt) \
	__rord(v, amt)
#else
u32 ROTR(const u32 v, const u32 amt)
{
	return v >> amt | v << (WSIZE_BITS - amt);
}
#endif

#ifdef DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...)
#endif

u32 *tsha256r_get_hashcode(struct tsha256 *state)
{
	return state->digest;
}

void tsha256r_reset(struct tsha256 *state)
{
	memset(state, 0, sizeof(struct tsha256));

	dprintf("Init digest\n");
	memcpy(state->digest, H_0, DIGEST_SIZE_BYTES);
}

void tsha256r_close(struct tsha256 *state)
{
	/* Securely wipe sensitive data.  Especially if password is used as the
	   message.							      */
	memset(state, 0, sizeof(struct tsha256));
}

/* returns:
	<0 - error
	n - bytes read							      */
s32 tsha256r_getch(struct tsha256 *state, u8 c)
{
	s32 ret = 0;


	if (state == NULL)
	{
		ret = -EINVAL;
		goto GETCH_DONE;
	}

	if (state->event != SHA256B_FSM_INPUT)
		goto GETCH_DONE;

	if (state->i_message < MSIZE_BYTES) {
		state->W8[seq[state->i_message]] = c;
		state->i_message++;
		state->msglen++;
		ret = 1;
	} else {
		state->event = SHA256B_FSM_INPUT_UPDATE;
	}

GETCH_DONE:
	return ret;
}

s32 _tsha256r_complete_message_block(struct tsha256 *state) {
	u32 i; /* H index */
	u32 j; /* Expanded message index */
	u32 *W32;

	dprintf("Called _tsha256r_complete_message_block\n");

	W32 = (u32*)state->W8;

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
	dprintf("Message contents of W32:\n");
	for (j = 0; j < 16 ; j++)
	{
		if (j % 8 == 0)
			dprintf("\n");
		dprintf("%08x ", W32[j]);
	}
	dprintf("\n");
#endif

	dprintf("Expanding message blocks\n");
	for (j = 16; j < NROUNDS; j++) {
		state->sig0 =	  ROTR(W32[j-15], 7)
				^ ROTR(W32[j-15], 18)
				^ (W32[j-15]  >>  3);
		state->sig1 = 	  ROTR(W32[j-2], 17)
				^ ROTR(W32[j-2], 19)
				^   (W32[j-2] >> 10);
		W32[j] = W32[j-16]
					+ state->sig0
					+ W32[j-7]
					+ state->sig1;
		if (j % 4 == 0)
			dprintf("\n");
		dprintf("%08x ", W32[j]);
	}
	dprintf("\n");

	// init state
	a = H0; b = H1; c = H2; d = H3;
	e = H4; f = H5; g = H6; h = H7;

	for (j = 0; j < NROUNDS; j++)
	{
		state->Ch = (e & f) ^ ((~e) & g);
		state->Maj = (a & b) ^ (a & c) ^ (b & c);
		state->SIG0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
		state->SIG1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
		state->T1   =     h
				+ state->SIG1
				+ state->Ch
				+ K[j]
				+ W32[j];
		state->T2   = state->SIG0 + state->Maj;
		dprintf( "j-1=%d Ch=%08x Maj=%08x SIG0=%08x SIG1=%08x T1=%08x"
			" T2=%08x h=%08x K=%08x W32=%08x\n",
			j-1, state->Ch, state->Maj, state->SIG0,
			state->SIG1, state->T1, state->T2, h, K[j],
			W32[j]);

		dprintf("Hex values %d:\n", j-1);
		dprintf("%08x %08x %08x %08x %08x %08x %08x %08x\n",
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

	dprintf("hex values %d:\n", j-1);
	dprintf("%08x %08x %08x %08x %08x %08x %08x %08x\n", a, b, c, d, e, f, g, h);

#ifdef DEBUG
	dprintf("\nDigest as in hex little endian:\n");
	for (i = 0; i < DIGEST_SIZE_WORDS; i++)
		dprintf("%08x", state->digest[i]);
		dprintf("\n");
#endif

	dprintf("Called _tsha256r_complete_message_block done\n");

	// process next
	state->i_message = 0;
	memset(state->W8, 0, MSIZE_BYTES);
}

s32 tsha256r_update(struct tsha256 *state, u32 finish)
{
	dprintf("Called tsha256r_update\n");


	if (finish == 1 || state->i_message >= MSIZE_BYTES)
	{
		dprintf("Message is ready.\n");
	}
	else
	{
		dprintf("Message is NOT ready.\n");
		return 0;
	}


	if (state->event == SHA256B_FSM_INPUT)
	{
		dprintf("state->event == SHA256B_FSM_INPUT\n");
		if (finish == 1)
		{
			dprintf("Finished reading\n");
			state->event = SHA256B_FSM_INPUT_UPDATE;
		}
	}
	else if (state->event == SHA256B_FSM_INPUT_UPDATE)
	{
		dprintf("state->event == SHA256B_FSM_INPUT_UPDATE\n");
		if (finish == 1)
		{
			state->event = SHA256B_FSM_APPEND_1BIT;
		}
		else
		{
			dprintf("Processing a message block before 1 bit.\n");
			_tsha256r_complete_message_block(state);
			state->event = SHA256B_FSM_INPUT;
		}
	}
	else if (state->event == SHA256B_FSM_APPEND_1BIT)
	{
		dprintf("state->event == SHA256B_FSM_APPEND_1BIT\n");
		if (state->i_message < MSIZE_BYTES) {
			dprintf("Added 0x80\n");
			state->W8[seq[state->i_message]] = (u8)0x80;
			state->i_message++;
			state->event = SHA256B_FSM_APPEND_0_PADDING;
		} else {
			dprintf("1 bit does not fix.  Forcing update.\n");

			// Process this then add to the beginning.
			_tsha256r_complete_message_block(state);

			dprintf("Added 0x80\n");
			state->W8[seq[state->i_message]] = (u8)0x80;
			state->i_message++;
			state->event = SHA256B_FSM_APPEND_0_PADDING;
		}
	}
	else if (state->event == SHA256B_FSM_APPEND_0_PADDING)
	{
		dprintf("state->event == SHA256B_FSM_APPEND_0_PADDING\n");
		if (state->i_message < MSIZE_BYTES - LSIZE_BYTES) {
			dprintf("Filling padding to i=MSIZE_BYTES:64-LSIZE_BYTES:8-1=55\n");
			state->event = SHA256B_FSM_APPEND_LENGTH;
		} else {
			dprintf("L does not fix.  Forcing update.\n");

			// Process this then add to the beginning.
			_tsha256r_complete_message_block(state);

			state->event = SHA256B_FSM_APPEND_0_PADDING;
		}
	}
	else if (state->event == SHA256B_FSM_APPEND_LENGTH) {
		dprintf("state->event == SHA256B_FSM_APPEND_LENGTH\n");
		if (state->i_message < MSIZE_BYTES - LSIZE_BYTES) {
			/* space check: 56 = MSIZE_BYTES - LSIZE_BYTES */
			dprintf("Message length:\n");
			/* gets message length */
			u8 len8[LSIZE_BYTES];
			u64 *len64 = (u64*)len8;
			u32 i;

			/* msglen doesn't require inc */

			*len64 = state->msglen*8;
			dprintf("%016llx\n", *len64);

			for (i = 0; i < LSIZE_BYTES; i++){
				dprintf("Printing %d %d\n", i,
					len8[i]);
				state->W8[seq2[i]] = len8[i];
			}
			dprintf("Hash is ready\n");
			_tsha256r_complete_message_block(state);

			dprintf("state->event == SHA256B_FSM_COMPLETE\n");
			state->event = SHA256B_FSM_COMPLETE;
		} else {
			dprintf("Expected state->i_message < MSIZE_BYTES - LSIZE_BYTES\n");
			state->event = SHA256B_FSM_ERROR;
		}
	} else {
		state->event = SHA256B_FSM_ERROR;
	}

	return 0;
}

s32 run_tests() {
	u32 digest[DIGEST_SIZE_WORDS];
	s32 ret = 0;
	s32 failed = 0;
	struct tsha256 __attribute__ ((aligned (16))) state;

#	define NTESTS 4

	struct TEST_CASES
	{
		const u8 *description;
		const u8 *message;
		u64 bytes;
		u32 *expected_digest;
	} test_cases[NTESTS];


	test_cases[0].description = "Empty string test";
	test_cases[0].message = "";
	test_cases[0].bytes = 0;
	u32 t0[8] = {0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924,
		     0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855};
	test_cases[0].expected_digest = t0;

	test_cases[1].description = "1 block, 3 char message test";
	test_cases[1].message = "abc";
	test_cases[1].bytes = 3;
	u32 t1[8] = {0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
		     0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad};
	test_cases[1].expected_digest = t1;

	test_cases[2].description = "2 block, 56 char message test";
	test_cases[2].message =
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	test_cases[2].bytes = 56;
	u32 t2[8] = {0x248d6a61, 0xd20638b8, 0xe5c02693, 0x0c3e6039,
		     0xa33ce459, 0x64ff2167, 0xf6ecedd4, 0x19db06c1};
	test_cases[2].expected_digest = t2;

	test_cases[3].description = "3 block, 128 char message test";
	test_cases[3].message =
		"abcdefghijabcdefghijabcdefghijababcdefghijabcdefghij"
		"abcdefghijababcdefghijabcdefghijabcdefghijababcdefgh"
		"ijabcdefghijabcdefghijab";
	test_cases[3].bytes = 128;
	u32 t3[8] = {0xc1a8e9a9, 0xd09f4a72, 0xa2ee2693, 0x8170d241,
		     0x50b2654b, 0x4e88c69a, 0xdf86dfe7, 0xb1a71f40};
	test_cases[3].expected_digest = t3;

	for (s32 i_test = 0 ; i_test < NTESTS ; i_test++)
	{
		dprintf("#### start test ####\n");
		const u8 *description = test_cases[i_test].description;
		const u8 *message = test_cases[i_test].message;
		const u32 *expected_digest = test_cases[i_test].expected_digest;
		const u64 bytes = test_cases[i_test].bytes;
		u64 i;

		dprintf("%s\n",description);

		tsha256r_reset(&state);

		i = 0;
		while (i < bytes)
		{
			s32 bytes_read = 0;
			bytes_read = tsha256r_getch(&state, message[i]);

			if (bytes_read < 0)
			{
				tsha256r_close(&state);
				ret = -EINVAL;
				goto DONE_RT;
			}

			i += bytes_read;

			if (state.event == SHA256B_FSM_INPUT_UPDATE)
				tsha256r_update(&state, 0);
		}
		do {
			tsha256r_update(&state, 1);
		} while (state.event != SHA256B_FSM_COMPLETE
			&& state.event != SHA256B_FSM_ERROR);
		u32 *hashcode = tsha256r_get_hashcode(&state);
		memcpy(digest, hashcode, DIGEST_SIZE_BYTES);
		tsha256r_close(&state);

		dprintf("Message as hex:\n");
		for (i = 0; i < bytes; i++)
			dprintf("%02x", message[i]);
		dprintf("\n");

		dprintf("Message as in characters: (len = %lld)\n", bytes);
		for (i = 0; i < bytes; i++)
			dprintf("%c", message[i]);
		dprintf("\n");

		dprintf("Digest as hex:\n");
		for (i = 0; i < DIGEST_SIZE_WORDS; i++)
			dprintf("%08x", digest[i]);
		dprintf("\n");

		dprintf("Expected digest as hex:\n");
		for (i = 0; i < DIGEST_SIZE_WORDS; i++)
			dprintf("%02x", expected_digest[i]);
		dprintf("\n");

		dprintf("\n");
		s32 result = memcmp(expected_digest, digest, DIGEST_SIZE_BYTES);
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
	struct tsha256 __attribute__ ((aligned (16))) state;
	s32 ret = 0;
	u64 i;
	s32 bytes;
	u32 digest[DIGEST_SIZE_WORDS];
	if (argc)
	if (argc == 2) {
		bytes = strlen(argv[1]);
		tsha256r_reset(&state);
		i = 0;
		while (i < bytes)
		{
			s32 bytes_read = 0;
			bytes_read = tsha256r_getch(&state, argv[1][i]);
			if (bytes_read < 0)
			{
				tsha256r_close(&state);
				ret = -EINVAL;
				goto DONE_ARGV;
			}

			i += bytes_read;
			if (state.event == SHA256B_FSM_INPUT_UPDATE)
				tsha256r_update(&state,0);
		}
		do {
			tsha256r_update(&state,1);
		} while (state.event != SHA256B_FSM_COMPLETE
			&& state.event != SHA256B_FSM_ERROR);
		u32 *hashcode = tsha256r_get_hashcode(&state);
		memcpy(digest, hashcode, DIGEST_SIZE_BYTES);
		tsha256r_close(&state);
		for (i = 0; i < DIGEST_SIZE_WORDS ; i++)
			dprintf("%04x", digest[i]);
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
