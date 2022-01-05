/*
 * tshax-256 - A register based Secure Hashing Algorithm 2 implementation (hybrid-plain)
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

   It requires this to be adaptated in the kernel space to guarantee
   non-preempted real-time execution in order for it to be effective so
   that the SSE & MMX state does not get dumped into memory.

   The plain non USE_ASM version was created to better understand the
   algorithm better primarly for the next version written in assembly.

   Both the asm and c versions currently do not have the complete changes
   for DMA attack mitigation.

   It used as the basis for the assembly only tshax_256
   implementation (aka next version) for use in fscrypt with TRESOR.
*/

/* Completion Time < 24 hours for v1 without USE_ASM			      */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#ifdef DEBUG
#include <fxsrintrin.h>
#endif // DEBUG

#define ALG_PLAIN

#include "tsha256.h"

#ifdef HAVE_SSE4_1
#    warning "Using SSE4.1 (UNTESTED)"
#elif defined(HAVE_SSE2)
#    warning "Using SSE2"
#else
#    error "You must add either -DHAVE_SSE4_1 or -DHAVE_SSE2 to CFLAGS."
#endif

#ifdef HAVE_BMI
#    warning "Using BMI (UNTESTED)"
#endif

#if defined(DEBUG) && !defined(USE_ASM)
#  define debug_printf(format, ...)						\
	do {									\
		printf(format, ##__VA_ARGS__);					\
	} while(0)
#  else
#    define debug_printf(format, ...)
#endif // DEBUG


/* rotate right */
#ifndef ROTRL
u32 ROTRL(const u32 v, const u8 amt)
{
	return v >> amt | v << (WORD_SIZE_BITS - amt);
}

#endif // ROTRL

u32 *tsha256hp_get_hashcode(struct tsha256 *state)
{
	return state->digest;
}

s32 tsha256hp_reset(struct tsha256 *state)
{
	memset(state, 0, sizeof(struct tsha256));
	debug_printf("Init digest\n");
	memcpy(state->digest, H_0, N_LETTERS * WORD_SIZE_BYTES);
}

s32 tsha256hp_close(struct tsha256 *state)
{
	/* Securely wipe sensitive data.  Especially if password is used as the
	   message.							      */
	memset(state, 0, sizeof(struct tsha256));
}

/* Reads a character at a time into a x86 calling convention register.
   returns:
	<0 - error
	n - bytes read							      */
s32 tsha256hp_getch(struct tsha256 *state, u8 c)
{
	s32 ret = 0;


	if (state == NULL)
	{
		ret = -EINVAL;
		goto GETCH_DONE;
	}

	if (state->event != TSHA256_FSM_INPUT)
		goto GETCH_DONE;

	if (state->i_message < MESSAGE_SIZE_BYTES) {
		state->W8[seq[state->i_message]] = c;
		state->msglen++;
		state->i_message++;
		ret = 1;
	} else {
		state->event = TSHA256_FSM_INPUT_UPDATE;
	}

GETCH_DONE:
	return ret;
}

#    define DO_EXPANSION_PLAIN(j)					\
do {										\
	state->sig0 =	  ROTRL(W32[j-15], 7)					\
			^ ROTRL(W32[j-15], 18)					\
			^ (W32[j-15]  >>  3);					\
	state->sig1 = 	  ROTRL(W32[j-2], 17)					\
			^ ROTRL(W32[j-2], 19)					\
			^   (W32[j-2] >> 10);					\
	W32[j] = W32[j-16]							\
				+ state->sig0					\
				+ W32[j-7]					\
				+ state->sig1;					\
	if (j % 4 == 0)								\
		debug_printf("\n");						\
	debug_printf("%08x ", W32[j]);						\
} while(0)

#    define DO_COMPRESSION_PLAIN(j, k)						\
do										\
{										\
	state->Ch = (e & f) ^ ((~e) & g);					\
	state->Maj = (a & b) ^ (a & c) ^ (b & c);				\
	state->SIG0 = ROTRL(a,2) ^ ROTRL(a,13) ^ ROTRL(a,22);			\
	state->SIG1 = ROTRL(e,6) ^ ROTRL(e,11) ^ ROTRL(e,25);			\
	state->T1   =     h							\
			+ state->SIG1						\
			+ state->Ch						\
			+ k							\
			+ W32[j];						\
	state->T2   = state->SIG0 + state->Maj;					\
	debug_printf( "i-1=%d Ch=%08x Maj=%08x SIG0=%08x SIG1=%08x T1=%08x"	\
		" T2=%08x h=%08x K=%08x W32=%08x\n",				\
		j-1, state->Ch, state->Maj, state->SIG0,			\
		state->SIG1, state->T1, state->T2, h, k,			\
		W32[j]);							\
										\
	debug_printf("Hex values %d:\n", j-1);					\
	debug_printf("%08x %08x %08x %08x %08x %08x %08x %08x\n",		\
		a, b, c, d, e, f, g, h);					\
	h = g;									\
	g = f;									\
	f = e;									\
	e = d + state->T1;							\
	d = c;									\
	c = b;									\
	b = a;									\
	a = state->T1 + state->T2;						\
} while(0)

#    define H0 state->digest[0]
#    define H1 state->digest[1]
#    define H2 state->digest[2]
#    define H3 state->digest[3]
#    define H4 state->digest[4]
#    define H5 state->digest[5]
#    define H6 state->digest[6]
#    define H7 state->digest[7]
#    define a state->A[0]
#    define b state->A[1]
#    define c state->A[2]
#    define d state->A[3]
#    define e state->A[4]
#    define f state->A[5]
#    define g state->A[6]
#    define h state->A[7]

#    define DO_MESSAGE_EXPANSION_PLAIN(j)					\
do {										\
	state->sig0 =	  ROTRL(W32[j-15], 7)					\
			^ ROTRL(W32[j-15], 18)					\
			^ (W32[j-15]  >>  3);					\
	state->sig1 =	  ROTRL(W32[j-2], 17)					\
			^ ROTRL(W32[j-2], 19)					\
			^   (W32[j-2] >> 10);					\
	W32[j] = W32[j-16]							\
				+ state->sig0					\
				+ W32[j-7]					\
				+ state->sig1;					\
	if (j % 4 == 0)								\
		debug_printf("\n");						\
	debug_printf("%08x ", W32[j]);						\
} while(0)

/* Unrolled do_compression generated by gen_asm_unroll_message_expansion.py */
#    define DO_MESSAGE_EXPANSION()						\
	DO_MESSAGE_EXPANSION_PLAIN(16);						\
	DO_MESSAGE_EXPANSION_PLAIN(17);						\
	DO_MESSAGE_EXPANSION_PLAIN(18);						\
	DO_MESSAGE_EXPANSION_PLAIN(19);						\
	DO_MESSAGE_EXPANSION_PLAIN(20);						\
	DO_MESSAGE_EXPANSION_PLAIN(21);						\
	DO_MESSAGE_EXPANSION_PLAIN(22);						\
	DO_MESSAGE_EXPANSION_PLAIN(23);						\
	DO_MESSAGE_EXPANSION_PLAIN(24);						\
	DO_MESSAGE_EXPANSION_PLAIN(25);						\
	DO_MESSAGE_EXPANSION_PLAIN(26);						\
	DO_MESSAGE_EXPANSION_PLAIN(27);						\
	DO_MESSAGE_EXPANSION_PLAIN(28);						\
	DO_MESSAGE_EXPANSION_PLAIN(29);						\
	DO_MESSAGE_EXPANSION_PLAIN(30);						\
	DO_MESSAGE_EXPANSION_PLAIN(31);						\
	DO_MESSAGE_EXPANSION_PLAIN(32);						\
	DO_MESSAGE_EXPANSION_PLAIN(33);						\
	DO_MESSAGE_EXPANSION_PLAIN(34);						\
	DO_MESSAGE_EXPANSION_PLAIN(35);						\
	DO_MESSAGE_EXPANSION_PLAIN(36);						\
	DO_MESSAGE_EXPANSION_PLAIN(37);						\
	DO_MESSAGE_EXPANSION_PLAIN(38);						\
	DO_MESSAGE_EXPANSION_PLAIN(39);						\
	DO_MESSAGE_EXPANSION_PLAIN(40);						\
	DO_MESSAGE_EXPANSION_PLAIN(41);						\
	DO_MESSAGE_EXPANSION_PLAIN(42);						\
	DO_MESSAGE_EXPANSION_PLAIN(43);						\
	DO_MESSAGE_EXPANSION_PLAIN(44);						\
	DO_MESSAGE_EXPANSION_PLAIN(45);						\
	DO_MESSAGE_EXPANSION_PLAIN(46);						\
	DO_MESSAGE_EXPANSION_PLAIN(47);						\
	DO_MESSAGE_EXPANSION_PLAIN(48);						\
	DO_MESSAGE_EXPANSION_PLAIN(49);						\
	DO_MESSAGE_EXPANSION_PLAIN(50);						\
	DO_MESSAGE_EXPANSION_PLAIN(51);						\
	DO_MESSAGE_EXPANSION_PLAIN(52);						\
	DO_MESSAGE_EXPANSION_PLAIN(53);						\
	DO_MESSAGE_EXPANSION_PLAIN(54);						\
	DO_MESSAGE_EXPANSION_PLAIN(55);						\
	DO_MESSAGE_EXPANSION_PLAIN(56);						\
	DO_MESSAGE_EXPANSION_PLAIN(57);						\
	DO_MESSAGE_EXPANSION_PLAIN(58);						\
	DO_MESSAGE_EXPANSION_PLAIN(59);						\
	DO_MESSAGE_EXPANSION_PLAIN(60);						\
	DO_MESSAGE_EXPANSION_PLAIN(61);						\
	DO_MESSAGE_EXPANSION_PLAIN(62);						\
	DO_MESSAGE_EXPANSION_PLAIN(63);
#    define DO_MESSAGE_COMPRESSION()						\
	DO_COMPRESSION_PLAIN(0,0x428a2f98);					\
	DO_COMPRESSION_PLAIN(1,0x71374491);					\
	DO_COMPRESSION_PLAIN(2,0xb5c0fbcf);					\
	DO_COMPRESSION_PLAIN(3,0xe9b5dba5);					\
	DO_COMPRESSION_PLAIN(4,0x3956c25b);					\
	DO_COMPRESSION_PLAIN(5,0x59f111f1);					\
	DO_COMPRESSION_PLAIN(6,0x923f82a4);					\
	DO_COMPRESSION_PLAIN(7,0xab1c5ed5);					\
	DO_COMPRESSION_PLAIN(8,0xd807aa98);					\
	DO_COMPRESSION_PLAIN(9,0x12835b01);					\
	DO_COMPRESSION_PLAIN(10,0x243185be);					\
	DO_COMPRESSION_PLAIN(11,0x550c7dc3);					\
	DO_COMPRESSION_PLAIN(12,0x72be5d74);					\
	DO_COMPRESSION_PLAIN(13,0x80deb1fe);					\
	DO_COMPRESSION_PLAIN(14,0x9bdc06a7);					\
	DO_COMPRESSION_PLAIN(15,0xc19bf174);					\
	DO_COMPRESSION_PLAIN(16,0xe49b69c1);					\
	DO_COMPRESSION_PLAIN(17,0xefbe4786);					\
	DO_COMPRESSION_PLAIN(18,0x0fc19dc6);					\
	DO_COMPRESSION_PLAIN(19,0x240ca1cc);					\
	DO_COMPRESSION_PLAIN(20,0x2de92c6f);					\
	DO_COMPRESSION_PLAIN(21,0x4a7484aa);					\
	DO_COMPRESSION_PLAIN(22,0x5cb0a9dc);					\
	DO_COMPRESSION_PLAIN(23,0x76f988da);					\
	DO_COMPRESSION_PLAIN(24,0x983e5152);					\
	DO_COMPRESSION_PLAIN(25,0xa831c66d);					\
	DO_COMPRESSION_PLAIN(26,0xb00327c8);					\
	DO_COMPRESSION_PLAIN(27,0xbf597fc7);					\
	DO_COMPRESSION_PLAIN(28,0xc6e00bf3);					\
	DO_COMPRESSION_PLAIN(29,0xd5a79147);					\
	DO_COMPRESSION_PLAIN(30,0x06ca6351);					\
	DO_COMPRESSION_PLAIN(31,0x14292967);					\
	DO_COMPRESSION_PLAIN(32,0x27b70a85);					\
	DO_COMPRESSION_PLAIN(33,0x2e1b2138);					\
	DO_COMPRESSION_PLAIN(34,0x4d2c6dfc);					\
	DO_COMPRESSION_PLAIN(35,0x53380d13);					\
	DO_COMPRESSION_PLAIN(36,0x650a7354);					\
	DO_COMPRESSION_PLAIN(37,0x766a0abb);					\
	DO_COMPRESSION_PLAIN(38,0x81c2c92e);					\
	DO_COMPRESSION_PLAIN(39,0x92722c85);					\
	DO_COMPRESSION_PLAIN(40,0xa2bfe8a1);					\
	DO_COMPRESSION_PLAIN(41,0xa81a664b);					\
	DO_COMPRESSION_PLAIN(42,0xc24b8b70);					\
	DO_COMPRESSION_PLAIN(43,0xc76c51a3);					\
	DO_COMPRESSION_PLAIN(44,0xd192e819);					\
	DO_COMPRESSION_PLAIN(45,0xd6990624);					\
	DO_COMPRESSION_PLAIN(46,0xf40e3585);					\
	DO_COMPRESSION_PLAIN(47,0x106aa070);					\
	DO_COMPRESSION_PLAIN(48,0x19a4c116);					\
	DO_COMPRESSION_PLAIN(49,0x1e376c08);					\
	DO_COMPRESSION_PLAIN(50,0x2748774c);					\
	DO_COMPRESSION_PLAIN(51,0x34b0bcb5);					\
	DO_COMPRESSION_PLAIN(52,0x391c0cb3);					\
	DO_COMPRESSION_PLAIN(53,0x4ed8aa4a);					\
	DO_COMPRESSION_PLAIN(54,0x5b9cca4f);					\
	DO_COMPRESSION_PLAIN(55,0x682e6ff3);					\
	DO_COMPRESSION_PLAIN(56,0x748f82ee);					\
	DO_COMPRESSION_PLAIN(57,0x78a5636f);					\
	DO_COMPRESSION_PLAIN(58,0x84c87814);					\
	DO_COMPRESSION_PLAIN(59,0x8cc70208);					\
	DO_COMPRESSION_PLAIN(60,0x90befffa);					\
	DO_COMPRESSION_PLAIN(61,0xa4506ceb);					\
	DO_COMPRESSION_PLAIN(62,0xbef9a3f7);					\
	DO_COMPRESSION_PLAIN(63,0xc67178f2);

static void _tsha256hp_complete_message_block(struct tsha256 *state) {
	u32 i; /* index for component of hash */
	u32 j; /* index for message blocks */
	u32 *W32;

	debug_printf("Called _tsha256hp_complete_message_block\n");

	W32 = (u32*)state->W8;

#  ifdef DEBUG
	debug_printf("Message contents of W32:\n");

	for (j = 0; j < MESSAGE_SIZE_WORDS ; j++)
	{
		if (j % 8 == 0)
			debug_printf("\n");
		debug_printf("%08x ", W32[j]);
	}
	debug_printf("\n");
#  endif

	debug_printf("Expanding message blocks\n");
	DO_MESSAGE_EXPANSION()
	debug_printf("\n");

	for (j=0; j<W_SIZE_WORDS; j++)
	{
		if (j%4 == 0)
			debug_printf("\n");
		debug_printf("%08x ", W32[j]);
	}
	debug_printf("\n");

	// init state
	a = H0; b = H1; c = H2; d = H3;
	e = H4; f = H5; g = H6; h = H7;

	DO_MESSAGE_COMPRESSION()

	debug_printf("\n");
	debug_printf("Updating intermediate hash values\n");

	debug_printf("hex values %d:\n", j-1);
	H0 = a + H0; H1 = b + H1; H2 = c + H2; H3 = d + H3;
	H4 = e + H4; H5 = f + H5; H6 = g + H6; H7 = h + H7;
	debug_printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", a, b, c, d, e, f, g, h);


#  ifdef DEBUG
	debug_printf("\nDigest as in hex little endian:\n");
	for (i = 0; i < DIGEST_SIZE_WORDS; i++)
		debug_printf("%08x", state->digest[i]);
		debug_printf("\n");
#  endif

	debug_printf("Called _tsha256hp_complete_message_block done\n");

DONE:

	/* Process next message block. */
	state->i_message = 0;
	memset(state->W8, 0, MESSAGE_SIZE_BYTES);
}

void tsha256hp_update(struct tsha256 *state, u32 finish)
{
	debug_printf("Called tsha256hp_update\n");


	if (finish == 1 || state->i_message >= MESSAGE_SIZE_BYTES)
	{
		debug_printf("Message is ready.\n");
	}
	else
	{
		debug_printf("Message is NOT ready.\n");
		return;
	}

	debug_printf("state: %d\n", state->event);

	if (state->event == TSHA256_FSM_INPUT)
	{
		debug_printf("state->event == TSHA256_FSM_INPUT\n");
		if (finish == 1)
		{
			debug_printf("Finished reading\n");
			state->event = TSHA256_FSM_INPUT_UPDATE;
		}
	}
	else if (state->event == TSHA256_FSM_INPUT_UPDATE)
	{
		debug_printf("state->event == TSHA256_FSM_INPUT_UPDATE\n");
		if (finish == 1)
		{
			state->event = TSHA256_FSM_APPEND_1BIT;
		}
		else
		{
			debug_printf("Processing a message block before 1 bit.\n");
			_tsha256hp_complete_message_block(state);
			state->event = TSHA256_FSM_INPUT;
		}
	}
	else if (state->event == TSHA256_FSM_APPEND_1BIT)
	{
//		u64 w_last;
		debug_printf("state->event == TSHA256_FSM_APPEND_1BIT\n");
		if (state->i_message < MESSAGE_SIZE_BYTES) {
			debug_printf("Added 0x80\n");
			state->W8[seq[state->i_message]] = (u8)0x80;
			state->i_message++;
			state->event = TSHA256_FSM_APPEND_0_PADDING;
		} else {
			debug_printf("1 bit does not fix.  Forcing update.\n");

//			w_last = state->i_message >> 2;

			// Process this then add to the beginning.
			_tsha256hp_complete_message_block(state);

			debug_printf("Added 0x80\n");
			state->W8[seq[state->i_message]] = (u8)0x80;
//			w_last = state->i_message >> 2;
			state->i_message++;
			state->event = TSHA256_FSM_APPEND_0_PADDING;
		}
	}
	else if (state->event == TSHA256_FSM_APPEND_0_PADDING)
	{
		debug_printf("state->event == TSHA256_FSM_APPEND_0_PADDING\n");
		if (state->i_message < 56) {
			debug_printf("Filling padding to i=55\n");
			state->event = TSHA256_FSM_APPEND_LENGTH;
		} else {
			debug_printf("L does not fix.  Forcing update.\n");

			// Process this then add to the beginning.
			_tsha256hp_complete_message_block(state);

			state->event = TSHA256_FSM_APPEND_0_PADDING;
		}
	}
	else if (state->event == TSHA256_FSM_APPEND_LENGTH) {
		debug_printf("state->event == TSHA256_FSM_APPEND_LENGTH\n");
		if (state->i_message < 56) {
			/* space check: 56 = MESSAGE_SIZE_BYTES - L_SIZE_BYTES */
			debug_printf("Message length:\n");
			/* gets message length */
			u8 len8[L_SIZE_BYTES];
			u64 *len64 = (u64*)len8;
			u32 i;

			*len64 = state->msglen << 3; /* *8 */
			debug_printf("%016llx\n", *len64);

			// 56 57 58 59  60 61 62 63 ; 55 is msb and 63 is lsb

			debug_printf("%016llx\n", *len64);

			for(i = 0; i < L_SIZE_BYTES; i++){
				state->W8[seq2[i]] = len8[i];
			}

			debug_printf("Hash is ready\n");
			_tsha256hp_complete_message_block(state);

			debug_printf("state->event == TSHA256_FSM_COMPLETE\n");
			state->event = TSHA256_FSM_COMPLETE;
		} else {
			debug_printf("Expected state->i_message < 56\n");
			state->event = TSHA256_FSM_ERROR;
		}
	} else {
		state->event = TSHA256_FSM_ERROR;
	}

	return;
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
		debug_printf("#### start test ####\n");
		const u8 *description = test_cases[i_test].description;
		const u8 *message = test_cases[i_test].message;
		const u32 *expected_digest = test_cases[i_test].expected_digest;
		const u64 bytes = test_cases[i_test].bytes;
		u64 i;

		debug_printf("%s\n",description);

		ret = tsha256hp_reset(&state);

		i = 0;
		while (i < bytes)
		{
			s32 bytes_read = 0;
			bytes_read = tsha256hp_getch(&state, message[i]);
			if (bytes_read < 0)
			{
				tsha256hp_close(&state);
				ret = -EINVAL;
				goto ERROR;
			}

			i += bytes_read;

			if (state.event == TSHA256_FSM_INPUT_UPDATE)
				tsha256hp_update(&state, 0);
		}
		do {
			tsha256hp_update(&state, 1);
		} while (state.event != TSHA256_FSM_COMPLETE
			&& state.event != TSHA256_FSM_ERROR);
		u32 *hashcode = tsha256hp_get_hashcode(&state);
		memcpy(digest, hashcode, DIGEST_SIZE_BYTES);
		tsha256hp_close(&state);

		debug_printf("Message as hex:\n");
		for (i = 0; i < bytes; i++)
			debug_printf("%02x", message[i]);
		debug_printf("\n");

		debug_printf("Message as in characters: (len = %lld)\n", bytes);
		for (i = 0; i < bytes; i++)
			debug_printf("%c", message[i]);
		debug_printf("\n");

		debug_printf("Digest as hex:\n");
		for (i = 0; i < DIGEST_SIZE_WORDS; i++)
			debug_printf("%08x", digest[i]);
		debug_printf("\n");

		debug_printf("Expected digest as hex:\n");
		for (i = 0; i < DIGEST_SIZE_WORDS; i++)
			debug_printf("%02x", expected_digest[i]);
		debug_printf("\n");

		debug_printf("\n");
		s32 result = memcmp(expected_digest, digest, DIGEST_SIZE_BYTES);
		if (result == 0)
			debug_printf("Pass\n");
		else
			debug_printf("Failed\n");
		debug_printf("---\n");
		failed |= result;
		debug_printf("#### end test ####\n");
	}

DONE_RT:
	return failed;

ERROR:
	return ret;
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
		ret = tsha256hp_reset(&state);
		i = 0;
		while (i < bytes)
		{
			s32 bytes_read = 0;
			bytes_read = tsha256hp_getch(&state, argv[1][i]);
			if (bytes_read < 0)
			{
				tsha256hp_close(&state);
				ret = -EINVAL;
				goto DONE_ARGV;
			}

			i += bytes_read;

			if (state.event == TSHA256_FSM_INPUT_UPDATE)
				tsha256hp_update(&state,0);
		}
		do {
			tsha256hp_update(&state,1);
		} while (state.event != TSHA256_FSM_COMPLETE
			&& state.event != TSHA256_FSM_ERROR);
		u32 *hashcode = tsha256hp_get_hashcode(&state);
		memcpy(digest, hashcode, DIGEST_SIZE_BYTES);
		tsha256hp_close(&state);
		for (i = 0; i < DIGEST_SIZE_WORDS; i++)
			debug_printf("%04x", digest[i]);
	}

DONE_ARGV:

	return ret;
}

s32 main(s32 argc, char *argv[])
{
	s32 ret = 0;
#ifdef DEBUG
	ret = run_tests();
#else
	ret = get_hash_argv(argc, argv);
#endif
	return ret;
}

