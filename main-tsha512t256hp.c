/*
 * tshax-512/256 - A register only implementation for SHA2-512/256
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
   each 1024-block in one pass so that it doesn't dynamically
   preallocate a larger duplicate concat message array which will expose a
   password in a DMA attack.  The security sensitive portion containing
   a possible key is placed in registers and the expanded derived
   version is sorted in memory.

   It requires this to be adaptated in the kernel space to guarantee
   non-preempted real-time execution in order for it to be effective so
   that the SSE & MMX state does not get dumped into memory.

   The plain non USE_ASM version was created to better understand the
   algorithm better primarly for the next version written in assembly.

   Both the asm and c versions currently do not have the complete changes
   for DMA attack mitigation.

   It used as the basis for the assembly only tresor_sha256b
   implementation (aka next version) for use in fscrypt with TRESOR.

   In the 512/256 version, the expansion and compression are combined and
   a section of W (viewport) is evaluated.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#ifdef DEBUG
#include <fxsrintrin.h>
#endif // DEBUG

#define ALG_PLAIN

#include "tsha512t256.h"

#if defined(USE_ASM) && !defined(ALG_PLAIN)
#  error "USE_ASM requires ALG_PLAIN"
#endif // defined(USE_ASM) && !defined(ALG_PLAIN)

#if defined(USE_ASM) && !defined(ALG_PLAIN)
#  error "USE_ASM is still in development.  The variable allocator may leak sensitive data."
#endif // defined(USE_ASM) && !defined(ALG_PLAIN)

#if defined(ALG_ASM) && defined(ALG_PLAIN)
#  error "ALG_ASM && ALG_PLAIN are mutually exclusive."
#endif // defined(ALG_ASM) && defined(ALG_PLAIN)

#ifdef HAVE_SSE4_1
#    warning "Using SSE4.1 (UNTESTED)"
#elif defined(HAVE_SSE2)
#    warning "Using SSE2"
#else
#    error "You must add either -DHAVE_SSE4_1 or -DHAVE_SSE2 to CFLAGS."
#endif // HAVE_SSE2

#ifdef HAVE_BMI
#    warning "Using BMI (UNTESTED)"
#endif // HAVE_BMI

#ifndef ROTRQ
u64 ROTRQ(const u64 v, const u8 amt)
{
	return v >> amt | v << (WORD_SIZE_BITS - amt);
}
#endif // !ROTRQ

#if defined(DEBUG) && !defined(USE_ASM)
#  define debug_printf(format, ...)						\
	do {									\
		printf(format, ##__VA_ARGS__);					\
	} while(0)
#else
#  define debug_printf(format, ...)
#endif // if defined(DEBUG) && defined(USE_ASM)

	/* Translated from sha256.S. */
	/* This is manually expanded for deterministic register use
	   to avoid compiler allocator from automatically leaking sensitive
	   info into RAM. */
#    define NEXT_W()								\
	do {									\
		W64[0] = W64[1];						\
		W64[1] = W64[2];						\
		W64[2] = W64[3];						\
		W64[4] = W64[5];						\
		W64[6] = W64[7];						\
		W64[8] = W64[9];						\
		W64[10] = W64[11];						\
		W64[11] = W64[12];						\
		W64[13] = W64[14];						\
		W64[14] = W64[15];						\
		W64[15] = W64[16];						\
	} while (0)

#    define DO_EXPANSION_PLAIN()						\
do										\
{										\
	state->sig0 =	  ROTRQ(W64[1], 1)					\
			^ ROTRQ(W64[1], 8)					\
			^ (W64[1]  >>  7);					\
	state->sig1 = 	  ROTRQ(W64[14], 19)					\
			^ ROTRQ(W64[14], 61)					\
			^   (W64[14] >> 6);					\
	W64[16] = W64[0]							\
				+ state->sig0					\
				+ W64[9]					\
				+ state->sig1;					\
} while (0)

#    define DO_COMPRESSION_PLAIN(k)						\
do										\
{										\
										\
										\
	state->Ch = (e & f) ^ ((~e) & g);					\
	state->Maj = (a & b) ^ (a & c) ^ (b & c);				\
	state->SIG0 = ROTRQ(a,28) ^ ROTRQ(a,34) ^ ROTRQ(a,39);			\
	state->SIG1 = ROTRQ(e,14) ^ ROTRQ(e,18) ^ ROTRQ(e,41);			\
	state->T1   =     h							\
			+ state->SIG1						\
			+ state->Ch						\
			+ k							\
			+ W64[16];						\
	state->T2   = state->SIG0 + state->Maj;					\
	debug_printf( "i-1=%d Ch=%016llx Maj=%016llx SIG0=%016llx SIG1=%016llx T1=%016llx"	\
		" T2=%016llx h=%016llx K=%016llx W64=%016llx\n",				\
		j-1, state->Ch, state->Maj, state->SIG0,			\
		state->SIG1, state->T1, state->T2, h, k,			\
		W64[16]);							\
										\
	debug_printf("Hex values %d:\n", j-1);					\
	debug_printf("%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",	\
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

u64 *plain_sha256t_get_hashcode(struct tsha512 *state)
{
	return state->digest;
}

void plain_sha256t_reset(struct tsha512 *state)
{
	memset(state, 0, sizeof(struct tsha512));
	debug_printf("Init digest\n");
	memcpy(state->digest, H_0, N_LETTERS * WORD_SIZE_BYTES);
}

void plain_sha256t_close(struct tsha512 *state)
{
	/* Securely wipe sensitive data.  Especially if password is used as the
	   message.							      */
	memset(state, 0, sizeof(struct tsha512));
}

void aprintf(u8 *a, s32 size)
{
	u64 *u = (u64*)a;
	for (s32 i = 3; i >= 0; i--)
	{
		debug_printf(" ");
		debug_printf("%016llx", u[i]);
	}
	debug_printf("\n");
}

/* Reads a character at a time into a x86 calling convention register.
   returns:
	<0 - error
	n - bytes read							      */
s32 plain_sha256t_getch(struct tsha512 *state, u8 c)
{
	s32 ret = 0;


	if (state == NULL)
	{
		ret = -EINVAL;
		goto GETCH_DONE;
	}

	if (state->event != SHA256T_FSM_INPUT)
		goto GETCH_DONE;

	if (state->i_message < MESSAGE_SIZE_BYTES) {
		state->W8[seq[state->i_message]] = c;
		state->msglen++;
		state->i_message++;
		ret = 1;
	} else {
		state->event = SHA256T_FSM_INPUT_UPDATE;
	}

GETCH_DONE:
	return ret;
}

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

// TODO
#define DO_MESSAGE_EXPANSION()							\
	DO_EXPANSION_PLAIN()

/* Unrolled do_compression generated by gen_asm_unroll_do_compression.py */
#define DO_MESSAGE_COMPRESSION()						\
	DO_COMPRESSION_PLAIN(K[16]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[17]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[18]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[19]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[20]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[21]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[22]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[23]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[24]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[25]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[26]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[27]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[28]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[29]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[30]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[31]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[32]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[33]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[34]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[35]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[36]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[37]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[38]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[39]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[40]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[41]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[42]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[43]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[44]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[45]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[46]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[47]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[48]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[49]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[50]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[51]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[52]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[53]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[54]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[55]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[56]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[57]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[58]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[59]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[60]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[61]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[62]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[63]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[64]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[65]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[66]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[67]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[68]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[69]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[70]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[71]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[72]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[73]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[74]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[75]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[76]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[77]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[78]);						\
	NEXT_W();								\
	DO_COMPRESSION_PLAIN(K[79]);

static void _plain_sha256t_complete_message_block(struct tsha512 *state) {
	u32 i; /* index for component of hash */
	u32 j; /* index for message blocks */
	u64 *W64;

	debug_printf("Called _plain_sha256t_complete_message_block\n");

	W64 = (u64*)state->W8;

#  ifdef DEBUG
	debug_printf("Message contents of W64:\n");

	for (j = 0; j < MESSAGE_SIZE_WORDS ; j++)
	{
		if (j % 4 == 0)
			debug_printf("\n");
		debug_printf("%016llx ", W64[16]);
	}
	debug_printf("\n");
#  endif // DEBUG

	debug_printf("Expanding and compessing message blocks\n");
	DO_MESSAGE_EXPANSION()

	// init state
	a = H0; b = H1; c = H2; d = H3;
	e = H4; f = H5; g = H6; h = H7;

	DO_MESSAGE_COMPRESSION()

	debug_printf("\n");
	debug_printf("Updating intermediate hash values\n");

	debug_printf("hex values %d:\n", j-1);
	H0 = a + H0; H1 = b + H1; H2 = c + H2; H3 = d + H3;
	H4 = e + H4; H5 = f + H5; H6 = g + H6; H7 = h + H7;
	debug_printf("%016llx%016llx%016llx%016llx%016llx%016llx%016llx%016llx\n", a, b, c, d, e, f, g, h);

#  ifdef DEBUG
	debug_printf("\nDigest as in hex little endian:\n");
	for (i = 0; i < DIGEST_SIZE_WORDS; i++)
		debug_printf("%016llx", state->digest[i]);
		debug_printf("\n");
#  endif // DEBUG

	debug_printf("Called _plain_sha256t_complete_message_block done\n");

DONE:

	/* Process next message block. */
	state->i_message = 0;
	memset(state->W8, 0, MESSAGE_SIZE_BYTES);
}

void plain_sha256t_update(struct tsha512 *state, u64 finish)
{
	debug_printf("Called plain_sha256t_update\n");


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

	if (state->event == SHA256T_FSM_INPUT)
	{
		debug_printf("state->event == SHA256T_FSM_INPUT\n");
		if (finish == 1)
		{
			debug_printf("Finished reading\n");
			state->event = SHA256T_FSM_INPUT_UPDATE;
		}
	}
	else if (state->event == SHA256T_FSM_INPUT_UPDATE)
	{
		debug_printf("state->event == SHA256T_FSM_INPUT_UPDATE\n");
		if (finish == 1)
		{
			state->event = SHA256T_FSM_APPEND_1BIT;
		}
		else
		{
			debug_printf("Processing a message block before 1 bit.\n");
			_plain_sha256t_complete_message_block(state);
			state->event = SHA256T_FSM_INPUT;
		}
	}
	else if (state->event == SHA256T_FSM_APPEND_1BIT)
	{
//		u64 w_last;
		debug_printf("state->event == SHA256T_FSM_APPEND_1BIT\n");
		if (state->i_message < MESSAGE_SIZE_BYTES) {
			debug_printf("Added 0x80\n");
			state->W8[seq[state->i_message]] = (u8)0x80;
			state->i_message++;
			state->event = SHA256T_FSM_APPEND_0_PADDING;
		} else {
			debug_printf("1 bit does not fix.  Forcing update.\n");

//			w_last = state->i_message >> 2;

			// Process this then add to the beginning.
			_plain_sha256t_complete_message_block(state);

			debug_printf("Added 0x80\n");
			state->W8[seq[state->i_message]] = (u8)0x80;
//			w_last = state->i_message >> 2;
			state->i_message++;
			state->event = SHA256T_FSM_APPEND_0_PADDING;
		}
	}
	else if (state->event == SHA256T_FSM_APPEND_0_PADDING)
	{
		debug_printf("state->event == SHA256T_FSM_APPEND_0_PADDING\n");
		if (state->i_message < MESSAGE_SIZE_BYTES - L_SIZE_BYTES) {
			// 112 = MESSAGE_SIZE_BYTES - L_SIZE_BYTES
			debug_printf("Filling padding to i=111\n");
			state->event = SHA256T_FSM_APPEND_LENGTH;
		} else {
			debug_printf("L does not fix.  Forcing update.\n");

			// Process this then add to the beginning.
			_plain_sha256t_complete_message_block(state);

			state->event = SHA256T_FSM_APPEND_0_PADDING;
		}
	}
	else if (state->event == SHA256T_FSM_APPEND_LENGTH) {
		debug_printf("state->event == SHA256T_FSM_APPEND_LENGTH\n");
		if (state->i_message < MESSAGE_SIZE_BYTES - L_SIZE_BYTES) {
			/* space check: 112 = MESSAGE_SIZE_BYTES - L_SIZE_BYTES */
			debug_printf("Message length:\n");
			/* gets message length */
			u8 len8[L_SIZE_BYTES];
			u128 *len128 = (u128*)len8;
			u64 i;

			*len128 = state->msglen << 3; /* *8 */
//			debug_printf("%016llx\n", *len128);

			// 56 57 58 59  60 61 62 63 ; 55 is msb and 63 is lsb

//			debug_printf("%016llx\n", *len128);

			for(i = 0; i < L_SIZE_BYTES; i++){
				state->W8[seq2[i]] = len8[i];
			}

			debug_printf("Hash is ready\n");
			_plain_sha256t_complete_message_block(state);

			debug_printf("state->event == SHA256T_FSM_COMPLETE\n");
			state->event = SHA256T_FSM_COMPLETE;
		} else {
			debug_printf("Expected state->i_message < 112\n");
			state->event = SHA256T_FSM_ERROR;
		}
	} else {
		state->event = SHA256T_FSM_ERROR;
	}

	return;
}

s32 run_tests() {
	u64 digest[DIGEST_SIZE_WORDS];
	s32 ret = 0;
	s32 failed = 0;
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


	for (u32 i_test = 0 ; i_test < NTESTS ; i_test++)
	{
		debug_printf("#### start test ####\n");
		const u8 *description = test_cases[i_test].description;
		const u8 *message = test_cases[i_test].message;
		const u64 *expected_digest = test_cases[i_test].expected_digest;
		const u64 bytes = test_cases[i_test].bytes;
		u32 i;

		debug_printf("%s\n",description);

		plain_sha256t_reset(&state);

		i = 0;
		while (i < bytes)
		{
			s32 bytes_read = 0;
			bytes_read = plain_sha256t_getch(&state, message[i]);
			if (bytes_read < 0)
			{
				plain_sha256t_close(&state);
				ret = -EINVAL;
				goto ERROR;
			}

			i += bytes_read;

			if (state.event == SHA256T_FSM_INPUT_UPDATE)
				plain_sha256t_update(&state, 0);
		}
		do {
			plain_sha256t_update(&state, 1);
		} while (state.event != SHA256T_FSM_COMPLETE
			&& state.event != SHA256T_FSM_ERROR);
		u64 *hashcode = plain_sha256t_get_hashcode(&state);
		memcpy(digest, hashcode, DIGEST_SIZE_BYTES);
		plain_sha256t_close(&state);

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
			debug_printf("%016llx", digest[i]);
		debug_printf("\n");

		debug_printf("Expected digest as hex:\n");
		for (i = 0; i < DIGEST_SIZE_WORDS; i++)
			debug_printf("%016llx", expected_digest[i]);
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
	struct tsha512 __attribute__ ((aligned (16))) state;
	s32 ret = 0;
	u64 i;
	s32 bytes;
	u64 digest[DIGEST_SIZE_WORDS];
	if (argc)
	if (argc == 2) {
		bytes = strlen(argv[1]);
		plain_sha256t_reset(&state);
		i = 0;
		while (i < bytes)
		{
			s32 bytes_read = 0;
			bytes_read = plain_sha256t_getch(&state, argv[1][i]);
			if (bytes_read < 0)
			{
				plain_sha256t_close(&state);
				ret = -EINVAL;
				goto DONE_ARGV;
			}

			i += bytes_read;

			if (state.event == SHA256T_FSM_INPUT_UPDATE)
				plain_sha256t_update(&state,0);
		}
		do {
			plain_sha256t_update(&state,1);
		} while (state.event != SHA256T_FSM_COMPLETE
			&& state.event != SHA256T_FSM_ERROR);
		u64 *hashcode = plain_sha256t_get_hashcode(&state);
		memcpy(digest, hashcode, DIGEST_SIZE_BYTES);
		plain_sha256t_close(&state);
		for (i = 0; i < DIGEST_SIZE_WORDS; i++)
			debug_printf("%016llx", digest[i]);
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
#endif // DEBUG
	return ret;
}
