/*
 * tsha-sha512/256h - A register only implementation for SHA2-512/256
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

   It used as the basis for the assembly only tsha_sha256b
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

#define USE_ASM
#define ALG_PLAIN

#include "tsha512t256.h"

#ifdef HAVE_SSE4_1
#  warning "Using SSE4.1 (UNTESTED)"
#elif defined(HAVE_SSE2)
#  warning "Using SSE2"
#else
#  error "You must add either -DHAVE_SSE4_1 or -DHAVE_SSE2 to CFLAGS."
#endif // HAVE_SSE2

#ifdef HAVE_BMI
#  warning "Using BMI (UNTESTED)"
#endif // HAVE_BMI

#ifdef HAVE_SSE4_1
#  include "tsha512t256-sse4_1.h"
#elif defined (HAVE_SSE2)
#  include "tsha512t256-sse2.h"
#else
#  include "tsha512t256-c.h"
#endif

#ifndef ROTRQ
u64 ROTRQ(const u64 v, const u8 amt)
{
	return v >> amt | v << (WORD_SIZE_BITS - amt);
}
#endif // !ROTRQ

void insert_W_byte(u64 bi, u8 c)
{
	register u64 gpr0 asm ("r8");
	gpr0 = 0x00000000000000ff & c;
	_insert_W_byte(bi, gpr0);
}

	/* Translated from sha256.S. */
	/* This is manually expanded for deterministic register use
	   to avoid compiler allocator from automatically leaking sensitive
	   info into RAM. */
#ifdef HAVE_BMI
#	define ANDN1								\
	asm(	"andnq		%%r9,%%r14,%%r9"				\
		:								\
		:								\
		: "r9",								\
		  "r14");
#else
#	define ANDN1								\
	r14 = ~r14;								\
	r9 = r14 & r9;
#endif // HAVE_BMI

#ifdef HAVE_SSE4_1
#	define GET_W0(W)							\
		GET_W(W,0,xmm0)
#	define GET_W1(W)							\
		GET_W(W,1,xmm0)
#	define GET_W9(W)							\
		GET_W(W,1,xmm4)
#	define GET_W14(W)							\
		GET_W(W,0,xmm7)
#	define GET_W16(W)							\
		GET_W(W,0,xmm8)
#	define SET_W16(W)							\
		SET_W(W,0,xmm8)
#else
#	define GET_W0(W)							\
		GET_WR(W,xmm0)
#	define GET_W1(W)							\
		GET_WL(W,xmm0)
#	define GET_W9(W)							\
		GET_WR(W,xmm4)
#	define GET_W14(W)							\
		GET_WR(W,xmm7)
#	define SET_W16(W)							\
		SET_WR(W,xmm8,xmm14,mask1)

#endif // HAVE_SSE4_1

/*
 *       w1  w0			xmm0	W64[j-15]	W64[j-16]
 *       w3  w2			xmm1
 *       w5  w4			xmm2
 *       w7  w6			xmm3
 *       w9  w8			xmm4	W64[j-7]
 *       w11 w10		xmm5
 *       w13 w12		xmm6
 *       w15 w14		xmm7			W64[j-2]
 *       t   w16		xmm8			W64[j]
 */


#    define DO_EXPANSION_ASM()							\
do {										\
	register u64 sig0 asm ("r12");						\
	register u64 sig1 asm ("rcx");						\
										\
	GET_W1(rbx);								\
	rax = rbx;								\
	rcx = rbx;								\
	ROTRQ(rax, 7);								\
	ROTRQ(rbx, 18);								\
	rcx = rcx >> 3;								\
	rbx = rax ^ rbx;							\
	rcx = rbx ^ rcx;							\
	sig0 = rcx;								\
										\
	GET_W14(rbx)								\
	rax = rbx;								\
	rcx = rbx;								\
	ROTRQ(rax, 17);								\
	ROTRQ(rbx, 19);								\
	rcx = rcx >> 10;							\
	rbx = rax ^ rbx;							\
	sig1 = rbx ^ rcx;							\
										\
	r13 = get_w(0);								\
	r14 = get_w(9);								\
	r13 = r13 + sig0;							\
	r13 = r13 + r14;							\
	r13 = r13 + sig1;							\
	SET_W16(r13);								\
} while (0)

#    define DO_COMPESSION_ASM(k)						\
do {										\
	register u64 T1 asm ("rcx");						\
	register u64 T2 asm ("rbx");						\
	register u64 Ch asm ("r9");						\
	register u64 Maj asm ("r15");						\
	register u64 SIG0 asm ("r11");						\
	register u64 SIG1 asm ("r11");						\
										\
	r8 = get_h();								\
	T1 = r8;								\
										\
	r14 = get_e();								\
	r10 = r14;								\
	r11 = r14;								\
	ROTRQ(r14,6);								\
	ROTRQ(r10,11);								\
	ROTRQ(r11,25);								\
	r10 = r14 ^ r10;							\
	SIG1 = r10 ^ r11;							\
	T1 = T1 + SIG1;								\
										\
	r14 = get_e();								\
	r9 = get_g();								\
	r15 = get_f();								\
	r15 = r14 & r15;							\
	ANDN1									\
	Ch = r15 ^ r9;								\
	T1 = T1 + Ch;								\
										\
	T1 = T1 + k;								\
										\
	GET16(rbx);								\
	T1 = T1 + rbx;								\
										\
	r14 = get_a();								\
	r10 = r14;								\
	r11 = r14;								\
	ROTRQ(r14,2);								\
	ROTRQ(r10,13);								\
	ROTRQ(r11,22);								\
	r10 = r14 ^ r10;							\
	SIG0 = r10 ^ r11;							\
	T2 = SIG0;								\
										\
	r10 = get_a();								\
	r11 = get_b();								\
	r14 = r11;								\
	r12 = get_c();								\
	r15 = r12;								\
	r11 = r10 & r11;							\
	r12 = r10 & r12;							\
	r15 = r14 & r15;							\
	r12 = r11 ^ r12;							\
	Maj = r12 ^ r15;							\
	T2 = T2 + Maj;								\
										\
	r9 = get_g();								\
	set_h(r9);								\
	r9 = get_f();								\
	set_g(r9);								\
	r9 = get_e();								\
	set_f(r9);								\
	r9 = get_d();								\
	rax = r9;								\
	rax = rax + T1;								\
	set_e(rax);								\
	r9 = get_c();								\
	set_d(r9);								\
	r9 = get_b();								\
	set_c(r9);								\
	r9 = get_a();								\
	set_b(r9);								\
	T1 = T1 + T2;								\
	set_a(T1);								\
} while(0)

u64 *plain_sha256t_get_hashcode(struct tsha512 *state)
{
	return state->digest;
}

void plain_sha256t_reset(struct tsha512 *state)
{
	memset(state, 0, sizeof(struct tsha512));
	CLEAR_A();
	CLEAR_W();
	debug_printf("Init digest\n");
	INIT_H(xmm0,state->digest,H_0,H_0[8]);
}

void plain_sha256t_close(struct tsha512 *state)
{
	/* Securely wipe sensitive data.  Especially if password is used as the
	   message.							      */
	CLEAR_A();
	CLEAR_W();
	CLEAR_GPR();
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

void print_W_array()
{
	debug_printf("Dumping xmm\n");
	register u64 t0 asm ("r8");

// 	For testing deterministic behavior to see if setting registers work.
//	SET_XMM(xmm0,0xffffffff,0x00000a00,0xffffffff,0x00000000,xmm15,t0);
//	SET_XMM(xmm1,0xffffffff,0x00000100,0xffffffff,0x00000000,xmm15,t0);
//	SET_XMM(xmm2,0xffffffff,0x00000200,0xffffffff,0x00000000,xmm15,t0);
//	SET_XMM(xmm3,0xffffffff,0x00000300,0xffffffff,0x00000000,xmm15,t0);
//	SET_XMM(xmm4,0xffffffff,0x00000400,0xffffffff,0x00000000,xmm15,t0);

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


	DUMP_XMM(m0,xmm0);
	aprintf(m0, 16);

	DUMP_XMM(m1,xmm1);
	aprintf(m1, 16);

	DUMP_XMM(m2,xmm2);
	aprintf(m2, 16);

	DUMP_XMM(m3,xmm3);
	aprintf(m3, 16);

	DUMP_XMM(m4,xmm4);
	aprintf(m4, 16);

	DUMP_XMM(m5,xmm5);
	aprintf(m5, 16);

	DUMP_XMM(m6,xmm6);
	aprintf(m6, 16);

	DUMP_XMM(m7,xmm7);
	aprintf(m7, 16);

	DUMP_XMM(m8,xmm8);
	aprintf(m8, 16);

	DUMP_XMM(m9,xmm9);
	aprintf(m9, 16);

	DUMP_XMM(m10,xmm10);
	aprintf(m10, 16);

	DUMP_XMM(m11,xmm11);
	aprintf(m11, 16);

	DUMP_XMM(m12,xmm12);
	aprintf(m12, 16);

	DUMP_XMM(m13,xmm13);
	aprintf(m13, 16);

	DUMP_XMM(m14,xmm14);
	aprintf(m14, 16);

#ifdef HAVE_SSE4_1
	DUMP_XMM(m15,xmm15);
#elif defined(HAVE_SSE2)
	DUMP_MM2(m15,mm4,mm5);
#endif // HAVE_SSE4_1
	aprintf(m15, 16);


	debug_printf("Done dumping xmm\n");
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
		insert_W_byte(seq[state->i_message], c);
		state->msglen++;
		state->i_message++;
		ret = 1;
	} else {
		state->event = SHA256T_FSM_INPUT_UPDATE;
	}

GETCH_DONE:
	return ret;
}

#    define a get_a()
#    define b get_b()
#    define c get_c()
#    define d get_d()
#    define e get_e()
#    define f get_f()
#    define g get_g()
#    define h get_h()


static void _plain_sha256t_complete_message_block(struct tsha512 *state) {
	u32 i; /* index for component of hash */
	u32 j; /* index for message blocks */

	register u64 t asm ("rax");

	debug_printf("Called _plain_sha256t_complete_message_block\n");

#ifdef DEBUG
	debug_printf("Message contents of W64:\n");

	for (j = 0; j < MESSAGE_SIZE_WORDS ; j++)
	{
		if (j % 4 == 0)
			debug_printf("\n");
#  if HAVE_SSE4_1
		GET_W(t,0,xmm8);
		//todo
		debug_printf("%016llx ", t);
#  else
		GET_WR(t,xmm8);
		debug_printf("%016llx ", t);
#  endif // HAVE_SSE4_1
#else
		debug_printf("%016llx ", W64[16]);
	}
	debug_printf("\n");
#endif // DEBUG

	debug_printf("Expanding and compessing message blocks\n");

	// init state
	INIT_ABCDEFGH(H0,H2,H4,H6);

/* Unrolled do_compression generated by gen_asm_unroll_do_compression.py */
	DO_COMPESSION_ASM(K[16]);
	NEXT_W();
	DO_COMPESSION_ASM(K[17]);
	NEXT_W();
	DO_COMPESSION_ASM(K[18]);
	NEXT_W();
	DO_COMPESSION_ASM(K[19]);
	NEXT_W();
	DO_COMPESSION_ASM(K[20]);
	NEXT_W();
	DO_COMPESSION_ASM(K[21]);
	NEXT_W();
	DO_COMPESSION_ASM(K[22]);
	NEXT_W();
	DO_COMPESSION_ASM(K[23]);
	NEXT_W();
	DO_COMPESSION_ASM(K[24]);
	NEXT_W();
	DO_COMPESSION_ASM(K[25]);
	NEXT_W();
	DO_COMPESSION_ASM(K[26]);
	NEXT_W();
	DO_COMPESSION_ASM(K[27]);
	NEXT_W();
	DO_COMPESSION_ASM(K[28]);
	NEXT_W();
	DO_COMPESSION_ASM(K[29]);
	NEXT_W();
	DO_COMPESSION_ASM(K[30]);
	NEXT_W();
	DO_COMPESSION_ASM(K[31]);
	NEXT_W();
	DO_COMPESSION_ASM(K[32]);
	NEXT_W();
	DO_COMPESSION_ASM(K[33]);
	NEXT_W();
	DO_COMPESSION_ASM(K[34]);
	NEXT_W();
	DO_COMPESSION_ASM(K[35]);
	NEXT_W();
	DO_COMPESSION_ASM(K[36]);
	NEXT_W();
	DO_COMPESSION_ASM(K[37]);
	NEXT_W();
	DO_COMPESSION_ASM(K[38]);
	NEXT_W();
	DO_COMPESSION_ASM(K[39]);
	NEXT_W();
	DO_COMPESSION_ASM(K[40]);
	NEXT_W();
	DO_COMPESSION_ASM(K[41]);
	NEXT_W();
	DO_COMPESSION_ASM(K[42]);
	NEXT_W();
	DO_COMPESSION_ASM(K[43]);
	NEXT_W();
	DO_COMPESSION_ASM(K[44]);
	NEXT_W();
	DO_COMPESSION_ASM(K[45]);
	NEXT_W();
	DO_COMPESSION_ASM(K[46]);
	NEXT_W();
	DO_COMPESSION_ASM(K[47]);
	NEXT_W();
	DO_COMPESSION_ASM(K[48]);
	NEXT_W();
	DO_COMPESSION_ASM(K[49]);
	NEXT_W();
	DO_COMPESSION_ASM(K[50]);
	NEXT_W();
	DO_COMPESSION_ASM(K[51]);
	NEXT_W();
	DO_COMPESSION_ASM(K[52]);
	NEXT_W();
	DO_COMPESSION_ASM(K[53]);
	NEXT_W();
	DO_COMPESSION_ASM(K[54]);
	NEXT_W();
	DO_COMPESSION_ASM(K[55]);
	NEXT_W();
	DO_COMPESSION_ASM(K[56]);
	NEXT_W();
	DO_COMPESSION_ASM(K[57]);
	NEXT_W();
	DO_COMPESSION_ASM(K[58]);
	NEXT_W();
	DO_COMPESSION_ASM(K[59]);
	NEXT_W();
	DO_COMPESSION_ASM(K[60]);
	NEXT_W();
	DO_COMPESSION_ASM(K[61]);
	NEXT_W();
	DO_COMPESSION_ASM(K[62]);
	NEXT_W();
	DO_COMPESSION_ASM(K[63]);
	NEXT_W();
	DO_COMPESSION_ASM(K[64]);
	NEXT_W();
	DO_COMPESSION_ASM(K[65]);
	NEXT_W();
	DO_COMPESSION_ASM(K[66]);
	NEXT_W();
	DO_COMPESSION_ASM(K[67]);
	NEXT_W();
	DO_COMPESSION_ASM(K[68]);
	NEXT_W();
	DO_COMPESSION_ASM(K[69]);
	NEXT_W();
	DO_COMPESSION_ASM(K[70]);
	NEXT_W();
	DO_COMPESSION_ASM(K[71]);
	NEXT_W();
	DO_COMPESSION_ASM(K[72]);
	NEXT_W();
	DO_COMPESSION_ASM(K[73]);
	NEXT_W();
	DO_COMPESSION_ASM(K[74]);
	NEXT_W();
	DO_COMPESSION_ASM(K[75]);
	NEXT_W();
	DO_COMPESSION_ASM(K[76]);
	NEXT_W();
	DO_COMPESSION_ASM(K[77]);
	NEXT_W();
	DO_COMPESSION_ASM(K[78]);
	NEXT_W();
	DO_COMPESSION_ASM(K[79]);

	debug_printf("\n");
	debug_printf("Updating intermediate hash values\n");

	debug_printf("hex values %d:\n", j-1);
	H0 = get_a() + H0; H1 = get_b() + H1;
	H2 = get_c() + H2; H3 = get_d() + H3;
	H4 = get_e() + H4; H5 = get_f() + H5;
	H6 = get_g() + H6; H7 = get_h() + H7;
	debug_printf("%016llx%016llx%016llx%016llx%016llx%016llx%016llx%016llx\n",
		get_a(), get_b(), get_c(), get_d(),
		get_e(), get_f(), get_g(), get_h());


#ifdef DEBUG
	debug_printf("\nDigest as in hex little endian:\n");
	for (i = 0; i < DIGEST_SIZE_WORDS; i++)
		debug_printf("%016llx", state->digest[i]);
		debug_printf("\n");
#endif // DEBUG

	debug_printf("Called _plain_sha256t_complete_message_block done\n");

DONE:

	/* Process next message block. */
	state->i_message = 0;
	CLEAR_W();
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
		u64 w_last;
		debug_printf("state->event == SHA256T_FSM_APPEND_1BIT\n");
		if (state->i_message < MESSAGE_SIZE_BYTES) {
			debug_printf("Added 0x80\n");
			insert_W_byte(seq[state->i_message], 0x80);

			state->i_message++;

			state->event = SHA256T_FSM_APPEND_0_PADDING;
		} else {
			debug_printf("1 bit does not fix.  Forcing update.\n");

			w_last = state->i_message >> 2;


			// Process this then add to the beginning.
			_plain_sha256t_complete_message_block(state);

			debug_printf("Added 0x80\n");
			insert_W_byte(seq[state->i_message], 0x80);

			w_last = state->i_message >> 2;

			state->i_message++;

			state->event = SHA256T_FSM_APPEND_0_PADDING;
		}
	}
	else if (state->event == SHA256T_FSM_APPEND_0_PADDING)
	{
		debug_printf("state->event == SHA256T_FSM_APPEND_0_PADDING\n");
		if (state->i_message < MESSAGE_SIZE_BYTES - L_SIZE_BYTES) {
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
				insert_W_byte(seq2[i], len8[i]);
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
	u32 failed = 0;
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
		s32 i;

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
	s64 i;
	u32 bytes;
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
