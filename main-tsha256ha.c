/*
 * tsha256ha - A register based Secure Hashing Algorithm 2 implementation (hybrid-assembly)
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

   Both the asm and c versions currently do not have the complete changes
   for DMA attack mitigation.

   It used as the basis for the assembly only tsha256
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

#define USE_ASM
#define ALG_PLAIN

#include "tsha256.h"

#ifdef HAVE_SSE4_1
#  warning "Using SSE4.1 (UNTESTED)"
#elif defined(HAVE_SSE2)
#  warning "Using SSE2"
#else
#  error "You must add either -DHAVE_SSE4_1 or -DHAVE_SSE2 to CFLAGS."
#endif

#ifdef HAVE_BMI
#  warning "Using BMI (UNTESTED)"
#endif

#ifdef HAVE_SSE4_1
#  include "tsha256-sse4_1.h"
#elif defined (HAVE_SSE2)
#  include "tsha256-sse2.h"
#else
#  error "You must add -DHAVE_SSE4_1 or -DHAVE_SSE2"
#endif

/* rotate right */
#ifndef ROTRL
u32 ROTRL(const u32 v, const u8 amt)
{
	return v >> amt | v << (WORD_SIZE_BITS - amt);
}
#endif // ROTRL

void insert_W_byte(u32 bi, u8 c)
{
	register u32 gpr0 asm ("r8");
	gpr0 = 0x000000ff & c;
	_insert_W_byte(bi, gpr0);
}

u32 *tsha256ha_get_hashcode(struct tsha256 *state)
{
	return state->digest;
}

s32 tsha256ha_reset(struct tsha256 *state)
{
	memset(state, 0, sizeof(struct tsha256));
	CLEAR_A();
	CLEAR_W();
	debug_printf("Init digest\n");
	INIT_H(xmm0,state->digest,H_0,H_0[4]);
}

s32 tsha256ha_close(struct tsha256 *state)
{
	/* Securely wipe sensitive data.  Especially if password is used as the
	   message.							      */
	CLEAR_A();
	CLEAR_W();
	CLEAR_GPR();
	memset(state, 0, sizeof(struct tsha256));
}

void aprintf(u8 *a, s32 size)
{
	u32 *u = (u32*)a;
	for (s32 i = 3; i >= 0; i--)
	{
		debug_printf(" ");
		debug_printf("%08x", u[i]);
	}
	debug_printf("\n");
}

void print_W_array()
{
	debug_printf("Dumping xmm\n");
	register u32 t0 asm ("r8");

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
#endif
	aprintf(m15, 16);


	debug_printf("Done dumping xmm\n");
}

/* Reads a character at a time into a x86 calling convention register.
   returns:
	<0 - error
	n - bytes read							      */
s32 tsha256ha_getch(struct tsha256 *state, u8 c)
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
		insert_W_byte(seq[state->i_message], c);
		state->msglen++;
		state->i_message++;
		ret = 1;
	} else {
		state->event = TSHA256_FSM_INPUT_UPDATE;
	}

GETCH_DONE:
	return ret;
}

#    define YX_SHLQ_REPLACE(MM,GPR)						\
        asm(	"movq	%1,%q0\n\t"						\
		"shlq	$32,%q0\n\t"						\
		"movq	%q0,%1"							\
		: "+r" (GPR),							\
		  "+y" (MM));

#    define H_EQ_G(MM,GPR)							\
	YX_SHLQ_REPLACE(MM,GPR)

#    define F_EQ_E(MM,GPR)							\
	YX_SHLQ_REPLACE(MM,GPR)

#    define D_EQ_C(MM,GPR)							\
	YX_SHLQ_REPLACE(MM,GPR)

#    define B_EQ_A(MM,GPR)							\
	YX_SHLQ_REPLACE(MM,GPR)

#ifdef HAVE_BMI
#      define ANDN1								\
	asm(	"andnq		%%r9d,%%r14,%%r9d"				\
		:								\
		:								\
		: "r9d",							\
		  "r14");
#else
#      define ANDN1								\
	r14d = ~r14d;								\
	r9d = r14d & r9d;
#endif

	/* Parallel register reuse can produce wrong result. */
	/* Translated from sha256.S. */
	/* This is manually expanded for deterministic register use
	   to avoid compiler allocator from automatically leaking sensitive
	   info into RAM. */
#    define DO_EXPANSION_ASM(j)							\
do {										\
	register u32 sig0 asm ("r12");						\
	register u32 sig1 asm ("ecx");						\
										\
	ebx = get_w(j-15);							\
	eax = ebx;								\
	ecx = ebx;								\
	ROTRL(eax, 7);								\
	ROTRL(ebx, 18);								\
	ecx = ecx >> 3;								\
	ebx = eax ^ ebx;							\
	ecx = ebx ^ ecx;							\
	sig0 = ecx;								\
										\
	ebx = get_w(j-2);							\
	eax = ebx;								\
	ecx = ebx;								\
	ROTRL(eax, 17);								\
	ROTRL(ebx, 19);								\
	ecx = ecx >> 10;							\
	ebx = eax ^ ebx;							\
	sig1 = ebx ^ ecx;							\
										\
	r13d = get_w(j-16);							\
	r14d = get_w(j-7);							\
	r13d = r13d + sig0;							\
	r13d = r13d + r14d;							\
	r13d = r13d + sig1;							\
	set_w(r13d, j);								\
	if (j % 4 == 0)								\
		debug_printf("\n");						\
	debug_printf("%08x ", get_w(j));					\
} while(0)

	/* Translated from sha256.S. */
	/* This is manually expanded for deterministic register use
	   to avoid compiler allocator from automatically leaking sensitive
	   info into RAM. */
#    define DO_COMPRESSION_ASM(j, k)						\
do {										\
	register u32 T1 asm ("ecx");						\
	register u32 T2 asm ("ebx");						\
	register u32 Ch asm ("r9");						\
	register u32 Maj asm ("r15");						\
	register u32 SIG0 asm ("r11");						\
	register u32 SIG1 asm ("r11");						\
										\
	r8d = get_h();								\
	T1 = r8d;								\
										\
	r14d = get_e();								\
	r10d = r14d;								\
	r11d = r14d;								\
	ROTRL(r14d,6);								\
	ROTRL(r10d,11);								\
	ROTRL(r11d,25);								\
	r10d = r14d ^ r10d;							\
	SIG1 = r10d ^ r11d;							\
	T1 = T1 + SIG1;								\
										\
	r14d = get_e();								\
	r9d = get_g();								\
	r15d = get_f();								\
	r15d = r14d & r15d;							\
	ANDN1									\
	Ch = r15d ^ r9d;							\
	T1 = T1 + Ch;								\
										\
	T1 = T1 + k;								\
										\
	ebx = get_w(j);								\
	T1 = T1 + ebx;								\
										\
	r14d = get_a();								\
	r10d = r14d;								\
	r11d = r14d;								\
	ROTRL(r14d,2);								\
	ROTRL(r10d,13);								\
	ROTRL(r11d,22);								\
	r10d = r14d ^ r10d;							\
	SIG0 = r10d ^ r11d;							\
	T2 = SIG0;								\
										\
	r10d = get_a();								\
	r11d = get_b();								\
	r14d = r11d;								\
	r12d = get_c();								\
	r15d = r12d;								\
	r11d = r10d & r11d;							\
	r12d = r10d & r12d;							\
	r15d = r14d & r15d;							\
	r12d = r11d ^ r12d;							\
	Maj = r12d ^ r15d;							\
	T2 = T2 + Maj;								\
										\
	H_EQ_G(mm3,r10);							\
	r9d = get_f();								\
	set_g(r9d);								\
	F_EQ_E(mm2,r10);							\
	r9d = get_d();								\
	rax = r9d;								\
	rax = rax + T1;								\
	set_e(rax);								\
	D_EQ_C(mm1,r10);							\
	r9d = get_b();								\
	set_c(r9d);								\
	B_EQ_A(mm0,r10);							\
	T1 = T1 + T2;								\
	set_a(T1);								\
} while(0)

#    define a get_a()
#    define b get_b()
#    define c get_c()
#    define d get_d()
#    define e get_e()
#    define f get_f()
#    define g get_g()
#    define h get_h()

	/* Parallel register reuse can produce wrong result. */
	/* Translated from sha256.S. */
	/* This is manually expanded for deterministic register use
	   to avoid compiler allocator from automatically leaking sensitive
	   info into RAM. */
#    define DO_MESSAGE_EXPANSION_ASM(j)						\
do {										\
	register u32 sig0 asm ("r12");						\
	register u32 sig1 asm ("ecx");						\
										\
	ebx = get_w(j-15);							\
	eax = ebx;								\
	ecx = ebx;								\
	ROTRL(eax, 7);								\
	ROTRL(ebx, 18);								\
	ecx = ecx >> 3;								\
	ebx = eax ^ ebx;							\
	ecx = ebx ^ ecx;							\
	sig0 = ecx;								\
										\
	ebx = get_w(j-2);							\
	eax = ebx;								\
	ecx = ebx;								\
	ROTRL(eax, 17);								\
	ROTRL(ebx, 19);								\
	ecx = ecx >> 10;							\
	ebx = eax ^ ebx;							\
	sig1 = ebx ^ ecx;							\
										\
	r13d = get_w(j-16);							\
	r14d = get_w(j-7);							\
	r13d = r13d + sig0;							\
	r13d = r13d + r14d;							\
	r13d = r13d + sig1;							\
	set_w(r13d, j);								\
	if (j % 4 == 0)								\
		debug_printf("\n");						\
	debug_printf("%08x ", get_w(j));					\
} while(0)

/* Unrolled do_compression generated by gen_asm_unroll_message_expansion.py */
#    define DO_MESSAGE_EXPANSION()						\
	DO_MESSAGE_EXPANSION_ASM(16);						\
	DO_MESSAGE_EXPANSION_ASM(17);						\
	DO_MESSAGE_EXPANSION_ASM(18);						\
	DO_MESSAGE_EXPANSION_ASM(19);						\
	DO_MESSAGE_EXPANSION_ASM(20);						\
	DO_MESSAGE_EXPANSION_ASM(21);						\
	DO_MESSAGE_EXPANSION_ASM(22);						\
	DO_MESSAGE_EXPANSION_ASM(23);						\
	DO_MESSAGE_EXPANSION_ASM(24);						\
	DO_MESSAGE_EXPANSION_ASM(25);						\
	DO_MESSAGE_EXPANSION_ASM(26);						\
	DO_MESSAGE_EXPANSION_ASM(27);						\
	DO_MESSAGE_EXPANSION_ASM(28);						\
	DO_MESSAGE_EXPANSION_ASM(29);						\
	DO_MESSAGE_EXPANSION_ASM(30);						\
	DO_MESSAGE_EXPANSION_ASM(31);						\
	DO_MESSAGE_EXPANSION_ASM(32);						\
	DO_MESSAGE_EXPANSION_ASM(33);						\
	DO_MESSAGE_EXPANSION_ASM(34);						\
	DO_MESSAGE_EXPANSION_ASM(35);						\
	DO_MESSAGE_EXPANSION_ASM(36);						\
	DO_MESSAGE_EXPANSION_ASM(37);						\
	DO_MESSAGE_EXPANSION_ASM(38);						\
	DO_MESSAGE_EXPANSION_ASM(39);						\
	DO_MESSAGE_EXPANSION_ASM(40);						\
	DO_MESSAGE_EXPANSION_ASM(41);						\
	DO_MESSAGE_EXPANSION_ASM(42);						\
	DO_MESSAGE_EXPANSION_ASM(43);						\
	DO_MESSAGE_EXPANSION_ASM(44);						\
	DO_MESSAGE_EXPANSION_ASM(45);						\
	DO_MESSAGE_EXPANSION_ASM(46);						\
	DO_MESSAGE_EXPANSION_ASM(47);						\
	DO_MESSAGE_EXPANSION_ASM(48);						\
	DO_MESSAGE_EXPANSION_ASM(49);						\
	DO_MESSAGE_EXPANSION_ASM(50);						\
	DO_MESSAGE_EXPANSION_ASM(51);						\
	DO_MESSAGE_EXPANSION_ASM(52);						\
	DO_MESSAGE_EXPANSION_ASM(53);						\
	DO_MESSAGE_EXPANSION_ASM(54);						\
	DO_MESSAGE_EXPANSION_ASM(55);						\
	DO_MESSAGE_EXPANSION_ASM(56);						\
	DO_MESSAGE_EXPANSION_ASM(57);						\
	DO_MESSAGE_EXPANSION_ASM(58);						\
	DO_MESSAGE_EXPANSION_ASM(59);						\
	DO_MESSAGE_EXPANSION_ASM(60);						\
	DO_MESSAGE_EXPANSION_ASM(61);						\
	DO_MESSAGE_EXPANSION_ASM(62);						\
	DO_MESSAGE_EXPANSION_ASM(63);
#    define DO_MESSAGE_COMPRESSION()						\
	DO_COMPRESSION_ASM(0,0x428a2f98);					\
	DO_COMPRESSION_ASM(1,0x71374491);					\
	DO_COMPRESSION_ASM(2,0xb5c0fbcf);					\
	DO_COMPRESSION_ASM(3,0xe9b5dba5);					\
	DO_COMPRESSION_ASM(4,0x3956c25b);					\
	DO_COMPRESSION_ASM(5,0x59f111f1);					\
	DO_COMPRESSION_ASM(6,0x923f82a4);					\
	DO_COMPRESSION_ASM(7,0xab1c5ed5);					\
	DO_COMPRESSION_ASM(8,0xd807aa98);					\
	DO_COMPRESSION_ASM(9,0x12835b01);					\
	DO_COMPRESSION_ASM(10,0x243185be);					\
	DO_COMPRESSION_ASM(11,0x550c7dc3);					\
	DO_COMPRESSION_ASM(12,0x72be5d74);					\
	DO_COMPRESSION_ASM(13,0x80deb1fe);					\
	DO_COMPRESSION_ASM(14,0x9bdc06a7);					\
	DO_COMPRESSION_ASM(15,0xc19bf174);					\
	DO_COMPRESSION_ASM(16,0xe49b69c1);					\
	DO_COMPRESSION_ASM(17,0xefbe4786);					\
	DO_COMPRESSION_ASM(18,0x0fc19dc6);					\
	DO_COMPRESSION_ASM(19,0x240ca1cc);					\
	DO_COMPRESSION_ASM(20,0x2de92c6f);					\
	DO_COMPRESSION_ASM(21,0x4a7484aa);					\
	DO_COMPRESSION_ASM(22,0x5cb0a9dc);					\
	DO_COMPRESSION_ASM(23,0x76f988da);					\
	DO_COMPRESSION_ASM(24,0x983e5152);					\
	DO_COMPRESSION_ASM(25,0xa831c66d);					\
	DO_COMPRESSION_ASM(26,0xb00327c8);					\
	DO_COMPRESSION_ASM(27,0xbf597fc7);					\
	DO_COMPRESSION_ASM(28,0xc6e00bf3);					\
	DO_COMPRESSION_ASM(29,0xd5a79147);					\
	DO_COMPRESSION_ASM(30,0x06ca6351);					\
	DO_COMPRESSION_ASM(31,0x14292967);					\
	DO_COMPRESSION_ASM(32,0x27b70a85);					\
	DO_COMPRESSION_ASM(33,0x2e1b2138);					\
	DO_COMPRESSION_ASM(34,0x4d2c6dfc);					\
	DO_COMPRESSION_ASM(35,0x53380d13);					\
	DO_COMPRESSION_ASM(36,0x650a7354);					\
	DO_COMPRESSION_ASM(37,0x766a0abb);					\
	DO_COMPRESSION_ASM(38,0x81c2c92e);					\
	DO_COMPRESSION_ASM(39,0x92722c85);					\
	DO_COMPRESSION_ASM(40,0xa2bfe8a1);					\
	DO_COMPRESSION_ASM(41,0xa81a664b);					\
	DO_COMPRESSION_ASM(42,0xc24b8b70);					\
	DO_COMPRESSION_ASM(43,0xc76c51a3);					\
	DO_COMPRESSION_ASM(44,0xd192e819);					\
	DO_COMPRESSION_ASM(45,0xd6990624);					\
	DO_COMPRESSION_ASM(46,0xf40e3585);					\
	DO_COMPRESSION_ASM(47,0x106aa070);					\
	DO_COMPRESSION_ASM(48,0x19a4c116);					\
	DO_COMPRESSION_ASM(49,0x1e376c08);					\
	DO_COMPRESSION_ASM(50,0x2748774c);					\
	DO_COMPRESSION_ASM(51,0x34b0bcb5);					\
	DO_COMPRESSION_ASM(52,0x391c0cb3);					\
	DO_COMPRESSION_ASM(53,0x4ed8aa4a);					\
	DO_COMPRESSION_ASM(54,0x5b9cca4f);					\
	DO_COMPRESSION_ASM(55,0x682e6ff3);					\
	DO_COMPRESSION_ASM(56,0x748f82ee);					\
	DO_COMPRESSION_ASM(57,0x78a5636f);					\
	DO_COMPRESSION_ASM(58,0x84c87814);					\
	DO_COMPRESSION_ASM(59,0x8cc70208);					\
	DO_COMPRESSION_ASM(60,0x90befffa);					\
	DO_COMPRESSION_ASM(61,0xa4506ceb);					\
	DO_COMPRESSION_ASM(62,0xbef9a3f7);					\
	DO_COMPRESSION_ASM(63,0xc67178f2);

static void _tsha256ha_complete_message_block(struct tsha256 *state) {
#       define H0 state->digest[0]
#       define H1 state->digest[1]
#       define H2 state->digest[2]
#       define H3 state->digest[3]
#       define H4 state->digest[4]
#       define H5 state->digest[5]
#       define H6 state->digest[6]
#       define H7 state->digest[7]

	u32 i; /* index for component of hash */
	u32 j; /* index for message blocks */

	debug_printf("Called _tsha256ha_complete_message_block\n");

#ifdef DEBUG
	debug_printf("Message contents of W32:\n");

	for (j = 0; j < MESSAGE_SIZE_WORDS ; j++)
	{
		if (j % 8 == 0)
			debug_printf("\n");
		debug_printf("%08x ", get_w(j));
	}
	debug_printf("\n");
#endif

	debug_printf("Expanding message blocks\n");
	DO_MESSAGE_EXPANSION()
	debug_printf("\n");

	print_W_array();
	debug_printf("\n");

	// init state
	INIT_ABCDEFGH(H0,H2,H4,H6);

	DO_MESSAGE_COMPRESSION()

	debug_printf("\n");
	debug_printf("Updating intermediate hash values\n");

	debug_printf("hex values %d:\n", j-1);
	H0 = get_a() + H0; H1 = get_b() + H1;
	H2 = get_c() + H2; H3 = get_d() + H3;
	H4 = get_e() + H4; H5 = get_f() + H5;
	H6 = get_g() + H6; H7 = get_h() + H7;
	debug_printf("%08x%08x%08x%08x%08x%08x%08x%08x\n",
		get_a(), get_b(), get_c(), get_d(),
		get_e(), get_f(), get_g(), get_h());


#ifdef DEBUG
	debug_printf("\nDigest as in hex little endian:\n");
	for (i = 0; i < DIGEST_SIZE_WORDS; i++)
		debug_printf("%08x", state->digest[i]);
		debug_printf("\n");
#endif

	debug_printf("Called _tsha256ha_complete_message_block done\n");

DONE:

	/* Process next message block. */
	state->i_message = 0;
	CLEAR_W();
}

void tsha256ha_update(struct tsha256 *state, u32 finish)
{
	debug_printf("Called tsha256ha_update\n");

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
			_tsha256ha_complete_message_block(state);
			state->event = TSHA256_FSM_INPUT;
		}
	}
	else if (state->event == TSHA256_FSM_APPEND_1BIT)
	{
//		u64 w_last;
		debug_printf("state->event == TSHA256_FSM_APPEND_1BIT\n");
		if (state->i_message < MESSAGE_SIZE_BYTES) {
			debug_printf("Added 0x80\n");
			insert_W_byte(seq[state->i_message], 0x80);
			state->i_message++;
			state->event = TSHA256_FSM_APPEND_0_PADDING;
		} else {
			debug_printf("1 bit does not fix.  Forcing update.\n");

//			w_last = state->i_message >> 2;

			// Process this then add to the beginning.
			_tsha256ha_complete_message_block(state);

			debug_printf("Added 0x80\n");
			insert_W_byte(seq[state->i_message], 0x80);
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
			_tsha256ha_complete_message_block(state);

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
				insert_W_byte(seq2[i], len8[i]);
			}

			debug_printf("Hash is ready\n");
			_tsha256ha_complete_message_block(state);

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

		ret = tsha256ha_reset(&state);

		i = 0;
		while (i < bytes)
		{
			s32 bytes_read = 0;
			bytes_read = tsha256ha_getch(&state, message[i]);
			if (bytes_read < 0)
			{
				tsha256ha_close(&state);
				ret = -EINVAL;
				goto ERROR;
			}

			i += bytes_read;

			if (state.event == TSHA256_FSM_INPUT_UPDATE)
				tsha256ha_update(&state, 0);
		}
		do {
			tsha256ha_update(&state, 1);
		} while (state.event != TSHA256_FSM_COMPLETE
			&& state.event != TSHA256_FSM_ERROR);
		u32 *hashcode = tsha256ha_get_hashcode(&state);
		memcpy(digest, hashcode, DIGEST_SIZE_BYTES);
		tsha256ha_close(&state);

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
		ret = tsha256ha_reset(&state);
		i = 0;
		while (i < bytes)
		{
			s32 bytes_read = 0;
			bytes_read = tsha256ha_getch(&state, argv[1][i]);
			if (bytes_read < 0)
			{
				tsha256ha_close(&state);
				ret = -EINVAL;
				goto DONE_ARGV;
			}

			i += bytes_read;

			if (state.event == TSHA256_FSM_INPUT_UPDATE)
				tsha256ha_update(&state,0);
		}
		do {
			tsha256ha_update(&state,1);
		} while (state.event != TSHA256_FSM_COMPLETE
			&& state.event != TSHA256_FSM_ERROR);
		u32 *hashcode = tsha256ha_get_hashcode(&state);
		memcpy(digest, hashcode, DIGEST_SIZE_BYTES);
		tsha256ha_close(&state);
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
