/*
 * tsha256a - An assembly based implementation of SHA-256 in x86_64 assembly
 *             using sse2 and mmx registers.
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
 * For this to be effective, preemption should be disabled and the sse register
 * file should not be copied to RAM.
 *
 * This implementation is a work in progress and inspired by TRESOR.
 * It's designed to keep a sensitive
 * message (aka the key) away from touching memory for DMA attack.  Primarly
 * will used for fscrypt with TRESOR.  The b suffix indicates the alternative to
 * the implementation used in the TRESOR patches.
 *
 * This is a translation from c to asm.  The c version is verified correct.
 *
 * The design prioritizes security over speed.
 *
 * Algorithm design requirements:
 *      Stores sensitive data in registers
 *      Clean up routine to wipe sensitive info
 *	End-to-end registers for sensitive data only, from function call to end.
 *	The message should be stored and retrieved from registers not memory.
 *	The root, parents, grandparents of the references of the message should
 *	not be touching any virtual address space.
 *	The message needs to be transferred per byte over register(s) only
 *	via per byte reader or by sets of xmm registers.
 *
 *	Expanded message blocks (w) memory requirements math:
 *
 *	64 words needed, 256 bytes total
 *	Used 16 sse registers
 *
 *			 total
 *	xmm0  +16 bytes  16
 *	xmm1  +16 bytes  32 bytes
 *	...
 *	...
 *	xmm14 +15 bytes  240 bytes
 *	xmm15 +16 bytes  256 bytes
 *
 *	w indices:
 *
 *	w array
 *	 w3  w2  w1  w0		xmm0
 *	 w7  w6  w5  w4		xmm1
 *	w11 w10  w9  w8		xmm2
 *	w15 w14 w13 w12		xmm3
 *	w19 w18 w17 w16		xmm4
 *	w23 w22 w21 w20		xmm5
 *	w27 w26 w25 w24		xmm6
 *	w31 w30 w29 w28		xmm7
 *	w35 w34 w33 w32		xmm8
 *	w39 w38 w37 w36		xmm9
 *	w43 w42 w41 w40		xmm10
 *	w47 w46 w45 w44		xmm11
 *	w51 w50 w49 w48		xmm12
 *	w55 w54 w53 w52		xmm13
 *	w59 w58 w57 w56		xmm14
 *	w63 w62 w61 w60		xmm15 for sse4.1 only
 *
 *	w61 w60			mm4 for sse2 only
 *	w63 w62			mm5 for sse2 only
 *
 *	xmm15 is not used as part of the array because
 *	no temp xmm registers left.
 *
 *	Compression function state (a, b, c, d, e, f, g, h) memory requirements
 *	math:
 *
 *	8 words needed, 32 bytes total
 *	Used 4 mmx registers
 *
 *			total
 *      mm0 +8 bytes	8
 *      mm1 +8 bytes	16
 *      mm2 +8 bytes	24
 *      mm3 +8 bytes	32
 *
 *	State indices:
 *
 *	b a	mm0
 *	d c	mm1
 *	f e	mm2
 *	h g	mm3
 *
 *	Message bit *L*ength:
 *	mm6
 *
 *	Temporary variables:
 *
 *	xmm15 for sse2 only
 *	mm7
 *
 *	Start - End competion:  Jan 29 2021 19:52 - Feb 8, 2021 17:42.
 *	10 days, 9 hrs, 50 min. - for ASM correct completion milestone
 *
 */

.file "tsha256a.S"

#ifdef HAVE_SSE4_1
#  warning "Using SSE4.1 (UNTESTED)"
#elif defined(HAVE_SSE2)
#  warning "Using SSE2"
#else
#  error "You must add either -DHAVE_SSE4_1 or -DHAVE_SSE2 to CFLAGS"
#endif

#ifdef HAVE_BMI
#  warning "Using BMI (UNTESTED)"
#endif

/* Declare global variables. */
/* u32 W[64]:xmm0-xmm15 */
/* u32 A[8]:mm0-mm3; */

/* For word expansion */
.set	xmm0,	%xmm0
.set	xmm1,	%xmm1
.set	xmm2,	%xmm2
.set	xmm3,	%xmm3
.set	xmm4,	%xmm4
.set	xmm5,	%xmm5
.set	xmm6,	%xmm6
.set	xmm7,	%xmm7
.set	xmm8,	%xmm8
.set	xmm9,	%xmm9
.set	xmm10,	%xmm10
.set	xmm11,	%xmm11
.set	xmm12,	%xmm12
.set	xmm13,	%xmm13
.set	xmm14,	%xmm14
.set	xmm15,	%xmm15

.set	mm0,	%mm0
.set	mm1,	%mm1
.set	mm2,	%mm2
.set	mm3,	%mm3
.set	mm4,	%mm4
.set	mm5,	%mm5
.set	mm6,	%mm6
.set	mm7,	%mm7

.set    r8,	%r8
.set    r8d,	%r8d
.set    r8b,	%r8b
.set    r9,	%r9
.set    r9d,	%r9d
.set    r9b,	%r9b
.set    r10,	%r10
.set    r10d,	%r10d
.set    r10b,	%r10b
.set    r11,	%r11
.set    r11d,	%r11d
.set    r11b,	%r11b
.set    r12,	%r12
.set    r12d,	%r12d
.set    r12b,	%r12b
.set    r13,	%r13
.set    r13d,	%r13d
.set    r13b,	%r13b
.set    r14,	%r14
.set    r14d,	%r14d
.set    r14b,	%r14b
.set    r15,	%r15
.set    r15d,	%r15d
.set    r15b,	%r15b

.set    al,     %al
.set    bl,     %bl
.set    cl,     %cl
.set    dl,     %dl

.set    eax,    %eax
.set    ebx,    %ebx
.set    ecx,    %ecx
.set    edx,    %edx
.set    esi,    %esi
.set    rip,    %rip

.set    rax,    %rax
.set    rbx,    %rbx
.set    rcx,    %rcx
.set    rdx,    %rdx
.set    rsi,    %rsi
.set    rdi,    %rdi
.set    rsp,    %rsp
.set    rbp,    %rbp

.set	db0,	%db0
.set	db1,	%db1
.set	db2,	%db2
.set	db3,	%db3

.data

K:	.align 16
	.long 	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
	.long	0x3956c25b, 0x59f111f1,	0x923f82a4, 0xab1c5ed5
	.long	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
	.long	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
	.long	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
	.long	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
	.long	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
	.long	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
	.long	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
	.long	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
	.long	0xa2bfe8a1, 0xa81a664b,	0xc24b8b70, 0xc76c51a3
	.long	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
	.long	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
	.long	0x391c0cb3, 0x4ed8aa4a,	0x5b9cca4f, 0x682e6ff3
	.long	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
	.long	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

H0_1:	.align 16
	.long	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
H0_2:	.align 16
	.long	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

/* Indices and sequence for inserting the message. */
seq:
	.long	3,  2,   1,  0
	.long	7,  6,   5,  4
	.long	11, 10,  9,  8
	.long	15, 14, 13, 12
	.long	19, 18, 17, 16
	.long	23, 22, 21, 20
	.long	27, 26, 25, 24
	.long	31, 30, 29, 28
	.long	35, 34, 33, 32
	.long	39, 38, 37, 36
	.long	43, 42, 41, 40
	.long	47, 46, 45, 44
	.long	51, 50, 49, 48
	.long	55, 54, 53, 52
	.long	59, 58, 57, 56
	.long	63, 62, 61, 60

/* Indices and sequence for inserting the Big Endian (BE) length (L). */
/* End of sub-array index positon: 56 57 58 59 60 61 62 63 */
/* char[0] MSB when printing le u64 */
/* char[7] LSB when printing le u64 */

seq2:	.long	60, 61, 62, 63
	.long	56, 57, 58, 59

/*	    b         a		*/
mask0:	.align 8
.quad	0x00000000ffffffff
mask1:	.align 8
.quad	0xffffffff00000000

#ifdef DEBUG
message_good:
	.asciz "good\n"

message_loop_i:
	.asciz "i=%d\n"

message_loop_j:
	.asciz "j=%d\n"

message_loop_msglen:
	.asciz "msglen=%d\n"

hex_values_header: .asciz "Hex values %d:\n"
hex_values_report: .asciz "%08x %08x %08x %08x %08x %08x %08x %08x\n"
mi_report: .asciz "%08x %08x %08x %08x\n"
print_int32: .asciz "int32=%d\n"
print_int64: .asciz "int64=%lld\n"
print_char: .asciz "char=%c\n"
print_hex2x: .asciz "hex=%02x\n"
print_hex8x: .asciz "hex=%08x\n"
print_hex8xl: .asciz "%s hex=%08x\n"
print_i_message: .asciz "i_message=%d\n"
print_j: .asciz "j=%d\n"
print_i: .asciz "i=%d\n"
print_it_works: .asciz "It works!\n"

str_event0: .asciz "event0:  TSHA256A_FSM_INPUT\n"
str_event1: .asciz "event1:  TSHA256A_FSM_INPUT_UPDATE\n"
str_event2: .asciz "event2:  TSHA256A_FSM_APPEND_1BIT\n"
str_event3: .asciz "event2:  TSHA256A_FSM_APPEND_0_PADDING\n"
str_event4: .asciz "event2:  TSHA256A_FSM_APPEND_LENGTH\n"
str_event5: .asciz "event2:  TSHA256A_FSM_COMPLETE\n"
str_event255: .asciz "event255:  TSHA256A_FSM_ERROR\n"

str_clearing_state: .asciz "Clearing state\n"
str_m: .asciz "The message:\n"
str_ch: .asciz "Ch"
str_maj: .asciz "Maj"
str_sig0: .asciz "SIG0"
str_sig1: .asciz "SIG1"
str_t1: .asciz "T1"
str_t2: .asciz "T2"
str_h: .asciz "h"
str_k: .asciz "k"
str_i: .asciz "i"
str_j: .asciz "j"
str_w32: .asciz "w32"
#endif

.set TSHA256A_FSM_INPUT,0
.set TSHA256A_FSM_INPUT_UPDATE,1
.set TSHA256A_FSM_APPEND_1BIT,2
.set TSHA256A_FSM_APPEND_0_PADDING,3
.set TSHA256A_FSM_APPEND_LENGTH,4
.set TSHA256A_FSM_COMPLETE,5
.set TSHA256A_FSM_ERROR,255

.set EINVAL,1

.text
.global tsha256a_update
.global tsha256a_getch
.global tsha256a_reset
.global tsha256a_close
.global tsha256a_get_hashcode

.set local_variables_size, 52 /* in bytes */

/*
struct tsha256 {
	u8 digest[DIGEST_SIZE]; //32
	u64 msglen;
	u32 i_message;
	u32 event;

#ifdef DEBUG
	u32 a;	// addr is 48
	u32 b;
	u32 c;
	u32 d;
	u32 e;
	u32 f;
	u32 g;
	u32 h;
	u8[16] m0; // addr is 80
	u8[16] m1;
	u8[16] m2;
	u8[16] m3;
	u8[16] m4;
	u8[16] m5;
	u8[16] m6;
	u8[16] m7;
	u8[16] m8;
	u8[16] m9;
	u8[16] m10;
	u8[16] m11;
	u8[16] m12;
	u8[16] m13;
	u8[16] m14;
	u8[16] m15;
#endif
}
*/

#ifdef DEBUG
.set state_size,336
#else
.set state_size,48
#endif



.set H0,0
.set H1,4
.set H2,8
.set H3,12
.set H4,16
.set H5,20
.set H6,24
.set H7,28

/* relative to struct *tsha256a */
.set digest,0
.set msglen,32
.set i_message,40
.set event,44

#ifdef DEBUG
#warning Using -DDEBUG reduces the security entirely
.set a,48
.set b,52
.set c,56
.set d,60
.set e,64
.set f,68
.set g,72
.set h,76

.set m0,80  /* keep address aligned at 16 */
.set m1,96
.set m2,112
.set m3,128
.set m4,144
.set m5,160
.set m6,176
.set m7,192
.set m8,208
.set m9,224
.set m10,240
.set m11,256
.set m12,272
.set m13,288
.set m14,304
.set m15,320
.set m15h,328
.set m15l,320
.set m,80
#endif

/*	Same as:
	digest[0] = H[0]; digest[1] = H[1]; digest[2] = H[2]; digest[3] = H[3];
	digest[4] = H[4]; digest[5] = H[5]; digest[6] = H[6]; digest[7] = H[7];
*/
.macro init_H
	movdqa		H0_1(rip),xmm0
	movdqa		xmm0,H0(rdi)
	movdqa		H0_2(rip),xmm0
	movdqa		xmm0,H4(rdi)
	pxor		xmm0,xmm0
.endm

/*	Init state
	 * a = H0; b = H1; c = H2; d = H3;
	 * e = H4; f = H5; g = H6; h = H7;
	 * ===
	 * ba = mm0 = H1H0
	 * dc = mm1 = H3H2
	 * fe = mm2 = H5H4
	 * hg = mm3 = H7H6					              */
.macro init_abcdefgh
	movq		H0(rdi),mm0
	movq		H2(rdi),mm1
	movq		H4(rdi),mm2
	movq		H6(rdi),mm3
.endm

/*
 * instruction set:
 * word = 16 bit
 * doubleword = 32 bit = dq
 * quad = quadword = 64 bit
 * double quadword = 128
 */

// aceg
// bdfh
.macro get_aceg w mm
	/* mm = b a */
	movd		\mm,\w /* w = a */
.endm

/* tmp0q and tmp0l must be the same register */
/* tmp1q and tmp1l must be the same register */
.macro set_aceg w mm tmp0q tmp0l tmp1q tmp1l
	movq		\mm,\tmp0q /* tmp0q = b a */
	andq		mask1(rip),\tmp0q /* tmp0q = b 00 */
	movl		\w,\tmp1l /* tmp1l = a */
//	shlq		$0,\tmp1q /* tmp1l = 0 a */
	xorq		\tmp1q,\tmp0q /* tmp0q = b a */
	movq		\tmp0q,\mm /* mm = b a */
.endm

/* tmpq and tmpl must be the same register */
.macro get_bdfh w mm tmpq tmpl
	movq		\mm,\tmpq /* tmpq = b a */
	shrq		$32,\tmpq /* tmpq = 00 b */
	movl		\tmpl,\w /* w = b */
.endm

/* tmp0q and tmp0l must be the same register */
/* tmp1q and tmp1l must be the same register */
.macro set_bdfh w mm tmp0q tmp0l tmp1q tmp1l
	movq		\mm,\tmp0q /* tmp0q = b a */
	andq		mask0(rip),\tmp0q /* tmp1q = 00 a */
	movl		\w,\tmp1l /* tmp1l = 00 b */
	shlq		$32,\tmp1q /* tmp1l = b 00 */
	xorq		\tmp1q,\tmp0q /* tmp0q = b a */
	movq		\tmp0q,\mm /* mm = b a */
.endm

.macro get_a w
	get_aceg	 \w,mm0
.endm

.macro set_a w tmp0q tmp0l tmp1q tmp1l
	set_aceg 	\w,mm0,\tmp0q,\tmp0l,\tmp1q,\tmp1l
.endm

.macro get_c w
	get_aceg 	\w,mm1
.endm

.macro set_c w tmp0q tmp0l tmp1q tmp1l
	set_aceg	\w,mm1,\tmp0q,\tmp0l,\tmp1q,\tmp1l
.endm

.macro get_e w
	get_aceg	\w,mm2
.endm

.macro set_e w tmp0q tmp0l tmp1q tmp1l
	set_aceg	\w,mm2,\tmp0q,\tmp0l,\tmp1q,\tmp1l
.endm

.macro get_g w
	get_aceg	\w,mm3
.endm

.macro set_g w tmp0q tmp0l tmp1q tmp1l
	set_aceg	\w,mm3,\tmp0q,\tmp0l,\tmp1q,\tmp1l
.endm

.macro get_b w tmpq tmpl
	get_bdfh	\w,mm0,\tmpq,\tmpl
.endm

.macro set_b w tmp0q tmp0l tmp1q tmp1l
	set_bdfh	\w,mm0,\tmp0q,\tmp0l,\tmp1q,\tmp1l
.endm

.macro get_d w tmpq tmpl
	get_bdfh	\w,mm1,\tmpq,\tmpl
.endm

.macro set_d w tmp0q tmp0l tmp1q tmp1l
	set_bdfh	\w,mm1,\tmp0q,\tmp0l,\tmp1q,\tmp1l
.endm

.macro get_f w tmpq tmpl
	get_bdfh	\w,mm2,\tmpq,\tmpl
.endm

.macro set_f w tmp0q tmp0l tmp1q tmp1l
	set_bdfh	\w,mm2,\tmp0q,\tmp0l,\tmp1q,\tmp1l
.endm

.macro get_h w tmpq tmpl
	get_bdfh	\w,mm3,\tmpq,\tmpl
.endm

.macro set_h w tmp0q tmp0l tmp1q tmp1l
	set_bdfh	\w,mm3,\tmp0q,\tmp0l,\tmp1q,\tmp1l
.endm

#ifdef DEBUG
.macro pushdqw xmm
	/* rsp is unaligned */
	subq		$16,rsp
	movdqu		\xmm,(rsp)
.endm

.macro popdqw xmm
	/* rsp is unaligned */
	movdqu		(rsp),\xmm
	addq		$16,rsp
.endm

.macro pushdw mm
	subq		$8,rsp
	movq		\mm,(rsp)
.endm

.macro popdw mm
	movq		(rsp),\mm
	addq		$8,rsp
.endm

/* 344 total */
.macro pusha64
	pushdqw		xmm0 /* keep aligned at 16 by keeping base 0 */
	pushdqw		xmm1
	pushdqw		xmm2
	pushdqw		xmm3
	pushdqw		xmm4
	pushdqw		xmm5
	pushdqw		xmm6
	pushdqw		xmm7
	pushdqw		xmm8
	pushdqw		xmm9
	pushdqw		xmm10
	pushdqw		xmm11
	pushdqw		xmm12
	pushdqw		xmm13
	pushdqw		xmm14
	pushdqw		xmm15
	pushdw		mm0
	pushdw		mm1
	pushdw		mm2
	pushdw		mm3
	pushdw		mm4
	pushdw		mm5
	pushdw		mm6
	pushdw		mm7
	pushq		rax
	pushq		rbx
	pushq		rcx
	pushq		rdx
	pushq		rsi
	pushq		rdi
	subq		$8,rsp /* aligned to 16 bytes */
.endm

.macro popa64
	addq		$8,rsp /* aligned to 16 bytes */
	popq		rdi
	popq		rsi
	popq		rdx
	popq		rcx
	popq		rbx
	popq		rax
	popdw		mm7
	popdw		mm6
	popdw		mm5
	popdw		mm4
	popdw		mm3
	popdw		mm2
	popdw		mm1
	popdw		mm0
	popdqw		xmm15
	popdqw		xmm14
	popdqw		xmm13
	popdqw		xmm12
	popdqw		xmm11
	popdqw		xmm10
	popdqw		xmm9
	popdqw		xmm8
	popdqw		xmm7
	popdqw		xmm6
	popdqw		xmm5
	popdqw		xmm4
	popdqw		xmm3
	popdqw		xmm2
	popdqw		xmm1
	popdqw		xmm0
.endm
#endif

.macro clear_state
	/* for (i=0; < state_size; i++)
		state[i] = 0;						      */
	movq		$0,rcx
	movq		rdi,rbx
0:	cmpq		$state_size,rcx
	jl		1f
	jmp		2f
1:		movb		$0,(rbx)
		incq		rbx
		incl		ecx
		jmp		0b
2:
.endm

.macro clear_W
	pxor		xmm0,xmm0
	pxor		xmm1,xmm1
	pxor		xmm2,xmm2
	pxor		xmm3,xmm3
	pxor		xmm4,xmm4
	pxor		xmm5,xmm5
	pxor		xmm6,xmm6
	pxor		xmm7,xmm7
	pxor		xmm8,xmm8
	pxor		xmm9,xmm9
	pxor		xmm10,xmm10
	pxor		xmm11,xmm11
	pxor		xmm12,xmm12
	pxor		xmm13,xmm13
	pxor		xmm14,xmm14
	pxor		xmm15,xmm15
.endm

.macro clear_A
	pxor		mm0,mm0
	pxor		mm1,mm1
	pxor		mm2,mm2
	pxor		mm3,mm3
	pxor		mm4,mm4
	pxor		mm5,mm5
	pxor		mm6,mm6
	pxor		mm7,mm7
.endm

.macro clear_gpr
	xorq		rax,rax
	xorq		rbx,rbx
	xorq		rcx,rcx
	xorq		rdx,rdx
	xorq		r8,r8
	xorq		r9,r9
	xorq		r10,r10
	xorq		r11,r11
	xorq		r12,r12
	xorq		r13,r13
	xorq		r14,r14
.endm

#ifdef HAVE_SSE4_1
.macro _get_w w ci xmm
	pextrd          $\ci,\xmm,\w
.endm

.macro _set_w w ci xmm
	pinsrd          $\ci,\w,\xmm
.endm
#elif defined(HAVE_SSE2)
/* ci must be 0 4 8 12 */
.macro _get_w w ci xmm txmm
	movdqa          \xmm,\txmm
	psrldq          $\ci,\txmm
	movd            \txmm,\w
.endm

.macro _get_w_alt_c0 w mm
	movd		\mm,\w
.endm

.macro _get_w_alt_c1 w mm gpr0q gpr0l
	movq		\mm,\gpr0q
	shrq		$32,\gpr0q
	movl		\gpr0l,\w
.endm

/* CI must be 0,4,8,12 */
.macro _set_w w ci xmm txmm gpr0l
	movl		$0xffffffff,\gpr0l
	movd		\gpr0l,\txmm
	pslldq		$\ci,\txmm
	pandn		\xmm,\txmm
	movdqa		\txmm,\xmm
	movd		\w,\txmm
	pslldq		$\ci,\txmm
	pxor		\txmm,\xmm
.endm

/* CI is only 0 or 32 */
.macro _set_w_alt w ci mm gpr0q gpr0l gpr1q
	movl            $0xffffffff,\gpr0l
	movq            \mm,\gpr1q
	shlq            $\ci,\gpr0q
#ifdef HAVE_BMI
	andnq		\gpr1q,\gpr0q,\gpr1q
#else
	notq            \gpr0q
	andq            \gpr0q,\gpr1q
#endif
	movl            \w,\gpr0l
	shlq            $\ci,\gpr0q
	xorq            \gpr0q,\gpr1q
	movq            \gpr1q,\mm
.endm
#endif // HAVE_SSE4_1

#ifdef HAVE_SSE4_1

.macro get_w		w wi trax teax trdx tedx
	movl		\wi,\tedx
	movl		get_w_sse4_1_jt\@(,\trdx,4),\teax
	cltq		/* sign extend address */
	leaq		get_w_sse4_1_jt\@(rip),\trdx
	addq		\trdx,\trax /* base address + offset */

	jmp 		*\trax /* essentially goto sign_extend32to64(get_w_sse4_1_jt[wi]) */

	/* Generated by gen_asm_reljump.py */
/* Get wi jump table for SSE4.1 */
.section .rodata
.align 4
get_w_sse4_1_jt\@:
.long	.L3000\@-get_w_sse4_1_jt\@
.long	.L3001\@-get_w_sse4_1_jt\@
.long	.L3002\@-get_w_sse4_1_jt\@
.long	.L3003\@-get_w_sse4_1_jt\@
.long	.L3004\@-get_w_sse4_1_jt\@
.long	.L3005\@-get_w_sse4_1_jt\@
.long	.L3006\@-get_w_sse4_1_jt\@
.long	.L3007\@-get_w_sse4_1_jt\@
.long	.L3008\@-get_w_sse4_1_jt\@
.long	.L3009\@-get_w_sse4_1_jt\@
.long	.L3010\@-get_w_sse4_1_jt\@
.long	.L3011\@-get_w_sse4_1_jt\@
.long	.L3012\@-get_w_sse4_1_jt\@
.long	.L3013\@-get_w_sse4_1_jt\@
.long	.L3014\@-get_w_sse4_1_jt\@
.long	.L3015\@-get_w_sse4_1_jt\@
.long	.L3016\@-get_w_sse4_1_jt\@
.long	.L3017\@-get_w_sse4_1_jt\@
.long	.L3018\@-get_w_sse4_1_jt\@
.long	.L3019\@-get_w_sse4_1_jt\@
.long	.L3020\@-get_w_sse4_1_jt\@
.long	.L3021\@-get_w_sse4_1_jt\@
.long	.L3022\@-get_w_sse4_1_jt\@
.long	.L3023\@-get_w_sse4_1_jt\@
.long	.L3024\@-get_w_sse4_1_jt\@
.long	.L3025\@-get_w_sse4_1_jt\@
.long	.L3026\@-get_w_sse4_1_jt\@
.long	.L3027\@-get_w_sse4_1_jt\@
.long	.L3028\@-get_w_sse4_1_jt\@
.long	.L3029\@-get_w_sse4_1_jt\@
.long	.L3030\@-get_w_sse4_1_jt\@
.long	.L3031\@-get_w_sse4_1_jt\@
.long	.L3032\@-get_w_sse4_1_jt\@
.long	.L3033\@-get_w_sse4_1_jt\@
.long	.L3034\@-get_w_sse4_1_jt\@
.long	.L3035\@-get_w_sse4_1_jt\@
.long	.L3036\@-get_w_sse4_1_jt\@
.long	.L3037\@-get_w_sse4_1_jt\@
.long	.L3038\@-get_w_sse4_1_jt\@
.long	.L3039\@-get_w_sse4_1_jt\@
.long	.L3040\@-get_w_sse4_1_jt\@
.long	.L3041\@-get_w_sse4_1_jt\@
.long	.L3042\@-get_w_sse4_1_jt\@
.long	.L3043\@-get_w_sse4_1_jt\@
.long	.L3044\@-get_w_sse4_1_jt\@
.long	.L3045\@-get_w_sse4_1_jt\@
.long	.L3046\@-get_w_sse4_1_jt\@
.long	.L3047\@-get_w_sse4_1_jt\@
.long	.L3048\@-get_w_sse4_1_jt\@
.long	.L3049\@-get_w_sse4_1_jt\@
.long	.L3050\@-get_w_sse4_1_jt\@
.long	.L3051\@-get_w_sse4_1_jt\@
.long	.L3052\@-get_w_sse4_1_jt\@
.long	.L3053\@-get_w_sse4_1_jt\@
.long	.L3054\@-get_w_sse4_1_jt\@
.long	.L3055\@-get_w_sse4_1_jt\@
.long	.L3056\@-get_w_sse4_1_jt\@
.long	.L3057\@-get_w_sse4_1_jt\@
.long	.L3058\@-get_w_sse4_1_jt\@
.long	.L3059\@-get_w_sse4_1_jt\@
.long	.L3060\@-get_w_sse4_1_jt\@
.long	.L3061\@-get_w_sse4_1_jt\@
.long	.L3062\@-get_w_sse4_1_jt\@
.long	.L3063\@-get_w_sse4_1_jt\@
.long	.L3064\@-get_w_sse4_1_jt\@
.text
.L3000\@:	_get_w \w,0,xmm0
	jmp		.L3064\@
.L3001\@:	_get_w \w,1,xmm0
	jmp		.L3064\@
.L3002\@:	_get_w \w,2,xmm0
	jmp		.L3064\@
.L3003\@:	_get_w \w,3,xmm0
	jmp		.L3064\@
.L3004\@:	_get_w \w,0,xmm1
	jmp		.L3064\@
.L3005\@:	_get_w \w,1,xmm1
	jmp		.L3064\@
.L3006\@:	_get_w \w,2,xmm1
	jmp		.L3064\@
.L3007\@:	_get_w \w,3,xmm1
	jmp		.L3064\@
.L3008\@:	_get_w \w,0,xmm2
	jmp		.L3064\@
.L3009\@:	_get_w \w,1,xmm2
	jmp		.L3064\@
.L3010\@:	_get_w \w,2,xmm2
	jmp		.L3064\@
.L3011\@:	_get_w \w,3,xmm2
	jmp		.L3064\@
.L3012\@:	_get_w \w,0,xmm3
	jmp		.L3064\@
.L3013\@:	_get_w \w,1,xmm3
	jmp		.L3064\@
.L3014\@:	_get_w \w,2,xmm3
	jmp		.L3064\@
.L3015\@:	_get_w \w,3,xmm3
	jmp		.L3064\@
.L3016\@:	_get_w \w,0,xmm4
	jmp		.L3064\@
.L3017\@:	_get_w \w,1,xmm4
	jmp		.L3064\@
.L3018\@:	_get_w \w,2,xmm4
	jmp		.L3064\@
.L3019\@:	_get_w \w,3,xmm4
	jmp		.L3064\@
.L3020\@:	_get_w \w,0,xmm5
	jmp		.L3064\@
.L3021\@:	_get_w \w,1,xmm5
	jmp		.L3064\@
.L3022\@:	_get_w \w,2,xmm5
	jmp		.L3064\@
.L3023\@:	_get_w \w,3,xmm5
	jmp		.L3064\@
.L3024\@:	_get_w \w,0,xmm6
	jmp		.L3064\@
.L3025\@:	_get_w \w,1,xmm6
	jmp		.L3064\@
.L3026\@:	_get_w \w,2,xmm6
	jmp		.L3064\@
.L3027\@:	_get_w \w,3,xmm6
	jmp		.L3064\@
.L3028\@:	_get_w \w,0,xmm7
	jmp		.L3064\@
.L3029\@:	_get_w \w,1,xmm7
	jmp		.L3064\@
.L3030\@:	_get_w \w,2,xmm7
	jmp		.L3064\@
.L3031\@:	_get_w \w,3,xmm7
	jmp		.L3064\@
.L3032\@:	_get_w \w,0,xmm8
	jmp		.L3064\@
.L3033\@:	_get_w \w,1,xmm8
	jmp		.L3064\@
.L3034\@:	_get_w \w,2,xmm8
	jmp		.L3064\@
.L3035\@:	_get_w \w,3,xmm8
	jmp		.L3064\@
.L3036\@:	_get_w \w,0,xmm9
	jmp		.L3064\@
.L3037\@:	_get_w \w,1,xmm9
	jmp		.L3064\@
.L3038\@:	_get_w \w,2,xmm9
	jmp		.L3064\@
.L3039\@:	_get_w \w,3,xmm9
	jmp		.L3064\@
.L3040\@:	_get_w \w,0,xmm10
	jmp		.L3064\@
.L3041\@:	_get_w \w,1,xmm10
	jmp		.L3064\@
.L3042\@:	_get_w \w,2,xmm10
	jmp		.L3064\@
.L3043\@:	_get_w \w,3,xmm10
	jmp		.L3064\@
.L3044\@:	_get_w \w,0,xmm11
	jmp		.L3064\@
.L3045\@:	_get_w \w,1,xmm11
	jmp		.L3064\@
.L3046\@:	_get_w \w,2,xmm11
	jmp		.L3064\@
.L3047\@:	_get_w \w,3,xmm11
	jmp		.L3064\@
.L3048\@:	_get_w \w,0,xmm12
	jmp		.L3064\@
.L3049\@:	_get_w \w,1,xmm12
	jmp		.L3064\@
.L3050\@:	_get_w \w,2,xmm12
	jmp		.L3064\@
.L3051\@:	_get_w \w,3,xmm12
	jmp		.L3064\@
.L3052\@:	_get_w \w,0,xmm13
	jmp		.L3064\@
.L3053\@:	_get_w \w,1,xmm13
	jmp		.L3064\@
.L3054\@:	_get_w \w,2,xmm13
	jmp		.L3064\@
.L3055\@:	_get_w \w,3,xmm13
	jmp		.L3064\@
.L3056\@:	_get_w \w,0,xmm14
	jmp		.L3064\@
.L3057\@:	_get_w \w,1,xmm14
	jmp		.L3064\@
.L3058\@:	_get_w \w,2,xmm14
	jmp		.L3064\@
.L3059\@:	_get_w \w,3,xmm14
	jmp		.L3064\@
.L3060\@:	_get_w \w,0,xmm15
	jmp		.L3064\@
.L3061\@:	_get_w \w,1,xmm15
	jmp		.L3064\@
.L3062\@:	_get_w \w,2,xmm15
	jmp		.L3064\@
.L3063\@:	_get_w \w,3,xmm15
	jmp		.L3064\@

.L3064\@:

.endm

.macro set_w		w wi trax teax trdx tedx
	movl		\wi,\tedx
	movl		set_w_sse4_1_jt\@(,\trdx,4),\teax
	cltq		/* sign extend address */
	leaq		set_w_sse4_1_jt\@(rip),\trdx
	addq		\trdx,\trax /* base address + offset */

	jmp 		*\trax /* essentially goto sign_extend32to64(set_w_sse4_1_jt[wi]) */

	/* Generated by gen_asm_reljump.py */
/* Set wi jump table for SSE4.1 */
.section .rodata
.align 4
set_w_sse4_1_jt\@:
.long	.L3500\@-set_w_sse4_1_jt\@
.long	.L3501\@-set_w_sse4_1_jt\@
.long	.L3502\@-set_w_sse4_1_jt\@
.long	.L3503\@-set_w_sse4_1_jt\@
.long	.L3504\@-set_w_sse4_1_jt\@
.long	.L3505\@-set_w_sse4_1_jt\@
.long	.L3506\@-set_w_sse4_1_jt\@
.long	.L3507\@-set_w_sse4_1_jt\@
.long	.L3508\@-set_w_sse4_1_jt\@
.long	.L3509\@-set_w_sse4_1_jt\@
.long	.L3510\@-set_w_sse4_1_jt\@
.long	.L3511\@-set_w_sse4_1_jt\@
.long	.L3512\@-set_w_sse4_1_jt\@
.long	.L3513\@-set_w_sse4_1_jt\@
.long	.L3514\@-set_w_sse4_1_jt\@
.long	.L3515\@-set_w_sse4_1_jt\@
.long	.L3516\@-set_w_sse4_1_jt\@
.long	.L3517\@-set_w_sse4_1_jt\@
.long	.L3518\@-set_w_sse4_1_jt\@
.long	.L3519\@-set_w_sse4_1_jt\@
.long	.L3520\@-set_w_sse4_1_jt\@
.long	.L3521\@-set_w_sse4_1_jt\@
.long	.L3522\@-set_w_sse4_1_jt\@
.long	.L3523\@-set_w_sse4_1_jt\@
.long	.L3524\@-set_w_sse4_1_jt\@
.long	.L3525\@-set_w_sse4_1_jt\@
.long	.L3526\@-set_w_sse4_1_jt\@
.long	.L3527\@-set_w_sse4_1_jt\@
.long	.L3528\@-set_w_sse4_1_jt\@
.long	.L3529\@-set_w_sse4_1_jt\@
.long	.L3530\@-set_w_sse4_1_jt\@
.long	.L3531\@-set_w_sse4_1_jt\@
.long	.L3532\@-set_w_sse4_1_jt\@
.long	.L3533\@-set_w_sse4_1_jt\@
.long	.L3534\@-set_w_sse4_1_jt\@
.long	.L3535\@-set_w_sse4_1_jt\@
.long	.L3536\@-set_w_sse4_1_jt\@
.long	.L3537\@-set_w_sse4_1_jt\@
.long	.L3538\@-set_w_sse4_1_jt\@
.long	.L3539\@-set_w_sse4_1_jt\@
.long	.L3540\@-set_w_sse4_1_jt\@
.long	.L3541\@-set_w_sse4_1_jt\@
.long	.L3542\@-set_w_sse4_1_jt\@
.long	.L3543\@-set_w_sse4_1_jt\@
.long	.L3544\@-set_w_sse4_1_jt\@
.long	.L3545\@-set_w_sse4_1_jt\@
.long	.L3546\@-set_w_sse4_1_jt\@
.long	.L3547\@-set_w_sse4_1_jt\@
.long	.L3548\@-set_w_sse4_1_jt\@
.long	.L3549\@-set_w_sse4_1_jt\@
.long	.L3550\@-set_w_sse4_1_jt\@
.long	.L3551\@-set_w_sse4_1_jt\@
.long	.L3552\@-set_w_sse4_1_jt\@
.long	.L3553\@-set_w_sse4_1_jt\@
.long	.L3554\@-set_w_sse4_1_jt\@
.long	.L3555\@-set_w_sse4_1_jt\@
.long	.L3556\@-set_w_sse4_1_jt\@
.long	.L3557\@-set_w_sse4_1_jt\@
.long	.L3558\@-set_w_sse4_1_jt\@
.long	.L3559\@-set_w_sse4_1_jt\@
.long	.L3560\@-set_w_sse4_1_jt\@
.long	.L3561\@-set_w_sse4_1_jt\@
.long	.L3562\@-set_w_sse4_1_jt\@
.long	.L3563\@-set_w_sse4_1_jt\@
.long	.L3564\@-set_w_sse4_1_jt\@
.text
.L3500\@:	_set_w \w,0,xmm0
	jmp		.L3564\@
.L3501\@:	_set_w \w,1,xmm0
	jmp		.L3564\@
.L3502\@:	_set_w \w,2,xmm0
	jmp		.L3564\@
.L3503\@:	_set_w \w,3,xmm0
	jmp		.L3564\@
.L3504\@:	_set_w \w,0,xmm1
	jmp		.L3564\@
.L3505\@:	_set_w \w,1,xmm1
	jmp		.L3564\@
.L3506\@:	_set_w \w,2,xmm1
	jmp		.L3564\@
.L3507\@:	_set_w \w,3,xmm1
	jmp		.L3564\@
.L3508\@:	_set_w \w,0,xmm2
	jmp		.L3564\@
.L3509\@:	_set_w \w,1,xmm2
	jmp		.L3564\@
.L3510\@:	_set_w \w,2,xmm2
	jmp		.L3564\@
.L3511\@:	_set_w \w,3,xmm2
	jmp		.L3564\@
.L3512\@:	_set_w \w,0,xmm3
	jmp		.L3564\@
.L3513\@:	_set_w \w,1,xmm3
	jmp		.L3564\@
.L3514\@:	_set_w \w,2,xmm3
	jmp		.L3564\@
.L3515\@:	_set_w \w,3,xmm3
	jmp		.L3564\@
.L3516\@:	_set_w \w,0,xmm4
	jmp		.L3564\@
.L3517\@:	_set_w \w,1,xmm4
	jmp		.L3564\@
.L3518\@:	_set_w \w,2,xmm4
	jmp		.L3564\@
.L3519\@:	_set_w \w,3,xmm4
	jmp		.L3564\@
.L3520\@:	_set_w \w,0,xmm5
	jmp		.L3564\@
.L3521\@:	_set_w \w,1,xmm5
	jmp		.L3564\@
.L3522\@:	_set_w \w,2,xmm5
	jmp		.L3564\@
.L3523\@:	_set_w \w,3,xmm5
	jmp		.L3564\@
.L3524\@:	_set_w \w,0,xmm6
	jmp		.L3564\@
.L3525\@:	_set_w \w,1,xmm6
	jmp		.L3564\@
.L3526\@:	_set_w \w,2,xmm6
	jmp		.L3564\@
.L3527\@:	_set_w \w,3,xmm6
	jmp		.L3564\@
.L3528\@:	_set_w \w,0,xmm7
	jmp		.L3564\@
.L3529\@:	_set_w \w,1,xmm7
	jmp		.L3564\@
.L3530\@:	_set_w \w,2,xmm7
	jmp		.L3564\@
.L3531\@:	_set_w \w,3,xmm7
	jmp		.L3564\@
.L3532\@:	_set_w \w,0,xmm8
	jmp		.L3564\@
.L3533\@:	_set_w \w,1,xmm8
	jmp		.L3564\@
.L3534\@:	_set_w \w,2,xmm8
	jmp		.L3564\@
.L3535\@:	_set_w \w,3,xmm8
	jmp		.L3564\@
.L3536\@:	_set_w \w,0,xmm9
	jmp		.L3564\@
.L3537\@:	_set_w \w,1,xmm9
	jmp		.L3564\@
.L3538\@:	_set_w \w,2,xmm9
	jmp		.L3564\@
.L3539\@:	_set_w \w,3,xmm9
	jmp		.L3564\@
.L3540\@:	_set_w \w,0,xmm10
	jmp		.L3564\@
.L3541\@:	_set_w \w,1,xmm10
	jmp		.L3564\@
.L3542\@:	_set_w \w,2,xmm10
	jmp		.L3564\@
.L3543\@:	_set_w \w,3,xmm10
	jmp		.L3564\@
.L3544\@:	_set_w \w,0,xmm11
	jmp		.L3564\@
.L3545\@:	_set_w \w,1,xmm11
	jmp		.L3564\@
.L3546\@:	_set_w \w,2,xmm11
	jmp		.L3564\@
.L3547\@:	_set_w \w,3,xmm11
	jmp		.L3564\@
.L3548\@:	_set_w \w,0,xmm12
	jmp		.L3564\@
.L3549\@:	_set_w \w,1,xmm12
	jmp		.L3564\@
.L3550\@:	_set_w \w,2,xmm12
	jmp		.L3564\@
.L3551\@:	_set_w \w,3,xmm12
	jmp		.L3564\@
.L3552\@:	_set_w \w,0,xmm13
	jmp		.L3564\@
.L3553\@:	_set_w \w,1,xmm13
	jmp		.L3564\@
.L3554\@:	_set_w \w,2,xmm13
	jmp		.L3564\@
.L3555\@:	_set_w \w,3,xmm13
	jmp		.L3564\@
.L3556\@:	_set_w \w,0,xmm14
	jmp		.L3564\@
.L3557\@:	_set_w \w,1,xmm14
	jmp		.L3564\@
.L3558\@:	_set_w \w,2,xmm14
	jmp		.L3564\@
.L3559\@:	_set_w \w,3,xmm14
	jmp		.L3564\@
.L3560\@:	_set_w \w,0,xmm15
	jmp		.L3564\@
.L3561\@:	_set_w \w,1,xmm15
	jmp		.L3564\@
.L3562\@:	_set_w \w,2,xmm15
	jmp		.L3564\@
.L3563\@:	_set_w \w,3,xmm15
	jmp		.L3564\@

.L3564\@:

.endm

#elif defined(HAVE_SSE2)

.macro get_w		w wi trax teax trdx tedx gpr0q gpr0l
	movl		\wi,\tedx
	movl		get_w_sse2_jt\@(,\trdx,4),\teax
	cltq		/* sign extend address */
	leaq		get_w_sse2_jt\@(rip),\trdx
	addq		\trdx,\trax /* base address + offset */

	jmp 		*\trax /* essentially goto sign_extend32to64(get_w_sse2_jt[wi]) */

	/* Generated by gen_asm_reljump.py */
/* Get wi jump table for SSE2 */
.section .rodata
.align 4
get_w_sse2_jt\@:
.long	.L4000\@-get_w_sse2_jt\@
.long	.L4001\@-get_w_sse2_jt\@
.long	.L4002\@-get_w_sse2_jt\@
.long	.L4003\@-get_w_sse2_jt\@
.long	.L4004\@-get_w_sse2_jt\@
.long	.L4005\@-get_w_sse2_jt\@
.long	.L4006\@-get_w_sse2_jt\@
.long	.L4007\@-get_w_sse2_jt\@
.long	.L4008\@-get_w_sse2_jt\@
.long	.L4009\@-get_w_sse2_jt\@
.long	.L4010\@-get_w_sse2_jt\@
.long	.L4011\@-get_w_sse2_jt\@
.long	.L4012\@-get_w_sse2_jt\@
.long	.L4013\@-get_w_sse2_jt\@
.long	.L4014\@-get_w_sse2_jt\@
.long	.L4015\@-get_w_sse2_jt\@
.long	.L4016\@-get_w_sse2_jt\@
.long	.L4017\@-get_w_sse2_jt\@
.long	.L4018\@-get_w_sse2_jt\@
.long	.L4019\@-get_w_sse2_jt\@
.long	.L4020\@-get_w_sse2_jt\@
.long	.L4021\@-get_w_sse2_jt\@
.long	.L4022\@-get_w_sse2_jt\@
.long	.L4023\@-get_w_sse2_jt\@
.long	.L4024\@-get_w_sse2_jt\@
.long	.L4025\@-get_w_sse2_jt\@
.long	.L4026\@-get_w_sse2_jt\@
.long	.L4027\@-get_w_sse2_jt\@
.long	.L4028\@-get_w_sse2_jt\@
.long	.L4029\@-get_w_sse2_jt\@
.long	.L4030\@-get_w_sse2_jt\@
.long	.L4031\@-get_w_sse2_jt\@
.long	.L4032\@-get_w_sse2_jt\@
.long	.L4033\@-get_w_sse2_jt\@
.long	.L4034\@-get_w_sse2_jt\@
.long	.L4035\@-get_w_sse2_jt\@
.long	.L4036\@-get_w_sse2_jt\@
.long	.L4037\@-get_w_sse2_jt\@
.long	.L4038\@-get_w_sse2_jt\@
.long	.L4039\@-get_w_sse2_jt\@
.long	.L4040\@-get_w_sse2_jt\@
.long	.L4041\@-get_w_sse2_jt\@
.long	.L4042\@-get_w_sse2_jt\@
.long	.L4043\@-get_w_sse2_jt\@
.long	.L4044\@-get_w_sse2_jt\@
.long	.L4045\@-get_w_sse2_jt\@
.long	.L4046\@-get_w_sse2_jt\@
.long	.L4047\@-get_w_sse2_jt\@
.long	.L4048\@-get_w_sse2_jt\@
.long	.L4049\@-get_w_sse2_jt\@
.long	.L4050\@-get_w_sse2_jt\@
.long	.L4051\@-get_w_sse2_jt\@
.long	.L4052\@-get_w_sse2_jt\@
.long	.L4053\@-get_w_sse2_jt\@
.long	.L4054\@-get_w_sse2_jt\@
.long	.L4055\@-get_w_sse2_jt\@
.long	.L4056\@-get_w_sse2_jt\@
.long	.L4057\@-get_w_sse2_jt\@
.long	.L4058\@-get_w_sse2_jt\@
.long	.L4059\@-get_w_sse2_jt\@
.long	.L4060\@-get_w_sse2_jt\@
.long	.L4061\@-get_w_sse2_jt\@
.long	.L4062\@-get_w_sse2_jt\@
.long	.L4063\@-get_w_sse2_jt\@
.long	.L4064\@-get_w_sse2_jt\@
.text
.L4000\@:	_get_w \w,0,xmm0,xmm15
	jmp		.L4064\@
.L4001\@:	_get_w \w,4,xmm0,xmm15
	jmp		.L4064\@
.L4002\@:	_get_w \w,8,xmm0,xmm15
	jmp		.L4064\@
.L4003\@:	_get_w \w,12,xmm0,xmm15
	jmp		.L4064\@
.L4004\@:	_get_w \w,0,xmm1,xmm15
	jmp		.L4064\@
.L4005\@:	_get_w \w,4,xmm1,xmm15
	jmp		.L4064\@
.L4006\@:	_get_w \w,8,xmm1,xmm15
	jmp		.L4064\@
.L4007\@:	_get_w \w,12,xmm1,xmm15
	jmp		.L4064\@
.L4008\@:	_get_w \w,0,xmm2,xmm15
	jmp		.L4064\@
.L4009\@:	_get_w \w,4,xmm2,xmm15
	jmp		.L4064\@
.L4010\@:	_get_w \w,8,xmm2,xmm15
	jmp		.L4064\@
.L4011\@:	_get_w \w,12,xmm2,xmm15
	jmp		.L4064\@
.L4012\@:	_get_w \w,0,xmm3,xmm15
	jmp		.L4064\@
.L4013\@:	_get_w \w,4,xmm3,xmm15
	jmp		.L4064\@
.L4014\@:	_get_w \w,8,xmm3,xmm15
	jmp		.L4064\@
.L4015\@:	_get_w \w,12,xmm3,xmm15
	jmp		.L4064\@
.L4016\@:	_get_w \w,0,xmm4,xmm15
	jmp		.L4064\@
.L4017\@:	_get_w \w,4,xmm4,xmm15
	jmp		.L4064\@
.L4018\@:	_get_w \w,8,xmm4,xmm15
	jmp		.L4064\@
.L4019\@:	_get_w \w,12,xmm4,xmm15
	jmp		.L4064\@
.L4020\@:	_get_w \w,0,xmm5,xmm15
	jmp		.L4064\@
.L4021\@:	_get_w \w,4,xmm5,xmm15
	jmp		.L4064\@
.L4022\@:	_get_w \w,8,xmm5,xmm15
	jmp		.L4064\@
.L4023\@:	_get_w \w,12,xmm5,xmm15
	jmp		.L4064\@
.L4024\@:	_get_w \w,0,xmm6,xmm15
	jmp		.L4064\@
.L4025\@:	_get_w \w,4,xmm6,xmm15
	jmp		.L4064\@
.L4026\@:	_get_w \w,8,xmm6,xmm15
	jmp		.L4064\@
.L4027\@:	_get_w \w,12,xmm6,xmm15
	jmp		.L4064\@
.L4028\@:	_get_w \w,0,xmm7,xmm15
	jmp		.L4064\@
.L4029\@:	_get_w \w,4,xmm7,xmm15
	jmp		.L4064\@
.L4030\@:	_get_w \w,8,xmm7,xmm15
	jmp		.L4064\@
.L4031\@:	_get_w \w,12,xmm7,xmm15
	jmp		.L4064\@
.L4032\@:	_get_w \w,0,xmm8,xmm15
	jmp		.L4064\@
.L4033\@:	_get_w \w,4,xmm8,xmm15
	jmp		.L4064\@
.L4034\@:	_get_w \w,8,xmm8,xmm15
	jmp		.L4064\@
.L4035\@:	_get_w \w,12,xmm8,xmm15
	jmp		.L4064\@
.L4036\@:	_get_w \w,0,xmm9,xmm15
	jmp		.L4064\@
.L4037\@:	_get_w \w,4,xmm9,xmm15
	jmp		.L4064\@
.L4038\@:	_get_w \w,8,xmm9,xmm15
	jmp		.L4064\@
.L4039\@:	_get_w \w,12,xmm9,xmm15
	jmp		.L4064\@
.L4040\@:	_get_w \w,0,xmm10,xmm15
	jmp		.L4064\@
.L4041\@:	_get_w \w,4,xmm10,xmm15
	jmp		.L4064\@
.L4042\@:	_get_w \w,8,xmm10,xmm15
	jmp		.L4064\@
.L4043\@:	_get_w \w,12,xmm10,xmm15
	jmp		.L4064\@
.L4044\@:	_get_w \w,0,xmm11,xmm15
	jmp		.L4064\@
.L4045\@:	_get_w \w,4,xmm11,xmm15
	jmp		.L4064\@
.L4046\@:	_get_w \w,8,xmm11,xmm15
	jmp		.L4064\@
.L4047\@:	_get_w \w,12,xmm11,xmm15
	jmp		.L4064\@
.L4048\@:	_get_w \w,0,xmm12,xmm15
	jmp		.L4064\@
.L4049\@:	_get_w \w,4,xmm12,xmm15
	jmp		.L4064\@
.L4050\@:	_get_w \w,8,xmm12,xmm15
	jmp		.L4064\@
.L4051\@:	_get_w \w,12,xmm12,xmm15
	jmp		.L4064\@
.L4052\@:	_get_w \w,0,xmm13,xmm15
	jmp		.L4064\@
.L4053\@:	_get_w \w,4,xmm13,xmm15
	jmp		.L4064\@
.L4054\@:	_get_w \w,8,xmm13,xmm15
	jmp		.L4064\@
.L4055\@:	_get_w \w,12,xmm13,xmm15
	jmp		.L4064\@
.L4056\@:	_get_w \w,0,xmm14,xmm15
	jmp		.L4064\@
.L4057\@:	_get_w \w,4,xmm14,xmm15
	jmp		.L4064\@
.L4058\@:	_get_w \w,8,xmm14,xmm15
	jmp		.L4064\@
.L4059\@:	_get_w \w,12,xmm14,xmm15
	jmp		.L4064\@
.L4060\@:	_get_w_alt_c0 \w,mm4
	jmp		.L4064\@
.L4061\@:	_get_w_alt_c1 \w,mm4,\gpr0q,\gpr0l
	jmp		.L4064\@
.L4062\@:	_get_w_alt_c0 \w,mm5
	jmp		.L4064\@
.L4063\@:	_get_w_alt_c1 \w,mm5,\gpr0q,\gpr0l
	jmp		.L4064\@

.L4064\@:

.endm

.macro set_w		w wi trax teax trdx tedx gpr0q gpr0l gpr1q
	movl		\wi,\tedx
	movl		set_w_sse2_jt\@(,\trdx,4),\teax
	cltq		/* sign extend address */
	leaq		set_w_sse2_jt\@(rip),\trdx
	addq		\trdx,\trax /* base address + offset */

	jmp 		*\trax /* essentially goto sign_extend32to64(set_w_sse2_jt[wi]) */

	/* Generated by gen_asm_reljump.py */
/* Set wi jump table for SSE2 */
.section .rodata
.align 4
set_w_sse2_jt\@:
.long	.L4500\@-set_w_sse2_jt\@
.long	.L4501\@-set_w_sse2_jt\@
.long	.L4502\@-set_w_sse2_jt\@
.long	.L4503\@-set_w_sse2_jt\@
.long	.L4504\@-set_w_sse2_jt\@
.long	.L4505\@-set_w_sse2_jt\@
.long	.L4506\@-set_w_sse2_jt\@
.long	.L4507\@-set_w_sse2_jt\@
.long	.L4508\@-set_w_sse2_jt\@
.long	.L4509\@-set_w_sse2_jt\@
.long	.L4510\@-set_w_sse2_jt\@
.long	.L4511\@-set_w_sse2_jt\@
.long	.L4512\@-set_w_sse2_jt\@
.long	.L4513\@-set_w_sse2_jt\@
.long	.L4514\@-set_w_sse2_jt\@
.long	.L4515\@-set_w_sse2_jt\@
.long	.L4516\@-set_w_sse2_jt\@
.long	.L4517\@-set_w_sse2_jt\@
.long	.L4518\@-set_w_sse2_jt\@
.long	.L4519\@-set_w_sse2_jt\@
.long	.L4520\@-set_w_sse2_jt\@
.long	.L4521\@-set_w_sse2_jt\@
.long	.L4522\@-set_w_sse2_jt\@
.long	.L4523\@-set_w_sse2_jt\@
.long	.L4524\@-set_w_sse2_jt\@
.long	.L4525\@-set_w_sse2_jt\@
.long	.L4526\@-set_w_sse2_jt\@
.long	.L4527\@-set_w_sse2_jt\@
.long	.L4528\@-set_w_sse2_jt\@
.long	.L4529\@-set_w_sse2_jt\@
.long	.L4530\@-set_w_sse2_jt\@
.long	.L4531\@-set_w_sse2_jt\@
.long	.L4532\@-set_w_sse2_jt\@
.long	.L4533\@-set_w_sse2_jt\@
.long	.L4534\@-set_w_sse2_jt\@
.long	.L4535\@-set_w_sse2_jt\@
.long	.L4536\@-set_w_sse2_jt\@
.long	.L4537\@-set_w_sse2_jt\@
.long	.L4538\@-set_w_sse2_jt\@
.long	.L4539\@-set_w_sse2_jt\@
.long	.L4540\@-set_w_sse2_jt\@
.long	.L4541\@-set_w_sse2_jt\@
.long	.L4542\@-set_w_sse2_jt\@
.long	.L4543\@-set_w_sse2_jt\@
.long	.L4544\@-set_w_sse2_jt\@
.long	.L4545\@-set_w_sse2_jt\@
.long	.L4546\@-set_w_sse2_jt\@
.long	.L4547\@-set_w_sse2_jt\@
.long	.L4548\@-set_w_sse2_jt\@
.long	.L4549\@-set_w_sse2_jt\@
.long	.L4550\@-set_w_sse2_jt\@
.long	.L4551\@-set_w_sse2_jt\@
.long	.L4552\@-set_w_sse2_jt\@
.long	.L4553\@-set_w_sse2_jt\@
.long	.L4554\@-set_w_sse2_jt\@
.long	.L4555\@-set_w_sse2_jt\@
.long	.L4556\@-set_w_sse2_jt\@
.long	.L4557\@-set_w_sse2_jt\@
.long	.L4558\@-set_w_sse2_jt\@
.long	.L4559\@-set_w_sse2_jt\@
.long	.L4560\@-set_w_sse2_jt\@
.long	.L4561\@-set_w_sse2_jt\@
.long	.L4562\@-set_w_sse2_jt\@
.long	.L4563\@-set_w_sse2_jt\@
.long	.L4564\@-set_w_sse2_jt\@
.text
.L4500\@:	_set_w \w,0,xmm0,xmm15,\gpr0l
	jmp		.L4564\@
.L4501\@:	_set_w \w,4,xmm0,xmm15,\gpr0l
	jmp		.L4564\@
.L4502\@:	_set_w \w,8,xmm0,xmm15,\gpr0l
	jmp		.L4564\@
.L4503\@:	_set_w \w,12,xmm0,xmm15,\gpr0l
	jmp		.L4564\@
.L4504\@:	_set_w \w,0,xmm1,xmm15,\gpr0l
	jmp		.L4564\@
.L4505\@:	_set_w \w,4,xmm1,xmm15,\gpr0l
	jmp		.L4564\@
.L4506\@:	_set_w \w,8,xmm1,xmm15,\gpr0l
	jmp		.L4564\@
.L4507\@:	_set_w \w,12,xmm1,xmm15,\gpr0l
	jmp		.L4564\@
.L4508\@:	_set_w \w,0,xmm2,xmm15,\gpr0l
	jmp		.L4564\@
.L4509\@:	_set_w \w,4,xmm2,xmm15,\gpr0l
	jmp		.L4564\@
.L4510\@:	_set_w \w,8,xmm2,xmm15,\gpr0l
	jmp		.L4564\@
.L4511\@:	_set_w \w,12,xmm2,xmm15,\gpr0l
	jmp		.L4564\@
.L4512\@:	_set_w \w,0,xmm3,xmm15,\gpr0l
	jmp		.L4564\@
.L4513\@:	_set_w \w,4,xmm3,xmm15,\gpr0l
	jmp		.L4564\@
.L4514\@:	_set_w \w,8,xmm3,xmm15,\gpr0l
	jmp		.L4564\@
.L4515\@:	_set_w \w,12,xmm3,xmm15,\gpr0l
	jmp		.L4564\@
.L4516\@:	_set_w \w,0,xmm4,xmm15,\gpr0l
	jmp		.L4564\@
.L4517\@:	_set_w \w,4,xmm4,xmm15,\gpr0l
	jmp		.L4564\@
.L4518\@:	_set_w \w,8,xmm4,xmm15,\gpr0l
	jmp		.L4564\@
.L4519\@:	_set_w \w,12,xmm4,xmm15,\gpr0l
	jmp		.L4564\@
.L4520\@:	_set_w \w,0,xmm5,xmm15,\gpr0l
	jmp		.L4564\@
.L4521\@:	_set_w \w,4,xmm5,xmm15,\gpr0l
	jmp		.L4564\@
.L4522\@:	_set_w \w,8,xmm5,xmm15,\gpr0l
	jmp		.L4564\@
.L4523\@:	_set_w \w,12,xmm5,xmm15,\gpr0l
	jmp		.L4564\@
.L4524\@:	_set_w \w,0,xmm6,xmm15,\gpr0l
	jmp		.L4564\@
.L4525\@:	_set_w \w,4,xmm6,xmm15,\gpr0l
	jmp		.L4564\@
.L4526\@:	_set_w \w,8,xmm6,xmm15,\gpr0l
	jmp		.L4564\@
.L4527\@:	_set_w \w,12,xmm6,xmm15,\gpr0l
	jmp		.L4564\@
.L4528\@:	_set_w \w,0,xmm7,xmm15,\gpr0l
	jmp		.L4564\@
.L4529\@:	_set_w \w,4,xmm7,xmm15,\gpr0l
	jmp		.L4564\@
.L4530\@:	_set_w \w,8,xmm7,xmm15,\gpr0l
	jmp		.L4564\@
.L4531\@:	_set_w \w,12,xmm7,xmm15,\gpr0l
	jmp		.L4564\@
.L4532\@:	_set_w \w,0,xmm8,xmm15,\gpr0l
	jmp		.L4564\@
.L4533\@:	_set_w \w,4,xmm8,xmm15,\gpr0l
	jmp		.L4564\@
.L4534\@:	_set_w \w,8,xmm8,xmm15,\gpr0l
	jmp		.L4564\@
.L4535\@:	_set_w \w,12,xmm8,xmm15,\gpr0l
	jmp		.L4564\@
.L4536\@:	_set_w \w,0,xmm9,xmm15,\gpr0l
	jmp		.L4564\@
.L4537\@:	_set_w \w,4,xmm9,xmm15,\gpr0l
	jmp		.L4564\@
.L4538\@:	_set_w \w,8,xmm9,xmm15,\gpr0l
	jmp		.L4564\@
.L4539\@:	_set_w \w,12,xmm9,xmm15,\gpr0l
	jmp		.L4564\@
.L4540\@:	_set_w \w,0,xmm10,xmm15,\gpr0l
	jmp		.L4564\@
.L4541\@:	_set_w \w,4,xmm10,xmm15,\gpr0l
	jmp		.L4564\@
.L4542\@:	_set_w \w,8,xmm10,xmm15,\gpr0l
	jmp		.L4564\@
.L4543\@:	_set_w \w,12,xmm10,xmm15,\gpr0l
	jmp		.L4564\@
.L4544\@:	_set_w \w,0,xmm11,xmm15,\gpr0l
	jmp		.L4564\@
.L4545\@:	_set_w \w,4,xmm11,xmm15,\gpr0l
	jmp		.L4564\@
.L4546\@:	_set_w \w,8,xmm11,xmm15,\gpr0l
	jmp		.L4564\@
.L4547\@:	_set_w \w,12,xmm11,xmm15,\gpr0l
	jmp		.L4564\@
.L4548\@:	_set_w \w,0,xmm12,xmm15,\gpr0l
	jmp		.L4564\@
.L4549\@:	_set_w \w,4,xmm12,xmm15,\gpr0l
	jmp		.L4564\@
.L4550\@:	_set_w \w,8,xmm12,xmm15,\gpr0l
	jmp		.L4564\@
.L4551\@:	_set_w \w,12,xmm12,xmm15,\gpr0l
	jmp		.L4564\@
.L4552\@:	_set_w \w,0,xmm13,xmm15,\gpr0l
	jmp		.L4564\@
.L4553\@:	_set_w \w,4,xmm13,xmm15,\gpr0l
	jmp		.L4564\@
.L4554\@:	_set_w \w,8,xmm13,xmm15,\gpr0l
	jmp		.L4564\@
.L4555\@:	_set_w \w,12,xmm13,xmm15,\gpr0l
	jmp		.L4564\@
.L4556\@:	_set_w \w,0,xmm14,xmm15,\gpr0l
	jmp		.L4564\@
.L4557\@:	_set_w \w,4,xmm14,xmm15,\gpr0l
	jmp		.L4564\@
.L4558\@:	_set_w \w,8,xmm14,xmm15,\gpr0l
	jmp		.L4564\@
.L4559\@:	_set_w \w,12,xmm14,xmm15,\gpr0l
	jmp		.L4564\@
.L4560\@:	_set_w_alt \w,0,mm4,\gpr0q,\gpr0l,\gpr1q
	jmp		.L4564\@
.L4561\@:	_set_w_alt \w,32,mm4,\gpr0q,\gpr0l,\gpr1q
	jmp		.L4564\@
.L4562\@:	_set_w_alt \w,0,mm5,\gpr0q,\gpr0l,\gpr1q
	jmp		.L4564\@
.L4563\@:	_set_w_alt \w,32,mm5,\gpr0q,\gpr0l,\gpr1q
	jmp		.L4564\@

.L4564\@:

.endm

#endif

#ifdef HAVE_SSE4_1
/* c is u32 */
.macro insert_byte ci c xmm
	pinsrb		$\ci,\c,\xmm
.endm

#elif defined(HAVE_SSE2)
/* c is u32 */
.macro insert_byte ci c xmm txmm
	movd		\c,\txmm
	pslldq		$\ci,\txmm
	pxor		\txmm,\xmm
.endm

/* c is u32 */
.macro insert_byte_alt ci c mm gpr0q gpr0l gpr1q
	movl		\c,\gpr0l
	shlq		$\ci,\gpr0q
	movq		\mm,\gpr1q
	xorq		\gpr0q,\gpr1q
	movq		\gpr1q,\mm
.endm


#endif // HAVE_SSE4_1

#ifdef HAVE_SSE4_1
.macro insert_W_byte_sse4_1 c bi trax teax trdx tedx
	andl		$0x000000ff,\c

	movl		\bi,\tedx
	andl		$0x000000ff,\tedx
	movl		insert_byte_sse4_1_jt\@(,\trdx,4),\teax
	cltq		/* sign extend address */
	leaq		insert_byte_sse4_1_jt\@(rip),\trdx
	addq		\trdx,\trax /* base address + offset */

	jmp 		*\trax /* essentially goto sign_extend32to64(insert_byte_sse4_1_jt[bi]) */

	/* Generated by gen_asm_reljump.py */
/* Insertion jump table for SSE4.1 */
.section .rodata
.align 4
insert_byte_sse4_1_jt\@:
.long	.L2500\@-insert_byte_sse4_1_jt\@
.long	.L2501\@-insert_byte_sse4_1_jt\@
.long	.L2502\@-insert_byte_sse4_1_jt\@
.long	.L2503\@-insert_byte_sse4_1_jt\@
.long	.L2504\@-insert_byte_sse4_1_jt\@
.long	.L2505\@-insert_byte_sse4_1_jt\@
.long	.L2506\@-insert_byte_sse4_1_jt\@
.long	.L2507\@-insert_byte_sse4_1_jt\@
.long	.L2508\@-insert_byte_sse4_1_jt\@
.long	.L2509\@-insert_byte_sse4_1_jt\@
.long	.L2510\@-insert_byte_sse4_1_jt\@
.long	.L2511\@-insert_byte_sse4_1_jt\@
.long	.L2512\@-insert_byte_sse4_1_jt\@
.long	.L2513\@-insert_byte_sse4_1_jt\@
.long	.L2514\@-insert_byte_sse4_1_jt\@
.long	.L2515\@-insert_byte_sse4_1_jt\@
.long	.L2516\@-insert_byte_sse4_1_jt\@
.long	.L2517\@-insert_byte_sse4_1_jt\@
.long	.L2518\@-insert_byte_sse4_1_jt\@
.long	.L2519\@-insert_byte_sse4_1_jt\@
.long	.L2520\@-insert_byte_sse4_1_jt\@
.long	.L2521\@-insert_byte_sse4_1_jt\@
.long	.L2522\@-insert_byte_sse4_1_jt\@
.long	.L2523\@-insert_byte_sse4_1_jt\@
.long	.L2524\@-insert_byte_sse4_1_jt\@
.long	.L2525\@-insert_byte_sse4_1_jt\@
.long	.L2526\@-insert_byte_sse4_1_jt\@
.long	.L2527\@-insert_byte_sse4_1_jt\@
.long	.L2528\@-insert_byte_sse4_1_jt\@
.long	.L2529\@-insert_byte_sse4_1_jt\@
.long	.L2530\@-insert_byte_sse4_1_jt\@
.long	.L2531\@-insert_byte_sse4_1_jt\@
.long	.L2532\@-insert_byte_sse4_1_jt\@
.long	.L2533\@-insert_byte_sse4_1_jt\@
.long	.L2534\@-insert_byte_sse4_1_jt\@
.long	.L2535\@-insert_byte_sse4_1_jt\@
.long	.L2536\@-insert_byte_sse4_1_jt\@
.long	.L2537\@-insert_byte_sse4_1_jt\@
.long	.L2538\@-insert_byte_sse4_1_jt\@
.long	.L2539\@-insert_byte_sse4_1_jt\@
.long	.L2540\@-insert_byte_sse4_1_jt\@
.long	.L2541\@-insert_byte_sse4_1_jt\@
.long	.L2542\@-insert_byte_sse4_1_jt\@
.long	.L2543\@-insert_byte_sse4_1_jt\@
.long	.L2544\@-insert_byte_sse4_1_jt\@
.long	.L2545\@-insert_byte_sse4_1_jt\@
.long	.L2546\@-insert_byte_sse4_1_jt\@
.long	.L2547\@-insert_byte_sse4_1_jt\@
.long	.L2548\@-insert_byte_sse4_1_jt\@
.long	.L2549\@-insert_byte_sse4_1_jt\@
.long	.L2550\@-insert_byte_sse4_1_jt\@
.long	.L2551\@-insert_byte_sse4_1_jt\@
.long	.L2552\@-insert_byte_sse4_1_jt\@
.long	.L2553\@-insert_byte_sse4_1_jt\@
.long	.L2554\@-insert_byte_sse4_1_jt\@
.long	.L2555\@-insert_byte_sse4_1_jt\@
.long	.L2556\@-insert_byte_sse4_1_jt\@
.long	.L2557\@-insert_byte_sse4_1_jt\@
.long	.L2558\@-insert_byte_sse4_1_jt\@
.long	.L2559\@-insert_byte_sse4_1_jt\@
.long	.L2560\@-insert_byte_sse4_1_jt\@
.long	.L2561\@-insert_byte_sse4_1_jt\@
.long	.L2562\@-insert_byte_sse4_1_jt\@
.long	.L2563\@-insert_byte_sse4_1_jt\@
.long	.L2564\@-insert_byte_sse4_1_jt\@
.long	.L2565\@-insert_byte_sse4_1_jt\@
.long	.L2566\@-insert_byte_sse4_1_jt\@
.long	.L2567\@-insert_byte_sse4_1_jt\@
.long	.L2568\@-insert_byte_sse4_1_jt\@
.long	.L2569\@-insert_byte_sse4_1_jt\@
.long	.L2570\@-insert_byte_sse4_1_jt\@
.long	.L2571\@-insert_byte_sse4_1_jt\@
.long	.L2572\@-insert_byte_sse4_1_jt\@
.long	.L2573\@-insert_byte_sse4_1_jt\@
.long	.L2574\@-insert_byte_sse4_1_jt\@
.long	.L2575\@-insert_byte_sse4_1_jt\@
.long	.L2576\@-insert_byte_sse4_1_jt\@
.long	.L2577\@-insert_byte_sse4_1_jt\@
.long	.L2578\@-insert_byte_sse4_1_jt\@
.long	.L2579\@-insert_byte_sse4_1_jt\@
.long	.L2580\@-insert_byte_sse4_1_jt\@
.long	.L2581\@-insert_byte_sse4_1_jt\@
.long	.L2582\@-insert_byte_sse4_1_jt\@
.long	.L2583\@-insert_byte_sse4_1_jt\@
.long	.L2584\@-insert_byte_sse4_1_jt\@
.long	.L2585\@-insert_byte_sse4_1_jt\@
.long	.L2586\@-insert_byte_sse4_1_jt\@
.long	.L2587\@-insert_byte_sse4_1_jt\@
.long	.L2588\@-insert_byte_sse4_1_jt\@
.long	.L2589\@-insert_byte_sse4_1_jt\@
.long	.L2590\@-insert_byte_sse4_1_jt\@
.long	.L2591\@-insert_byte_sse4_1_jt\@
.long	.L2592\@-insert_byte_sse4_1_jt\@
.long	.L2593\@-insert_byte_sse4_1_jt\@
.long	.L2594\@-insert_byte_sse4_1_jt\@
.long	.L2595\@-insert_byte_sse4_1_jt\@
.long	.L2596\@-insert_byte_sse4_1_jt\@
.long	.L2597\@-insert_byte_sse4_1_jt\@
.long	.L2598\@-insert_byte_sse4_1_jt\@
.long	.L2599\@-insert_byte_sse4_1_jt\@
.long	.L2600\@-insert_byte_sse4_1_jt\@
.long	.L2601\@-insert_byte_sse4_1_jt\@
.long	.L2602\@-insert_byte_sse4_1_jt\@
.long	.L2603\@-insert_byte_sse4_1_jt\@
.long	.L2604\@-insert_byte_sse4_1_jt\@
.long	.L2605\@-insert_byte_sse4_1_jt\@
.long	.L2606\@-insert_byte_sse4_1_jt\@
.long	.L2607\@-insert_byte_sse4_1_jt\@
.long	.L2608\@-insert_byte_sse4_1_jt\@
.long	.L2609\@-insert_byte_sse4_1_jt\@
.long	.L2610\@-insert_byte_sse4_1_jt\@
.long	.L2611\@-insert_byte_sse4_1_jt\@
.long	.L2612\@-insert_byte_sse4_1_jt\@
.long	.L2613\@-insert_byte_sse4_1_jt\@
.long	.L2614\@-insert_byte_sse4_1_jt\@
.long	.L2615\@-insert_byte_sse4_1_jt\@
.long	.L2616\@-insert_byte_sse4_1_jt\@
.long	.L2617\@-insert_byte_sse4_1_jt\@
.long	.L2618\@-insert_byte_sse4_1_jt\@
.long	.L2619\@-insert_byte_sse4_1_jt\@
.long	.L2620\@-insert_byte_sse4_1_jt\@
.long	.L2621\@-insert_byte_sse4_1_jt\@
.long	.L2622\@-insert_byte_sse4_1_jt\@
.long	.L2623\@-insert_byte_sse4_1_jt\@
.long	.L2624\@-insert_byte_sse4_1_jt\@
.long	.L2625\@-insert_byte_sse4_1_jt\@
.long	.L2626\@-insert_byte_sse4_1_jt\@
.long	.L2627\@-insert_byte_sse4_1_jt\@
.long	.L2628\@-insert_byte_sse4_1_jt\@
.long	.L2629\@-insert_byte_sse4_1_jt\@
.long	.L2630\@-insert_byte_sse4_1_jt\@
.long	.L2631\@-insert_byte_sse4_1_jt\@
.long	.L2632\@-insert_byte_sse4_1_jt\@
.long	.L2633\@-insert_byte_sse4_1_jt\@
.long	.L2634\@-insert_byte_sse4_1_jt\@
.long	.L2635\@-insert_byte_sse4_1_jt\@
.long	.L2636\@-insert_byte_sse4_1_jt\@
.long	.L2637\@-insert_byte_sse4_1_jt\@
.long	.L2638\@-insert_byte_sse4_1_jt\@
.long	.L2639\@-insert_byte_sse4_1_jt\@
.long	.L2640\@-insert_byte_sse4_1_jt\@
.long	.L2641\@-insert_byte_sse4_1_jt\@
.long	.L2642\@-insert_byte_sse4_1_jt\@
.long	.L2643\@-insert_byte_sse4_1_jt\@
.long	.L2644\@-insert_byte_sse4_1_jt\@
.long	.L2645\@-insert_byte_sse4_1_jt\@
.long	.L2646\@-insert_byte_sse4_1_jt\@
.long	.L2647\@-insert_byte_sse4_1_jt\@
.long	.L2648\@-insert_byte_sse4_1_jt\@
.long	.L2649\@-insert_byte_sse4_1_jt\@
.long	.L2650\@-insert_byte_sse4_1_jt\@
.long	.L2651\@-insert_byte_sse4_1_jt\@
.long	.L2652\@-insert_byte_sse4_1_jt\@
.long	.L2653\@-insert_byte_sse4_1_jt\@
.long	.L2654\@-insert_byte_sse4_1_jt\@
.long	.L2655\@-insert_byte_sse4_1_jt\@
.long	.L2656\@-insert_byte_sse4_1_jt\@
.long	.L2657\@-insert_byte_sse4_1_jt\@
.long	.L2658\@-insert_byte_sse4_1_jt\@
.long	.L2659\@-insert_byte_sse4_1_jt\@
.long	.L2660\@-insert_byte_sse4_1_jt\@
.long	.L2661\@-insert_byte_sse4_1_jt\@
.long	.L2662\@-insert_byte_sse4_1_jt\@
.long	.L2663\@-insert_byte_sse4_1_jt\@
.long	.L2664\@-insert_byte_sse4_1_jt\@
.long	.L2665\@-insert_byte_sse4_1_jt\@
.long	.L2666\@-insert_byte_sse4_1_jt\@
.long	.L2667\@-insert_byte_sse4_1_jt\@
.long	.L2668\@-insert_byte_sse4_1_jt\@
.long	.L2669\@-insert_byte_sse4_1_jt\@
.long	.L2670\@-insert_byte_sse4_1_jt\@
.long	.L2671\@-insert_byte_sse4_1_jt\@
.long	.L2672\@-insert_byte_sse4_1_jt\@
.long	.L2673\@-insert_byte_sse4_1_jt\@
.long	.L2674\@-insert_byte_sse4_1_jt\@
.long	.L2675\@-insert_byte_sse4_1_jt\@
.long	.L2676\@-insert_byte_sse4_1_jt\@
.long	.L2677\@-insert_byte_sse4_1_jt\@
.long	.L2678\@-insert_byte_sse4_1_jt\@
.long	.L2679\@-insert_byte_sse4_1_jt\@
.long	.L2680\@-insert_byte_sse4_1_jt\@
.long	.L2681\@-insert_byte_sse4_1_jt\@
.long	.L2682\@-insert_byte_sse4_1_jt\@
.long	.L2683\@-insert_byte_sse4_1_jt\@
.long	.L2684\@-insert_byte_sse4_1_jt\@
.long	.L2685\@-insert_byte_sse4_1_jt\@
.long	.L2686\@-insert_byte_sse4_1_jt\@
.long	.L2687\@-insert_byte_sse4_1_jt\@
.long	.L2688\@-insert_byte_sse4_1_jt\@
.long	.L2689\@-insert_byte_sse4_1_jt\@
.long	.L2690\@-insert_byte_sse4_1_jt\@
.long	.L2691\@-insert_byte_sse4_1_jt\@
.long	.L2692\@-insert_byte_sse4_1_jt\@
.long	.L2693\@-insert_byte_sse4_1_jt\@
.long	.L2694\@-insert_byte_sse4_1_jt\@
.long	.L2695\@-insert_byte_sse4_1_jt\@
.long	.L2696\@-insert_byte_sse4_1_jt\@
.long	.L2697\@-insert_byte_sse4_1_jt\@
.long	.L2698\@-insert_byte_sse4_1_jt\@
.long	.L2699\@-insert_byte_sse4_1_jt\@
.long	.L2700\@-insert_byte_sse4_1_jt\@
.long	.L2701\@-insert_byte_sse4_1_jt\@
.long	.L2702\@-insert_byte_sse4_1_jt\@
.long	.L2703\@-insert_byte_sse4_1_jt\@
.long	.L2704\@-insert_byte_sse4_1_jt\@
.long	.L2705\@-insert_byte_sse4_1_jt\@
.long	.L2706\@-insert_byte_sse4_1_jt\@
.long	.L2707\@-insert_byte_sse4_1_jt\@
.long	.L2708\@-insert_byte_sse4_1_jt\@
.long	.L2709\@-insert_byte_sse4_1_jt\@
.long	.L2710\@-insert_byte_sse4_1_jt\@
.long	.L2711\@-insert_byte_sse4_1_jt\@
.long	.L2712\@-insert_byte_sse4_1_jt\@
.long	.L2713\@-insert_byte_sse4_1_jt\@
.long	.L2714\@-insert_byte_sse4_1_jt\@
.long	.L2715\@-insert_byte_sse4_1_jt\@
.long	.L2716\@-insert_byte_sse4_1_jt\@
.long	.L2717\@-insert_byte_sse4_1_jt\@
.long	.L2718\@-insert_byte_sse4_1_jt\@
.long	.L2719\@-insert_byte_sse4_1_jt\@
.long	.L2720\@-insert_byte_sse4_1_jt\@
.long	.L2721\@-insert_byte_sse4_1_jt\@
.long	.L2722\@-insert_byte_sse4_1_jt\@
.long	.L2723\@-insert_byte_sse4_1_jt\@
.long	.L2724\@-insert_byte_sse4_1_jt\@
.long	.L2725\@-insert_byte_sse4_1_jt\@
.long	.L2726\@-insert_byte_sse4_1_jt\@
.long	.L2727\@-insert_byte_sse4_1_jt\@
.long	.L2728\@-insert_byte_sse4_1_jt\@
.long	.L2729\@-insert_byte_sse4_1_jt\@
.long	.L2730\@-insert_byte_sse4_1_jt\@
.long	.L2731\@-insert_byte_sse4_1_jt\@
.long	.L2732\@-insert_byte_sse4_1_jt\@
.long	.L2733\@-insert_byte_sse4_1_jt\@
.long	.L2734\@-insert_byte_sse4_1_jt\@
.long	.L2735\@-insert_byte_sse4_1_jt\@
.long	.L2736\@-insert_byte_sse4_1_jt\@
.long	.L2737\@-insert_byte_sse4_1_jt\@
.long	.L2738\@-insert_byte_sse4_1_jt\@
.long	.L2739\@-insert_byte_sse4_1_jt\@
.long	.L2740\@-insert_byte_sse4_1_jt\@
.long	.L2741\@-insert_byte_sse4_1_jt\@
.long	.L2742\@-insert_byte_sse4_1_jt\@
.long	.L2743\@-insert_byte_sse4_1_jt\@
.long	.L2744\@-insert_byte_sse4_1_jt\@
.long	.L2745\@-insert_byte_sse4_1_jt\@
.long	.L2746\@-insert_byte_sse4_1_jt\@
.long	.L2747\@-insert_byte_sse4_1_jt\@
.long	.L2748\@-insert_byte_sse4_1_jt\@
.long	.L2749\@-insert_byte_sse4_1_jt\@
.long	.L2750\@-insert_byte_sse4_1_jt\@
.long	.L2751\@-insert_byte_sse4_1_jt\@
.long	.L2752\@-insert_byte_sse4_1_jt\@
.long	.L2753\@-insert_byte_sse4_1_jt\@
.long	.L2754\@-insert_byte_sse4_1_jt\@
.long	.L2755\@-insert_byte_sse4_1_jt\@
.long	.L2756\@-insert_byte_sse4_1_jt\@
.text
.L2500\@:	insert_byte 0,\c,xmm0
	jmp		.L2756\@
.L2501\@:	insert_byte 1,\c,xmm0
	jmp		.L2756\@
.L2502\@:	insert_byte 2,\c,xmm0
	jmp		.L2756\@
.L2503\@:	insert_byte 3,\c,xmm0
	jmp		.L2756\@
.L2504\@:	insert_byte 4,\c,xmm0
	jmp		.L2756\@
.L2505\@:	insert_byte 5,\c,xmm0
	jmp		.L2756\@
.L2506\@:	insert_byte 6,\c,xmm0
	jmp		.L2756\@
.L2507\@:	insert_byte 7,\c,xmm0
	jmp		.L2756\@
.L2508\@:	insert_byte 8,\c,xmm0
	jmp		.L2756\@
.L2509\@:	insert_byte 9,\c,xmm0
	jmp		.L2756\@
.L2510\@:	insert_byte 10,\c,xmm0
	jmp		.L2756\@
.L2511\@:	insert_byte 11,\c,xmm0
	jmp		.L2756\@
.L2512\@:	insert_byte 12,\c,xmm0
	jmp		.L2756\@
.L2513\@:	insert_byte 13,\c,xmm0
	jmp		.L2756\@
.L2514\@:	insert_byte 14,\c,xmm0
	jmp		.L2756\@
.L2515\@:	insert_byte 15,\c,xmm0
	jmp		.L2756\@
.L2516\@:	insert_byte 0,\c,xmm1
	jmp		.L2756\@
.L2517\@:	insert_byte 1,\c,xmm1
	jmp		.L2756\@
.L2518\@:	insert_byte 2,\c,xmm1
	jmp		.L2756\@
.L2519\@:	insert_byte 3,\c,xmm1
	jmp		.L2756\@
.L2520\@:	insert_byte 4,\c,xmm1
	jmp		.L2756\@
.L2521\@:	insert_byte 5,\c,xmm1
	jmp		.L2756\@
.L2522\@:	insert_byte 6,\c,xmm1
	jmp		.L2756\@
.L2523\@:	insert_byte 7,\c,xmm1
	jmp		.L2756\@
.L2524\@:	insert_byte 8,\c,xmm1
	jmp		.L2756\@
.L2525\@:	insert_byte 9,\c,xmm1
	jmp		.L2756\@
.L2526\@:	insert_byte 10,\c,xmm1
	jmp		.L2756\@
.L2527\@:	insert_byte 11,\c,xmm1
	jmp		.L2756\@
.L2528\@:	insert_byte 12,\c,xmm1
	jmp		.L2756\@
.L2529\@:	insert_byte 13,\c,xmm1
	jmp		.L2756\@
.L2530\@:	insert_byte 14,\c,xmm1
	jmp		.L2756\@
.L2531\@:	insert_byte 15,\c,xmm1
	jmp		.L2756\@
.L2532\@:	insert_byte 0,\c,xmm2
	jmp		.L2756\@
.L2533\@:	insert_byte 1,\c,xmm2
	jmp		.L2756\@
.L2534\@:	insert_byte 2,\c,xmm2
	jmp		.L2756\@
.L2535\@:	insert_byte 3,\c,xmm2
	jmp		.L2756\@
.L2536\@:	insert_byte 4,\c,xmm2
	jmp		.L2756\@
.L2537\@:	insert_byte 5,\c,xmm2
	jmp		.L2756\@
.L2538\@:	insert_byte 6,\c,xmm2
	jmp		.L2756\@
.L2539\@:	insert_byte 7,\c,xmm2
	jmp		.L2756\@
.L2540\@:	insert_byte 8,\c,xmm2
	jmp		.L2756\@
.L2541\@:	insert_byte 9,\c,xmm2
	jmp		.L2756\@
.L2542\@:	insert_byte 10,\c,xmm2
	jmp		.L2756\@
.L2543\@:	insert_byte 11,\c,xmm2
	jmp		.L2756\@
.L2544\@:	insert_byte 12,\c,xmm2
	jmp		.L2756\@
.L2545\@:	insert_byte 13,\c,xmm2
	jmp		.L2756\@
.L2546\@:	insert_byte 14,\c,xmm2
	jmp		.L2756\@
.L2547\@:	insert_byte 15,\c,xmm2
	jmp		.L2756\@
.L2548\@:	insert_byte 0,\c,xmm3
	jmp		.L2756\@
.L2549\@:	insert_byte 1,\c,xmm3
	jmp		.L2756\@
.L2550\@:	insert_byte 2,\c,xmm3
	jmp		.L2756\@
.L2551\@:	insert_byte 3,\c,xmm3
	jmp		.L2756\@
.L2552\@:	insert_byte 4,\c,xmm3
	jmp		.L2756\@
.L2553\@:	insert_byte 5,\c,xmm3
	jmp		.L2756\@
.L2554\@:	insert_byte 6,\c,xmm3
	jmp		.L2756\@
.L2555\@:	insert_byte 7,\c,xmm3
	jmp		.L2756\@
.L2556\@:	insert_byte 8,\c,xmm3
	jmp		.L2756\@
.L2557\@:	insert_byte 9,\c,xmm3
	jmp		.L2756\@
.L2558\@:	insert_byte 10,\c,xmm3
	jmp		.L2756\@
.L2559\@:	insert_byte 11,\c,xmm3
	jmp		.L2756\@
.L2560\@:	insert_byte 12,\c,xmm3
	jmp		.L2756\@
.L2561\@:	insert_byte 13,\c,xmm3
	jmp		.L2756\@
.L2562\@:	insert_byte 14,\c,xmm3
	jmp		.L2756\@
.L2563\@:	insert_byte 15,\c,xmm3
	jmp		.L2756\@
.L2564\@:	insert_byte 0,\c,xmm4
	jmp		.L2756\@
.L2565\@:	insert_byte 1,\c,xmm4
	jmp		.L2756\@
.L2566\@:	insert_byte 2,\c,xmm4
	jmp		.L2756\@
.L2567\@:	insert_byte 3,\c,xmm4
	jmp		.L2756\@
.L2568\@:	insert_byte 4,\c,xmm4
	jmp		.L2756\@
.L2569\@:	insert_byte 5,\c,xmm4
	jmp		.L2756\@
.L2570\@:	insert_byte 6,\c,xmm4
	jmp		.L2756\@
.L2571\@:	insert_byte 7,\c,xmm4
	jmp		.L2756\@
.L2572\@:	insert_byte 8,\c,xmm4
	jmp		.L2756\@
.L2573\@:	insert_byte 9,\c,xmm4
	jmp		.L2756\@
.L2574\@:	insert_byte 10,\c,xmm4
	jmp		.L2756\@
.L2575\@:	insert_byte 11,\c,xmm4
	jmp		.L2756\@
.L2576\@:	insert_byte 12,\c,xmm4
	jmp		.L2756\@
.L2577\@:	insert_byte 13,\c,xmm4
	jmp		.L2756\@
.L2578\@:	insert_byte 14,\c,xmm4
	jmp		.L2756\@
.L2579\@:	insert_byte 15,\c,xmm4
	jmp		.L2756\@
.L2580\@:	insert_byte 0,\c,xmm5
	jmp		.L2756\@
.L2581\@:	insert_byte 1,\c,xmm5
	jmp		.L2756\@
.L2582\@:	insert_byte 2,\c,xmm5
	jmp		.L2756\@
.L2583\@:	insert_byte 3,\c,xmm5
	jmp		.L2756\@
.L2584\@:	insert_byte 4,\c,xmm5
	jmp		.L2756\@
.L2585\@:	insert_byte 5,\c,xmm5
	jmp		.L2756\@
.L2586\@:	insert_byte 6,\c,xmm5
	jmp		.L2756\@
.L2587\@:	insert_byte 7,\c,xmm5
	jmp		.L2756\@
.L2588\@:	insert_byte 8,\c,xmm5
	jmp		.L2756\@
.L2589\@:	insert_byte 9,\c,xmm5
	jmp		.L2756\@
.L2590\@:	insert_byte 10,\c,xmm5
	jmp		.L2756\@
.L2591\@:	insert_byte 11,\c,xmm5
	jmp		.L2756\@
.L2592\@:	insert_byte 12,\c,xmm5
	jmp		.L2756\@
.L2593\@:	insert_byte 13,\c,xmm5
	jmp		.L2756\@
.L2594\@:	insert_byte 14,\c,xmm5
	jmp		.L2756\@
.L2595\@:	insert_byte 15,\c,xmm5
	jmp		.L2756\@
.L2596\@:	insert_byte 0,\c,xmm6
	jmp		.L2756\@
.L2597\@:	insert_byte 1,\c,xmm6
	jmp		.L2756\@
.L2598\@:	insert_byte 2,\c,xmm6
	jmp		.L2756\@
.L2599\@:	insert_byte 3,\c,xmm6
	jmp		.L2756\@
.L2600\@:	insert_byte 4,\c,xmm6
	jmp		.L2756\@
.L2601\@:	insert_byte 5,\c,xmm6
	jmp		.L2756\@
.L2602\@:	insert_byte 6,\c,xmm6
	jmp		.L2756\@
.L2603\@:	insert_byte 7,\c,xmm6
	jmp		.L2756\@
.L2604\@:	insert_byte 8,\c,xmm6
	jmp		.L2756\@
.L2605\@:	insert_byte 9,\c,xmm6
	jmp		.L2756\@
.L2606\@:	insert_byte 10,\c,xmm6
	jmp		.L2756\@
.L2607\@:	insert_byte 11,\c,xmm6
	jmp		.L2756\@
.L2608\@:	insert_byte 12,\c,xmm6
	jmp		.L2756\@
.L2609\@:	insert_byte 13,\c,xmm6
	jmp		.L2756\@
.L2610\@:	insert_byte 14,\c,xmm6
	jmp		.L2756\@
.L2611\@:	insert_byte 15,\c,xmm6
	jmp		.L2756\@
.L2612\@:	insert_byte 0,\c,xmm7
	jmp		.L2756\@
.L2613\@:	insert_byte 1,\c,xmm7
	jmp		.L2756\@
.L2614\@:	insert_byte 2,\c,xmm7
	jmp		.L2756\@
.L2615\@:	insert_byte 3,\c,xmm7
	jmp		.L2756\@
.L2616\@:	insert_byte 4,\c,xmm7
	jmp		.L2756\@
.L2617\@:	insert_byte 5,\c,xmm7
	jmp		.L2756\@
.L2618\@:	insert_byte 6,\c,xmm7
	jmp		.L2756\@
.L2619\@:	insert_byte 7,\c,xmm7
	jmp		.L2756\@
.L2620\@:	insert_byte 8,\c,xmm7
	jmp		.L2756\@
.L2621\@:	insert_byte 9,\c,xmm7
	jmp		.L2756\@
.L2622\@:	insert_byte 10,\c,xmm7
	jmp		.L2756\@
.L2623\@:	insert_byte 11,\c,xmm7
	jmp		.L2756\@
.L2624\@:	insert_byte 12,\c,xmm7
	jmp		.L2756\@
.L2625\@:	insert_byte 13,\c,xmm7
	jmp		.L2756\@
.L2626\@:	insert_byte 14,\c,xmm7
	jmp		.L2756\@
.L2627\@:	insert_byte 15,\c,xmm7
	jmp		.L2756\@
.L2628\@:	insert_byte 0,\c,xmm8
	jmp		.L2756\@
.L2629\@:	insert_byte 1,\c,xmm8
	jmp		.L2756\@
.L2630\@:	insert_byte 2,\c,xmm8
	jmp		.L2756\@
.L2631\@:	insert_byte 3,\c,xmm8
	jmp		.L2756\@
.L2632\@:	insert_byte 4,\c,xmm8
	jmp		.L2756\@
.L2633\@:	insert_byte 5,\c,xmm8
	jmp		.L2756\@
.L2634\@:	insert_byte 6,\c,xmm8
	jmp		.L2756\@
.L2635\@:	insert_byte 7,\c,xmm8
	jmp		.L2756\@
.L2636\@:	insert_byte 8,\c,xmm8
	jmp		.L2756\@
.L2637\@:	insert_byte 9,\c,xmm8
	jmp		.L2756\@
.L2638\@:	insert_byte 10,\c,xmm8
	jmp		.L2756\@
.L2639\@:	insert_byte 11,\c,xmm8
	jmp		.L2756\@
.L2640\@:	insert_byte 12,\c,xmm8
	jmp		.L2756\@
.L2641\@:	insert_byte 13,\c,xmm8
	jmp		.L2756\@
.L2642\@:	insert_byte 14,\c,xmm8
	jmp		.L2756\@
.L2643\@:	insert_byte 15,\c,xmm8
	jmp		.L2756\@
.L2644\@:	insert_byte 0,\c,xmm9
	jmp		.L2756\@
.L2645\@:	insert_byte 1,\c,xmm9
	jmp		.L2756\@
.L2646\@:	insert_byte 2,\c,xmm9
	jmp		.L2756\@
.L2647\@:	insert_byte 3,\c,xmm9
	jmp		.L2756\@
.L2648\@:	insert_byte 4,\c,xmm9
	jmp		.L2756\@
.L2649\@:	insert_byte 5,\c,xmm9
	jmp		.L2756\@
.L2650\@:	insert_byte 6,\c,xmm9
	jmp		.L2756\@
.L2651\@:	insert_byte 7,\c,xmm9
	jmp		.L2756\@
.L2652\@:	insert_byte 8,\c,xmm9
	jmp		.L2756\@
.L2653\@:	insert_byte 9,\c,xmm9
	jmp		.L2756\@
.L2654\@:	insert_byte 10,\c,xmm9
	jmp		.L2756\@
.L2655\@:	insert_byte 11,\c,xmm9
	jmp		.L2756\@
.L2656\@:	insert_byte 12,\c,xmm9
	jmp		.L2756\@
.L2657\@:	insert_byte 13,\c,xmm9
	jmp		.L2756\@
.L2658\@:	insert_byte 14,\c,xmm9
	jmp		.L2756\@
.L2659\@:	insert_byte 15,\c,xmm9
	jmp		.L2756\@
.L2660\@:	insert_byte 0,\c,xmm10
	jmp		.L2756\@
.L2661\@:	insert_byte 1,\c,xmm10
	jmp		.L2756\@
.L2662\@:	insert_byte 2,\c,xmm10
	jmp		.L2756\@
.L2663\@:	insert_byte 3,\c,xmm10
	jmp		.L2756\@
.L2664\@:	insert_byte 4,\c,xmm10
	jmp		.L2756\@
.L2665\@:	insert_byte 5,\c,xmm10
	jmp		.L2756\@
.L2666\@:	insert_byte 6,\c,xmm10
	jmp		.L2756\@
.L2667\@:	insert_byte 7,\c,xmm10
	jmp		.L2756\@
.L2668\@:	insert_byte 8,\c,xmm10
	jmp		.L2756\@
.L2669\@:	insert_byte 9,\c,xmm10
	jmp		.L2756\@
.L2670\@:	insert_byte 10,\c,xmm10
	jmp		.L2756\@
.L2671\@:	insert_byte 11,\c,xmm10
	jmp		.L2756\@
.L2672\@:	insert_byte 12,\c,xmm10
	jmp		.L2756\@
.L2673\@:	insert_byte 13,\c,xmm10
	jmp		.L2756\@
.L2674\@:	insert_byte 14,\c,xmm10
	jmp		.L2756\@
.L2675\@:	insert_byte 15,\c,xmm10
	jmp		.L2756\@
.L2676\@:	insert_byte 0,\c,xmm11
	jmp		.L2756\@
.L2677\@:	insert_byte 1,\c,xmm11
	jmp		.L2756\@
.L2678\@:	insert_byte 2,\c,xmm11
	jmp		.L2756\@
.L2679\@:	insert_byte 3,\c,xmm11
	jmp		.L2756\@
.L2680\@:	insert_byte 4,\c,xmm11
	jmp		.L2756\@
.L2681\@:	insert_byte 5,\c,xmm11
	jmp		.L2756\@
.L2682\@:	insert_byte 6,\c,xmm11
	jmp		.L2756\@
.L2683\@:	insert_byte 7,\c,xmm11
	jmp		.L2756\@
.L2684\@:	insert_byte 8,\c,xmm11
	jmp		.L2756\@
.L2685\@:	insert_byte 9,\c,xmm11
	jmp		.L2756\@
.L2686\@:	insert_byte 10,\c,xmm11
	jmp		.L2756\@
.L2687\@:	insert_byte 11,\c,xmm11
	jmp		.L2756\@
.L2688\@:	insert_byte 12,\c,xmm11
	jmp		.L2756\@
.L2689\@:	insert_byte 13,\c,xmm11
	jmp		.L2756\@
.L2690\@:	insert_byte 14,\c,xmm11
	jmp		.L2756\@
.L2691\@:	insert_byte 15,\c,xmm11
	jmp		.L2756\@
.L2692\@:	insert_byte 0,\c,xmm12
	jmp		.L2756\@
.L2693\@:	insert_byte 1,\c,xmm12
	jmp		.L2756\@
.L2694\@:	insert_byte 2,\c,xmm12
	jmp		.L2756\@
.L2695\@:	insert_byte 3,\c,xmm12
	jmp		.L2756\@
.L2696\@:	insert_byte 4,\c,xmm12
	jmp		.L2756\@
.L2697\@:	insert_byte 5,\c,xmm12
	jmp		.L2756\@
.L2698\@:	insert_byte 6,\c,xmm12
	jmp		.L2756\@
.L2699\@:	insert_byte 7,\c,xmm12
	jmp		.L2756\@
.L2700\@:	insert_byte 8,\c,xmm12
	jmp		.L2756\@
.L2701\@:	insert_byte 9,\c,xmm12
	jmp		.L2756\@
.L2702\@:	insert_byte 10,\c,xmm12
	jmp		.L2756\@
.L2703\@:	insert_byte 11,\c,xmm12
	jmp		.L2756\@
.L2704\@:	insert_byte 12,\c,xmm12
	jmp		.L2756\@
.L2705\@:	insert_byte 13,\c,xmm12
	jmp		.L2756\@
.L2706\@:	insert_byte 14,\c,xmm12
	jmp		.L2756\@
.L2707\@:	insert_byte 15,\c,xmm12
	jmp		.L2756\@
.L2708\@:	insert_byte 0,\c,xmm13
	jmp		.L2756\@
.L2709\@:	insert_byte 1,\c,xmm13
	jmp		.L2756\@
.L2710\@:	insert_byte 2,\c,xmm13
	jmp		.L2756\@
.L2711\@:	insert_byte 3,\c,xmm13
	jmp		.L2756\@
.L2712\@:	insert_byte 4,\c,xmm13
	jmp		.L2756\@
.L2713\@:	insert_byte 5,\c,xmm13
	jmp		.L2756\@
.L2714\@:	insert_byte 6,\c,xmm13
	jmp		.L2756\@
.L2715\@:	insert_byte 7,\c,xmm13
	jmp		.L2756\@
.L2716\@:	insert_byte 8,\c,xmm13
	jmp		.L2756\@
.L2717\@:	insert_byte 9,\c,xmm13
	jmp		.L2756\@
.L2718\@:	insert_byte 10,\c,xmm13
	jmp		.L2756\@
.L2719\@:	insert_byte 11,\c,xmm13
	jmp		.L2756\@
.L2720\@:	insert_byte 12,\c,xmm13
	jmp		.L2756\@
.L2721\@:	insert_byte 13,\c,xmm13
	jmp		.L2756\@
.L2722\@:	insert_byte 14,\c,xmm13
	jmp		.L2756\@
.L2723\@:	insert_byte 15,\c,xmm13
	jmp		.L2756\@
.L2724\@:	insert_byte 0,\c,xmm14
	jmp		.L2756\@
.L2725\@:	insert_byte 1,\c,xmm14
	jmp		.L2756\@
.L2726\@:	insert_byte 2,\c,xmm14
	jmp		.L2756\@
.L2727\@:	insert_byte 3,\c,xmm14
	jmp		.L2756\@
.L2728\@:	insert_byte 4,\c,xmm14
	jmp		.L2756\@
.L2729\@:	insert_byte 5,\c,xmm14
	jmp		.L2756\@
.L2730\@:	insert_byte 6,\c,xmm14
	jmp		.L2756\@
.L2731\@:	insert_byte 7,\c,xmm14
	jmp		.L2756\@
.L2732\@:	insert_byte 8,\c,xmm14
	jmp		.L2756\@
.L2733\@:	insert_byte 9,\c,xmm14
	jmp		.L2756\@
.L2734\@:	insert_byte 10,\c,xmm14
	jmp		.L2756\@
.L2735\@:	insert_byte 11,\c,xmm14
	jmp		.L2756\@
.L2736\@:	insert_byte 12,\c,xmm14
	jmp		.L2756\@
.L2737\@:	insert_byte 13,\c,xmm14
	jmp		.L2756\@
.L2738\@:	insert_byte 14,\c,xmm14
	jmp		.L2756\@
.L2739\@:	insert_byte 15,\c,xmm14
	jmp		.L2756\@
.L2740\@:	insert_byte 0,\c,xmm15
	jmp		.L2756\@
.L2741\@:	insert_byte 1,\c,xmm15
	jmp		.L2756\@
.L2742\@:	insert_byte 2,\c,xmm15
	jmp		.L2756\@
.L2743\@:	insert_byte 3,\c,xmm15
	jmp		.L2756\@
.L2744\@:	insert_byte 4,\c,xmm15
	jmp		.L2756\@
.L2745\@:	insert_byte 5,\c,xmm15
	jmp		.L2756\@
.L2746\@:	insert_byte 6,\c,xmm15
	jmp		.L2756\@
.L2747\@:	insert_byte 7,\c,xmm15
	jmp		.L2756\@
.L2748\@:	insert_byte 8,\c,xmm15
	jmp		.L2756\@
.L2749\@:	insert_byte 9,\c,xmm15
	jmp		.L2756\@
.L2750\@:	insert_byte 10,\c,xmm15
	jmp		.L2756\@
.L2751\@:	insert_byte 11,\c,xmm15
	jmp		.L2756\@
.L2752\@:	insert_byte 12,\c,xmm15
	jmp		.L2756\@
.L2753\@:	insert_byte 13,\c,xmm15
	jmp		.L2756\@
.L2754\@:	insert_byte 14,\c,xmm15
	jmp		.L2756\@
.L2755\@:	insert_byte 15,\c,xmm15
	jmp		.L2756\@

.L2756\@:

.endm

#elif defined(HAVE_SSE2)
.macro insert_W_byte_sse2 c bi trax teax trdx tedx gpr0q gpr0l gpr1q
	andl		$0x000000ff,\c

	movl		\bi,\tedx
	andl		$0x000000ff,\tedx
	movl		insert_byte_sse2_jt\@(,\trdx,4),\teax
	cltq		/* sign extend address */
	leaq		insert_byte_sse2_jt\@(rip),\trdx
	addq		\trdx,\trax /* base address + offset */

	jmp 		*\trax /* essentially goto sign_extend32to64(insert_byte_sse2_jt[bi]) */

	/* Generated by gen_asm_reljump.py */
/* Insertion jump table for SSE2 */
.section .rodata
.align 4
insert_byte_sse2_jt\@:
.long	.L2000\@-insert_byte_sse2_jt\@
.long	.L2001\@-insert_byte_sse2_jt\@
.long	.L2002\@-insert_byte_sse2_jt\@
.long	.L2003\@-insert_byte_sse2_jt\@
.long	.L2004\@-insert_byte_sse2_jt\@
.long	.L2005\@-insert_byte_sse2_jt\@
.long	.L2006\@-insert_byte_sse2_jt\@
.long	.L2007\@-insert_byte_sse2_jt\@
.long	.L2008\@-insert_byte_sse2_jt\@
.long	.L2009\@-insert_byte_sse2_jt\@
.long	.L2010\@-insert_byte_sse2_jt\@
.long	.L2011\@-insert_byte_sse2_jt\@
.long	.L2012\@-insert_byte_sse2_jt\@
.long	.L2013\@-insert_byte_sse2_jt\@
.long	.L2014\@-insert_byte_sse2_jt\@
.long	.L2015\@-insert_byte_sse2_jt\@
.long	.L2016\@-insert_byte_sse2_jt\@
.long	.L2017\@-insert_byte_sse2_jt\@
.long	.L2018\@-insert_byte_sse2_jt\@
.long	.L2019\@-insert_byte_sse2_jt\@
.long	.L2020\@-insert_byte_sse2_jt\@
.long	.L2021\@-insert_byte_sse2_jt\@
.long	.L2022\@-insert_byte_sse2_jt\@
.long	.L2023\@-insert_byte_sse2_jt\@
.long	.L2024\@-insert_byte_sse2_jt\@
.long	.L2025\@-insert_byte_sse2_jt\@
.long	.L2026\@-insert_byte_sse2_jt\@
.long	.L2027\@-insert_byte_sse2_jt\@
.long	.L2028\@-insert_byte_sse2_jt\@
.long	.L2029\@-insert_byte_sse2_jt\@
.long	.L2030\@-insert_byte_sse2_jt\@
.long	.L2031\@-insert_byte_sse2_jt\@
.long	.L2032\@-insert_byte_sse2_jt\@
.long	.L2033\@-insert_byte_sse2_jt\@
.long	.L2034\@-insert_byte_sse2_jt\@
.long	.L2035\@-insert_byte_sse2_jt\@
.long	.L2036\@-insert_byte_sse2_jt\@
.long	.L2037\@-insert_byte_sse2_jt\@
.long	.L2038\@-insert_byte_sse2_jt\@
.long	.L2039\@-insert_byte_sse2_jt\@
.long	.L2040\@-insert_byte_sse2_jt\@
.long	.L2041\@-insert_byte_sse2_jt\@
.long	.L2042\@-insert_byte_sse2_jt\@
.long	.L2043\@-insert_byte_sse2_jt\@
.long	.L2044\@-insert_byte_sse2_jt\@
.long	.L2045\@-insert_byte_sse2_jt\@
.long	.L2046\@-insert_byte_sse2_jt\@
.long	.L2047\@-insert_byte_sse2_jt\@
.long	.L2048\@-insert_byte_sse2_jt\@
.long	.L2049\@-insert_byte_sse2_jt\@
.long	.L2050\@-insert_byte_sse2_jt\@
.long	.L2051\@-insert_byte_sse2_jt\@
.long	.L2052\@-insert_byte_sse2_jt\@
.long	.L2053\@-insert_byte_sse2_jt\@
.long	.L2054\@-insert_byte_sse2_jt\@
.long	.L2055\@-insert_byte_sse2_jt\@
.long	.L2056\@-insert_byte_sse2_jt\@
.long	.L2057\@-insert_byte_sse2_jt\@
.long	.L2058\@-insert_byte_sse2_jt\@
.long	.L2059\@-insert_byte_sse2_jt\@
.long	.L2060\@-insert_byte_sse2_jt\@
.long	.L2061\@-insert_byte_sse2_jt\@
.long	.L2062\@-insert_byte_sse2_jt\@
.long	.L2063\@-insert_byte_sse2_jt\@
.long	.L2064\@-insert_byte_sse2_jt\@
.long	.L2065\@-insert_byte_sse2_jt\@
.long	.L2066\@-insert_byte_sse2_jt\@
.long	.L2067\@-insert_byte_sse2_jt\@
.long	.L2068\@-insert_byte_sse2_jt\@
.long	.L2069\@-insert_byte_sse2_jt\@
.long	.L2070\@-insert_byte_sse2_jt\@
.long	.L2071\@-insert_byte_sse2_jt\@
.long	.L2072\@-insert_byte_sse2_jt\@
.long	.L2073\@-insert_byte_sse2_jt\@
.long	.L2074\@-insert_byte_sse2_jt\@
.long	.L2075\@-insert_byte_sse2_jt\@
.long	.L2076\@-insert_byte_sse2_jt\@
.long	.L2077\@-insert_byte_sse2_jt\@
.long	.L2078\@-insert_byte_sse2_jt\@
.long	.L2079\@-insert_byte_sse2_jt\@
.long	.L2080\@-insert_byte_sse2_jt\@
.long	.L2081\@-insert_byte_sse2_jt\@
.long	.L2082\@-insert_byte_sse2_jt\@
.long	.L2083\@-insert_byte_sse2_jt\@
.long	.L2084\@-insert_byte_sse2_jt\@
.long	.L2085\@-insert_byte_sse2_jt\@
.long	.L2086\@-insert_byte_sse2_jt\@
.long	.L2087\@-insert_byte_sse2_jt\@
.long	.L2088\@-insert_byte_sse2_jt\@
.long	.L2089\@-insert_byte_sse2_jt\@
.long	.L2090\@-insert_byte_sse2_jt\@
.long	.L2091\@-insert_byte_sse2_jt\@
.long	.L2092\@-insert_byte_sse2_jt\@
.long	.L2093\@-insert_byte_sse2_jt\@
.long	.L2094\@-insert_byte_sse2_jt\@
.long	.L2095\@-insert_byte_sse2_jt\@
.long	.L2096\@-insert_byte_sse2_jt\@
.long	.L2097\@-insert_byte_sse2_jt\@
.long	.L2098\@-insert_byte_sse2_jt\@
.long	.L2099\@-insert_byte_sse2_jt\@
.long	.L2100\@-insert_byte_sse2_jt\@
.long	.L2101\@-insert_byte_sse2_jt\@
.long	.L2102\@-insert_byte_sse2_jt\@
.long	.L2103\@-insert_byte_sse2_jt\@
.long	.L2104\@-insert_byte_sse2_jt\@
.long	.L2105\@-insert_byte_sse2_jt\@
.long	.L2106\@-insert_byte_sse2_jt\@
.long	.L2107\@-insert_byte_sse2_jt\@
.long	.L2108\@-insert_byte_sse2_jt\@
.long	.L2109\@-insert_byte_sse2_jt\@
.long	.L2110\@-insert_byte_sse2_jt\@
.long	.L2111\@-insert_byte_sse2_jt\@
.long	.L2112\@-insert_byte_sse2_jt\@
.long	.L2113\@-insert_byte_sse2_jt\@
.long	.L2114\@-insert_byte_sse2_jt\@
.long	.L2115\@-insert_byte_sse2_jt\@
.long	.L2116\@-insert_byte_sse2_jt\@
.long	.L2117\@-insert_byte_sse2_jt\@
.long	.L2118\@-insert_byte_sse2_jt\@
.long	.L2119\@-insert_byte_sse2_jt\@
.long	.L2120\@-insert_byte_sse2_jt\@
.long	.L2121\@-insert_byte_sse2_jt\@
.long	.L2122\@-insert_byte_sse2_jt\@
.long	.L2123\@-insert_byte_sse2_jt\@
.long	.L2124\@-insert_byte_sse2_jt\@
.long	.L2125\@-insert_byte_sse2_jt\@
.long	.L2126\@-insert_byte_sse2_jt\@
.long	.L2127\@-insert_byte_sse2_jt\@
.long	.L2128\@-insert_byte_sse2_jt\@
.long	.L2129\@-insert_byte_sse2_jt\@
.long	.L2130\@-insert_byte_sse2_jt\@
.long	.L2131\@-insert_byte_sse2_jt\@
.long	.L2132\@-insert_byte_sse2_jt\@
.long	.L2133\@-insert_byte_sse2_jt\@
.long	.L2134\@-insert_byte_sse2_jt\@
.long	.L2135\@-insert_byte_sse2_jt\@
.long	.L2136\@-insert_byte_sse2_jt\@
.long	.L2137\@-insert_byte_sse2_jt\@
.long	.L2138\@-insert_byte_sse2_jt\@
.long	.L2139\@-insert_byte_sse2_jt\@
.long	.L2140\@-insert_byte_sse2_jt\@
.long	.L2141\@-insert_byte_sse2_jt\@
.long	.L2142\@-insert_byte_sse2_jt\@
.long	.L2143\@-insert_byte_sse2_jt\@
.long	.L2144\@-insert_byte_sse2_jt\@
.long	.L2145\@-insert_byte_sse2_jt\@
.long	.L2146\@-insert_byte_sse2_jt\@
.long	.L2147\@-insert_byte_sse2_jt\@
.long	.L2148\@-insert_byte_sse2_jt\@
.long	.L2149\@-insert_byte_sse2_jt\@
.long	.L2150\@-insert_byte_sse2_jt\@
.long	.L2151\@-insert_byte_sse2_jt\@
.long	.L2152\@-insert_byte_sse2_jt\@
.long	.L2153\@-insert_byte_sse2_jt\@
.long	.L2154\@-insert_byte_sse2_jt\@
.long	.L2155\@-insert_byte_sse2_jt\@
.long	.L2156\@-insert_byte_sse2_jt\@
.long	.L2157\@-insert_byte_sse2_jt\@
.long	.L2158\@-insert_byte_sse2_jt\@
.long	.L2159\@-insert_byte_sse2_jt\@
.long	.L2160\@-insert_byte_sse2_jt\@
.long	.L2161\@-insert_byte_sse2_jt\@
.long	.L2162\@-insert_byte_sse2_jt\@
.long	.L2163\@-insert_byte_sse2_jt\@
.long	.L2164\@-insert_byte_sse2_jt\@
.long	.L2165\@-insert_byte_sse2_jt\@
.long	.L2166\@-insert_byte_sse2_jt\@
.long	.L2167\@-insert_byte_sse2_jt\@
.long	.L2168\@-insert_byte_sse2_jt\@
.long	.L2169\@-insert_byte_sse2_jt\@
.long	.L2170\@-insert_byte_sse2_jt\@
.long	.L2171\@-insert_byte_sse2_jt\@
.long	.L2172\@-insert_byte_sse2_jt\@
.long	.L2173\@-insert_byte_sse2_jt\@
.long	.L2174\@-insert_byte_sse2_jt\@
.long	.L2175\@-insert_byte_sse2_jt\@
.long	.L2176\@-insert_byte_sse2_jt\@
.long	.L2177\@-insert_byte_sse2_jt\@
.long	.L2178\@-insert_byte_sse2_jt\@
.long	.L2179\@-insert_byte_sse2_jt\@
.long	.L2180\@-insert_byte_sse2_jt\@
.long	.L2181\@-insert_byte_sse2_jt\@
.long	.L2182\@-insert_byte_sse2_jt\@
.long	.L2183\@-insert_byte_sse2_jt\@
.long	.L2184\@-insert_byte_sse2_jt\@
.long	.L2185\@-insert_byte_sse2_jt\@
.long	.L2186\@-insert_byte_sse2_jt\@
.long	.L2187\@-insert_byte_sse2_jt\@
.long	.L2188\@-insert_byte_sse2_jt\@
.long	.L2189\@-insert_byte_sse2_jt\@
.long	.L2190\@-insert_byte_sse2_jt\@
.long	.L2191\@-insert_byte_sse2_jt\@
.long	.L2192\@-insert_byte_sse2_jt\@
.long	.L2193\@-insert_byte_sse2_jt\@
.long	.L2194\@-insert_byte_sse2_jt\@
.long	.L2195\@-insert_byte_sse2_jt\@
.long	.L2196\@-insert_byte_sse2_jt\@
.long	.L2197\@-insert_byte_sse2_jt\@
.long	.L2198\@-insert_byte_sse2_jt\@
.long	.L2199\@-insert_byte_sse2_jt\@
.long	.L2200\@-insert_byte_sse2_jt\@
.long	.L2201\@-insert_byte_sse2_jt\@
.long	.L2202\@-insert_byte_sse2_jt\@
.long	.L2203\@-insert_byte_sse2_jt\@
.long	.L2204\@-insert_byte_sse2_jt\@
.long	.L2205\@-insert_byte_sse2_jt\@
.long	.L2206\@-insert_byte_sse2_jt\@
.long	.L2207\@-insert_byte_sse2_jt\@
.long	.L2208\@-insert_byte_sse2_jt\@
.long	.L2209\@-insert_byte_sse2_jt\@
.long	.L2210\@-insert_byte_sse2_jt\@
.long	.L2211\@-insert_byte_sse2_jt\@
.long	.L2212\@-insert_byte_sse2_jt\@
.long	.L2213\@-insert_byte_sse2_jt\@
.long	.L2214\@-insert_byte_sse2_jt\@
.long	.L2215\@-insert_byte_sse2_jt\@
.long	.L2216\@-insert_byte_sse2_jt\@
.long	.L2217\@-insert_byte_sse2_jt\@
.long	.L2218\@-insert_byte_sse2_jt\@
.long	.L2219\@-insert_byte_sse2_jt\@
.long	.L2220\@-insert_byte_sse2_jt\@
.long	.L2221\@-insert_byte_sse2_jt\@
.long	.L2222\@-insert_byte_sse2_jt\@
.long	.L2223\@-insert_byte_sse2_jt\@
.long	.L2224\@-insert_byte_sse2_jt\@
.long	.L2225\@-insert_byte_sse2_jt\@
.long	.L2226\@-insert_byte_sse2_jt\@
.long	.L2227\@-insert_byte_sse2_jt\@
.long	.L2228\@-insert_byte_sse2_jt\@
.long	.L2229\@-insert_byte_sse2_jt\@
.long	.L2230\@-insert_byte_sse2_jt\@
.long	.L2231\@-insert_byte_sse2_jt\@
.long	.L2232\@-insert_byte_sse2_jt\@
.long	.L2233\@-insert_byte_sse2_jt\@
.long	.L2234\@-insert_byte_sse2_jt\@
.long	.L2235\@-insert_byte_sse2_jt\@
.long	.L2236\@-insert_byte_sse2_jt\@
.long	.L2237\@-insert_byte_sse2_jt\@
.long	.L2238\@-insert_byte_sse2_jt\@
.long	.L2239\@-insert_byte_sse2_jt\@
.long	.L2240\@-insert_byte_sse2_jt\@
.long	.L2241\@-insert_byte_sse2_jt\@
.long	.L2242\@-insert_byte_sse2_jt\@
.long	.L2243\@-insert_byte_sse2_jt\@
.long	.L2244\@-insert_byte_sse2_jt\@
.long	.L2245\@-insert_byte_sse2_jt\@
.long	.L2246\@-insert_byte_sse2_jt\@
.long	.L2247\@-insert_byte_sse2_jt\@
.long	.L2248\@-insert_byte_sse2_jt\@
.long	.L2249\@-insert_byte_sse2_jt\@
.long	.L2250\@-insert_byte_sse2_jt\@
.long	.L2251\@-insert_byte_sse2_jt\@
.long	.L2252\@-insert_byte_sse2_jt\@
.long	.L2253\@-insert_byte_sse2_jt\@
.long	.L2254\@-insert_byte_sse2_jt\@
.long	.L2255\@-insert_byte_sse2_jt\@
.long	.L2256\@-insert_byte_sse2_jt\@
.text
.L2000\@:	insert_byte 0,\c,xmm0,xmm15
	jmp		.L2256\@
.L2001\@:	insert_byte 1,\c,xmm0,xmm15
	jmp		.L2256\@
.L2002\@:	insert_byte 2,\c,xmm0,xmm15
	jmp		.L2256\@
.L2003\@:	insert_byte 3,\c,xmm0,xmm15
	jmp		.L2256\@
.L2004\@:	insert_byte 4,\c,xmm0,xmm15
	jmp		.L2256\@
.L2005\@:	insert_byte 5,\c,xmm0,xmm15
	jmp		.L2256\@
.L2006\@:	insert_byte 6,\c,xmm0,xmm15
	jmp		.L2256\@
.L2007\@:	insert_byte 7,\c,xmm0,xmm15
	jmp		.L2256\@
.L2008\@:	insert_byte 8,\c,xmm0,xmm15
	jmp		.L2256\@
.L2009\@:	insert_byte 9,\c,xmm0,xmm15
	jmp		.L2256\@
.L2010\@:	insert_byte 10,\c,xmm0,xmm15
	jmp		.L2256\@
.L2011\@:	insert_byte 11,\c,xmm0,xmm15
	jmp		.L2256\@
.L2012\@:	insert_byte 12,\c,xmm0,xmm15
	jmp		.L2256\@
.L2013\@:	insert_byte 13,\c,xmm0,xmm15
	jmp		.L2256\@
.L2014\@:	insert_byte 14,\c,xmm0,xmm15
	jmp		.L2256\@
.L2015\@:	insert_byte 15,\c,xmm0,xmm15
	jmp		.L2256\@
.L2016\@:	insert_byte 0,\c,xmm1,xmm15
	jmp		.L2256\@
.L2017\@:	insert_byte 1,\c,xmm1,xmm15
	jmp		.L2256\@
.L2018\@:	insert_byte 2,\c,xmm1,xmm15
	jmp		.L2256\@
.L2019\@:	insert_byte 3,\c,xmm1,xmm15
	jmp		.L2256\@
.L2020\@:	insert_byte 4,\c,xmm1,xmm15
	jmp		.L2256\@
.L2021\@:	insert_byte 5,\c,xmm1,xmm15
	jmp		.L2256\@
.L2022\@:	insert_byte 6,\c,xmm1,xmm15
	jmp		.L2256\@
.L2023\@:	insert_byte 7,\c,xmm1,xmm15
	jmp		.L2256\@
.L2024\@:	insert_byte 8,\c,xmm1,xmm15
	jmp		.L2256\@
.L2025\@:	insert_byte 9,\c,xmm1,xmm15
	jmp		.L2256\@
.L2026\@:	insert_byte 10,\c,xmm1,xmm15
	jmp		.L2256\@
.L2027\@:	insert_byte 11,\c,xmm1,xmm15
	jmp		.L2256\@
.L2028\@:	insert_byte 12,\c,xmm1,xmm15
	jmp		.L2256\@
.L2029\@:	insert_byte 13,\c,xmm1,xmm15
	jmp		.L2256\@
.L2030\@:	insert_byte 14,\c,xmm1,xmm15
	jmp		.L2256\@
.L2031\@:	insert_byte 15,\c,xmm1,xmm15
	jmp		.L2256\@
.L2032\@:	insert_byte 0,\c,xmm2,xmm15
	jmp		.L2256\@
.L2033\@:	insert_byte 1,\c,xmm2,xmm15
	jmp		.L2256\@
.L2034\@:	insert_byte 2,\c,xmm2,xmm15
	jmp		.L2256\@
.L2035\@:	insert_byte 3,\c,xmm2,xmm15
	jmp		.L2256\@
.L2036\@:	insert_byte 4,\c,xmm2,xmm15
	jmp		.L2256\@
.L2037\@:	insert_byte 5,\c,xmm2,xmm15
	jmp		.L2256\@
.L2038\@:	insert_byte 6,\c,xmm2,xmm15
	jmp		.L2256\@
.L2039\@:	insert_byte 7,\c,xmm2,xmm15
	jmp		.L2256\@
.L2040\@:	insert_byte 8,\c,xmm2,xmm15
	jmp		.L2256\@
.L2041\@:	insert_byte 9,\c,xmm2,xmm15
	jmp		.L2256\@
.L2042\@:	insert_byte 10,\c,xmm2,xmm15
	jmp		.L2256\@
.L2043\@:	insert_byte 11,\c,xmm2,xmm15
	jmp		.L2256\@
.L2044\@:	insert_byte 12,\c,xmm2,xmm15
	jmp		.L2256\@
.L2045\@:	insert_byte 13,\c,xmm2,xmm15
	jmp		.L2256\@
.L2046\@:	insert_byte 14,\c,xmm2,xmm15
	jmp		.L2256\@
.L2047\@:	insert_byte 15,\c,xmm2,xmm15
	jmp		.L2256\@
.L2048\@:	insert_byte 0,\c,xmm3,xmm15
	jmp		.L2256\@
.L2049\@:	insert_byte 1,\c,xmm3,xmm15
	jmp		.L2256\@
.L2050\@:	insert_byte 2,\c,xmm3,xmm15
	jmp		.L2256\@
.L2051\@:	insert_byte 3,\c,xmm3,xmm15
	jmp		.L2256\@
.L2052\@:	insert_byte 4,\c,xmm3,xmm15
	jmp		.L2256\@
.L2053\@:	insert_byte 5,\c,xmm3,xmm15
	jmp		.L2256\@
.L2054\@:	insert_byte 6,\c,xmm3,xmm15
	jmp		.L2256\@
.L2055\@:	insert_byte 7,\c,xmm3,xmm15
	jmp		.L2256\@
.L2056\@:	insert_byte 8,\c,xmm3,xmm15
	jmp		.L2256\@
.L2057\@:	insert_byte 9,\c,xmm3,xmm15
	jmp		.L2256\@
.L2058\@:	insert_byte 10,\c,xmm3,xmm15
	jmp		.L2256\@
.L2059\@:	insert_byte 11,\c,xmm3,xmm15
	jmp		.L2256\@
.L2060\@:	insert_byte 12,\c,xmm3,xmm15
	jmp		.L2256\@
.L2061\@:	insert_byte 13,\c,xmm3,xmm15
	jmp		.L2256\@
.L2062\@:	insert_byte 14,\c,xmm3,xmm15
	jmp		.L2256\@
.L2063\@:	insert_byte 15,\c,xmm3,xmm15
	jmp		.L2256\@
.L2064\@:	insert_byte 0,\c,xmm4,xmm15
	jmp		.L2256\@
.L2065\@:	insert_byte 1,\c,xmm4,xmm15
	jmp		.L2256\@
.L2066\@:	insert_byte 2,\c,xmm4,xmm15
	jmp		.L2256\@
.L2067\@:	insert_byte 3,\c,xmm4,xmm15
	jmp		.L2256\@
.L2068\@:	insert_byte 4,\c,xmm4,xmm15
	jmp		.L2256\@
.L2069\@:	insert_byte 5,\c,xmm4,xmm15
	jmp		.L2256\@
.L2070\@:	insert_byte 6,\c,xmm4,xmm15
	jmp		.L2256\@
.L2071\@:	insert_byte 7,\c,xmm4,xmm15
	jmp		.L2256\@
.L2072\@:	insert_byte 8,\c,xmm4,xmm15
	jmp		.L2256\@
.L2073\@:	insert_byte 9,\c,xmm4,xmm15
	jmp		.L2256\@
.L2074\@:	insert_byte 10,\c,xmm4,xmm15
	jmp		.L2256\@
.L2075\@:	insert_byte 11,\c,xmm4,xmm15
	jmp		.L2256\@
.L2076\@:	insert_byte 12,\c,xmm4,xmm15
	jmp		.L2256\@
.L2077\@:	insert_byte 13,\c,xmm4,xmm15
	jmp		.L2256\@
.L2078\@:	insert_byte 14,\c,xmm4,xmm15
	jmp		.L2256\@
.L2079\@:	insert_byte 15,\c,xmm4,xmm15
	jmp		.L2256\@
.L2080\@:	insert_byte 0,\c,xmm5,xmm15
	jmp		.L2256\@
.L2081\@:	insert_byte 1,\c,xmm5,xmm15
	jmp		.L2256\@
.L2082\@:	insert_byte 2,\c,xmm5,xmm15
	jmp		.L2256\@
.L2083\@:	insert_byte 3,\c,xmm5,xmm15
	jmp		.L2256\@
.L2084\@:	insert_byte 4,\c,xmm5,xmm15
	jmp		.L2256\@
.L2085\@:	insert_byte 5,\c,xmm5,xmm15
	jmp		.L2256\@
.L2086\@:	insert_byte 6,\c,xmm5,xmm15
	jmp		.L2256\@
.L2087\@:	insert_byte 7,\c,xmm5,xmm15
	jmp		.L2256\@
.L2088\@:	insert_byte 8,\c,xmm5,xmm15
	jmp		.L2256\@
.L2089\@:	insert_byte 9,\c,xmm5,xmm15
	jmp		.L2256\@
.L2090\@:	insert_byte 10,\c,xmm5,xmm15
	jmp		.L2256\@
.L2091\@:	insert_byte 11,\c,xmm5,xmm15
	jmp		.L2256\@
.L2092\@:	insert_byte 12,\c,xmm5,xmm15
	jmp		.L2256\@
.L2093\@:	insert_byte 13,\c,xmm5,xmm15
	jmp		.L2256\@
.L2094\@:	insert_byte 14,\c,xmm5,xmm15
	jmp		.L2256\@
.L2095\@:	insert_byte 15,\c,xmm5,xmm15
	jmp		.L2256\@
.L2096\@:	insert_byte 0,\c,xmm6,xmm15
	jmp		.L2256\@
.L2097\@:	insert_byte 1,\c,xmm6,xmm15
	jmp		.L2256\@
.L2098\@:	insert_byte 2,\c,xmm6,xmm15
	jmp		.L2256\@
.L2099\@:	insert_byte 3,\c,xmm6,xmm15
	jmp		.L2256\@
.L2100\@:	insert_byte 4,\c,xmm6,xmm15
	jmp		.L2256\@
.L2101\@:	insert_byte 5,\c,xmm6,xmm15
	jmp		.L2256\@
.L2102\@:	insert_byte 6,\c,xmm6,xmm15
	jmp		.L2256\@
.L2103\@:	insert_byte 7,\c,xmm6,xmm15
	jmp		.L2256\@
.L2104\@:	insert_byte 8,\c,xmm6,xmm15
	jmp		.L2256\@
.L2105\@:	insert_byte 9,\c,xmm6,xmm15
	jmp		.L2256\@
.L2106\@:	insert_byte 10,\c,xmm6,xmm15
	jmp		.L2256\@
.L2107\@:	insert_byte 11,\c,xmm6,xmm15
	jmp		.L2256\@
.L2108\@:	insert_byte 12,\c,xmm6,xmm15
	jmp		.L2256\@
.L2109\@:	insert_byte 13,\c,xmm6,xmm15
	jmp		.L2256\@
.L2110\@:	insert_byte 14,\c,xmm6,xmm15
	jmp		.L2256\@
.L2111\@:	insert_byte 15,\c,xmm6,xmm15
	jmp		.L2256\@
.L2112\@:	insert_byte 0,\c,xmm7,xmm15
	jmp		.L2256\@
.L2113\@:	insert_byte 1,\c,xmm7,xmm15
	jmp		.L2256\@
.L2114\@:	insert_byte 2,\c,xmm7,xmm15
	jmp		.L2256\@
.L2115\@:	insert_byte 3,\c,xmm7,xmm15
	jmp		.L2256\@
.L2116\@:	insert_byte 4,\c,xmm7,xmm15
	jmp		.L2256\@
.L2117\@:	insert_byte 5,\c,xmm7,xmm15
	jmp		.L2256\@
.L2118\@:	insert_byte 6,\c,xmm7,xmm15
	jmp		.L2256\@
.L2119\@:	insert_byte 7,\c,xmm7,xmm15
	jmp		.L2256\@
.L2120\@:	insert_byte 8,\c,xmm7,xmm15
	jmp		.L2256\@
.L2121\@:	insert_byte 9,\c,xmm7,xmm15
	jmp		.L2256\@
.L2122\@:	insert_byte 10,\c,xmm7,xmm15
	jmp		.L2256\@
.L2123\@:	insert_byte 11,\c,xmm7,xmm15
	jmp		.L2256\@
.L2124\@:	insert_byte 12,\c,xmm7,xmm15
	jmp		.L2256\@
.L2125\@:	insert_byte 13,\c,xmm7,xmm15
	jmp		.L2256\@
.L2126\@:	insert_byte 14,\c,xmm7,xmm15
	jmp		.L2256\@
.L2127\@:	insert_byte 15,\c,xmm7,xmm15
	jmp		.L2256\@
.L2128\@:	insert_byte 0,\c,xmm8,xmm15
	jmp		.L2256\@
.L2129\@:	insert_byte 1,\c,xmm8,xmm15
	jmp		.L2256\@
.L2130\@:	insert_byte 2,\c,xmm8,xmm15
	jmp		.L2256\@
.L2131\@:	insert_byte 3,\c,xmm8,xmm15
	jmp		.L2256\@
.L2132\@:	insert_byte 4,\c,xmm8,xmm15
	jmp		.L2256\@
.L2133\@:	insert_byte 5,\c,xmm8,xmm15
	jmp		.L2256\@
.L2134\@:	insert_byte 6,\c,xmm8,xmm15
	jmp		.L2256\@
.L2135\@:	insert_byte 7,\c,xmm8,xmm15
	jmp		.L2256\@
.L2136\@:	insert_byte 8,\c,xmm8,xmm15
	jmp		.L2256\@
.L2137\@:	insert_byte 9,\c,xmm8,xmm15
	jmp		.L2256\@
.L2138\@:	insert_byte 10,\c,xmm8,xmm15
	jmp		.L2256\@
.L2139\@:	insert_byte 11,\c,xmm8,xmm15
	jmp		.L2256\@
.L2140\@:	insert_byte 12,\c,xmm8,xmm15
	jmp		.L2256\@
.L2141\@:	insert_byte 13,\c,xmm8,xmm15
	jmp		.L2256\@
.L2142\@:	insert_byte 14,\c,xmm8,xmm15
	jmp		.L2256\@
.L2143\@:	insert_byte 15,\c,xmm8,xmm15
	jmp		.L2256\@
.L2144\@:	insert_byte 0,\c,xmm9,xmm15
	jmp		.L2256\@
.L2145\@:	insert_byte 1,\c,xmm9,xmm15
	jmp		.L2256\@
.L2146\@:	insert_byte 2,\c,xmm9,xmm15
	jmp		.L2256\@
.L2147\@:	insert_byte 3,\c,xmm9,xmm15
	jmp		.L2256\@
.L2148\@:	insert_byte 4,\c,xmm9,xmm15
	jmp		.L2256\@
.L2149\@:	insert_byte 5,\c,xmm9,xmm15
	jmp		.L2256\@
.L2150\@:	insert_byte 6,\c,xmm9,xmm15
	jmp		.L2256\@
.L2151\@:	insert_byte 7,\c,xmm9,xmm15
	jmp		.L2256\@
.L2152\@:	insert_byte 8,\c,xmm9,xmm15
	jmp		.L2256\@
.L2153\@:	insert_byte 9,\c,xmm9,xmm15
	jmp		.L2256\@
.L2154\@:	insert_byte 10,\c,xmm9,xmm15
	jmp		.L2256\@
.L2155\@:	insert_byte 11,\c,xmm9,xmm15
	jmp		.L2256\@
.L2156\@:	insert_byte 12,\c,xmm9,xmm15
	jmp		.L2256\@
.L2157\@:	insert_byte 13,\c,xmm9,xmm15
	jmp		.L2256\@
.L2158\@:	insert_byte 14,\c,xmm9,xmm15
	jmp		.L2256\@
.L2159\@:	insert_byte 15,\c,xmm9,xmm15
	jmp		.L2256\@
.L2160\@:	insert_byte 0,\c,xmm10,xmm15
	jmp		.L2256\@
.L2161\@:	insert_byte 1,\c,xmm10,xmm15
	jmp		.L2256\@
.L2162\@:	insert_byte 2,\c,xmm10,xmm15
	jmp		.L2256\@
.L2163\@:	insert_byte 3,\c,xmm10,xmm15
	jmp		.L2256\@
.L2164\@:	insert_byte 4,\c,xmm10,xmm15
	jmp		.L2256\@
.L2165\@:	insert_byte 5,\c,xmm10,xmm15
	jmp		.L2256\@
.L2166\@:	insert_byte 6,\c,xmm10,xmm15
	jmp		.L2256\@
.L2167\@:	insert_byte 7,\c,xmm10,xmm15
	jmp		.L2256\@
.L2168\@:	insert_byte 8,\c,xmm10,xmm15
	jmp		.L2256\@
.L2169\@:	insert_byte 9,\c,xmm10,xmm15
	jmp		.L2256\@
.L2170\@:	insert_byte 10,\c,xmm10,xmm15
	jmp		.L2256\@
.L2171\@:	insert_byte 11,\c,xmm10,xmm15
	jmp		.L2256\@
.L2172\@:	insert_byte 12,\c,xmm10,xmm15
	jmp		.L2256\@
.L2173\@:	insert_byte 13,\c,xmm10,xmm15
	jmp		.L2256\@
.L2174\@:	insert_byte 14,\c,xmm10,xmm15
	jmp		.L2256\@
.L2175\@:	insert_byte 15,\c,xmm10,xmm15
	jmp		.L2256\@
.L2176\@:	insert_byte 0,\c,xmm11,xmm15
	jmp		.L2256\@
.L2177\@:	insert_byte 1,\c,xmm11,xmm15
	jmp		.L2256\@
.L2178\@:	insert_byte 2,\c,xmm11,xmm15
	jmp		.L2256\@
.L2179\@:	insert_byte 3,\c,xmm11,xmm15
	jmp		.L2256\@
.L2180\@:	insert_byte 4,\c,xmm11,xmm15
	jmp		.L2256\@
.L2181\@:	insert_byte 5,\c,xmm11,xmm15
	jmp		.L2256\@
.L2182\@:	insert_byte 6,\c,xmm11,xmm15
	jmp		.L2256\@
.L2183\@:	insert_byte 7,\c,xmm11,xmm15
	jmp		.L2256\@
.L2184\@:	insert_byte 8,\c,xmm11,xmm15
	jmp		.L2256\@
.L2185\@:	insert_byte 9,\c,xmm11,xmm15
	jmp		.L2256\@
.L2186\@:	insert_byte 10,\c,xmm11,xmm15
	jmp		.L2256\@
.L2187\@:	insert_byte 11,\c,xmm11,xmm15
	jmp		.L2256\@
.L2188\@:	insert_byte 12,\c,xmm11,xmm15
	jmp		.L2256\@
.L2189\@:	insert_byte 13,\c,xmm11,xmm15
	jmp		.L2256\@
.L2190\@:	insert_byte 14,\c,xmm11,xmm15
	jmp		.L2256\@
.L2191\@:	insert_byte 15,\c,xmm11,xmm15
	jmp		.L2256\@
.L2192\@:	insert_byte 0,\c,xmm12,xmm15
	jmp		.L2256\@
.L2193\@:	insert_byte 1,\c,xmm12,xmm15
	jmp		.L2256\@
.L2194\@:	insert_byte 2,\c,xmm12,xmm15
	jmp		.L2256\@
.L2195\@:	insert_byte 3,\c,xmm12,xmm15
	jmp		.L2256\@
.L2196\@:	insert_byte 4,\c,xmm12,xmm15
	jmp		.L2256\@
.L2197\@:	insert_byte 5,\c,xmm12,xmm15
	jmp		.L2256\@
.L2198\@:	insert_byte 6,\c,xmm12,xmm15
	jmp		.L2256\@
.L2199\@:	insert_byte 7,\c,xmm12,xmm15
	jmp		.L2256\@
.L2200\@:	insert_byte 8,\c,xmm12,xmm15
	jmp		.L2256\@
.L2201\@:	insert_byte 9,\c,xmm12,xmm15
	jmp		.L2256\@
.L2202\@:	insert_byte 10,\c,xmm12,xmm15
	jmp		.L2256\@
.L2203\@:	insert_byte 11,\c,xmm12,xmm15
	jmp		.L2256\@
.L2204\@:	insert_byte 12,\c,xmm12,xmm15
	jmp		.L2256\@
.L2205\@:	insert_byte 13,\c,xmm12,xmm15
	jmp		.L2256\@
.L2206\@:	insert_byte 14,\c,xmm12,xmm15
	jmp		.L2256\@
.L2207\@:	insert_byte 15,\c,xmm12,xmm15
	jmp		.L2256\@
.L2208\@:	insert_byte 0,\c,xmm13,xmm15
	jmp		.L2256\@
.L2209\@:	insert_byte 1,\c,xmm13,xmm15
	jmp		.L2256\@
.L2210\@:	insert_byte 2,\c,xmm13,xmm15
	jmp		.L2256\@
.L2211\@:	insert_byte 3,\c,xmm13,xmm15
	jmp		.L2256\@
.L2212\@:	insert_byte 4,\c,xmm13,xmm15
	jmp		.L2256\@
.L2213\@:	insert_byte 5,\c,xmm13,xmm15
	jmp		.L2256\@
.L2214\@:	insert_byte 6,\c,xmm13,xmm15
	jmp		.L2256\@
.L2215\@:	insert_byte 7,\c,xmm13,xmm15
	jmp		.L2256\@
.L2216\@:	insert_byte 8,\c,xmm13,xmm15
	jmp		.L2256\@
.L2217\@:	insert_byte 9,\c,xmm13,xmm15
	jmp		.L2256\@
.L2218\@:	insert_byte 10,\c,xmm13,xmm15
	jmp		.L2256\@
.L2219\@:	insert_byte 11,\c,xmm13,xmm15
	jmp		.L2256\@
.L2220\@:	insert_byte 12,\c,xmm13,xmm15
	jmp		.L2256\@
.L2221\@:	insert_byte 13,\c,xmm13,xmm15
	jmp		.L2256\@
.L2222\@:	insert_byte 14,\c,xmm13,xmm15
	jmp		.L2256\@
.L2223\@:	insert_byte 15,\c,xmm13,xmm15
	jmp		.L2256\@
.L2224\@:	insert_byte 0,\c,xmm14,xmm15
	jmp		.L2256\@
.L2225\@:	insert_byte 1,\c,xmm14,xmm15
	jmp		.L2256\@
.L2226\@:	insert_byte 2,\c,xmm14,xmm15
	jmp		.L2256\@
.L2227\@:	insert_byte 3,\c,xmm14,xmm15
	jmp		.L2256\@
.L2228\@:	insert_byte 4,\c,xmm14,xmm15
	jmp		.L2256\@
.L2229\@:	insert_byte 5,\c,xmm14,xmm15
	jmp		.L2256\@
.L2230\@:	insert_byte 6,\c,xmm14,xmm15
	jmp		.L2256\@
.L2231\@:	insert_byte 7,\c,xmm14,xmm15
	jmp		.L2256\@
.L2232\@:	insert_byte 8,\c,xmm14,xmm15
	jmp		.L2256\@
.L2233\@:	insert_byte 9,\c,xmm14,xmm15
	jmp		.L2256\@
.L2234\@:	insert_byte 10,\c,xmm14,xmm15
	jmp		.L2256\@
.L2235\@:	insert_byte 11,\c,xmm14,xmm15
	jmp		.L2256\@
.L2236\@:	insert_byte 12,\c,xmm14,xmm15
	jmp		.L2256\@
.L2237\@:	insert_byte 13,\c,xmm14,xmm15
	jmp		.L2256\@
.L2238\@:	insert_byte 14,\c,xmm14,xmm15
	jmp		.L2256\@
.L2239\@:	insert_byte 15,\c,xmm14,xmm15
	jmp		.L2256\@
.L2240\@:	insert_byte_alt 0,\c,mm4,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2241\@:	insert_byte_alt 1,\c,mm4,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2242\@:	insert_byte_alt 2,\c,mm4,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2243\@:	insert_byte_alt 3,\c,mm4,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2244\@:	insert_byte_alt 4,\c,mm4,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2245\@:	insert_byte_alt 5,\c,mm4,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2246\@:	insert_byte_alt 6,\c,mm4,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2247\@:	insert_byte_alt 7,\c,mm4,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2248\@:	insert_byte_alt 0,\c,mm5,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2249\@:	insert_byte_alt 1,\c,mm5,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2250\@:	insert_byte_alt 2,\c,mm5,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2251\@:	insert_byte_alt 3,\c,mm5,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2252\@:	insert_byte_alt 4,\c,mm5,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2253\@:	insert_byte_alt 5,\c,mm5,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2254\@:	insert_byte_alt 6,\c,mm5,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@
.L2255\@:	insert_byte_alt 7,\c,mm5,\gpr0q,\gpr0l,\gpr1q
	jmp		.L2256\@

.L2256\@:

.endm
#endif


/* Local variable positions on the stack.  See tsha256a_update for details. */
.set state,-8
.set finish,-12
.set ret,-16
.set i,-20
.set j,-24
.set i_len,-28

.macro set_length
/*	for(i_len = 0, i = 64 - L_SIZE ; i < 64 ; i++, i_len++):
 *		W8[seq2[i_len]] = len8[i_len];		      */

	movq		msglen(rdi),rax

	salq		$3,rax /* state->msglen*8 */
	movq		rax,mm6	/* len8:mm6 */

	/* i_len = 0 ; i_len is index of byte in mm6 */
	movl		$0,i_len(rbp)

	/* i = 64 - L_SIZE */
	movl		$64,ebx
	subl		$8,ebx /* L_SIZE */
	movl		ebx,i(rbp)

	/* i < 64 */
200:	cmpl		$64,ebx
	jl		201f
	jmp		202f

201:
		/* t = seq2[i_len] */
		movl		i_len(rbp),ecx
		movl		seq2(,rcx,4),r11d

		movq		mm6,rax
		movb		al,r10b

#ifdef HAVE_SSE4_1
		insert_W_byte_sse4_1 r10d,r11d,rax,eax,rdx,edx
#elif defined(HAVE_SSE2)
		insert_W_byte_sse2 r10d,r11d,rax,eax,rdx,edx,r13,r13d,r14
#endif

		movq		mm6,rax
		shrq		$8,rax
		movq		rax,mm6

		/* i_len++ */
		movl		i_len(rbp),ebx
		incl		ebx
		movl		ebx,i_len(rbp)

		/* i++ */
		movl		i(rbp),ebx
		incl		ebx
		movl		ebx,i(rbp)

		jmp 		200b
202:
.endm

.macro expand_message_blocks j
	/* Expanding message blocks
	 * for (j = 16; j < 64; j++):
	 *	u32 sig0, sig1;
	 *	sig0 = ROTR(W32[j-15],7) ^ ROTR(W32[j-15],18)
	 *		^ (W32[j-15] >> 3);
	 *	sig1 = ROTR(W32[j-2],17) ^ ROTR(W32[j-2], 19)
	 *		^ (W32[j-2] >> 10);
	 *	W32[j] = W32[j-16] + sig0 + W32[j-7] + sig1;
	 */


	/* sig0 = ROTR(W32[j-15],7) ^ ROTR(W32[j-15],18)
			^ (W32[j-15] >> 3)				      */
	movl		$\j,r11d
	subl		$15,r11d
#ifdef HAVE_SSE4_1
	get_w		ebx,r11d,rax,eax,rdx,edx
#elif defined(HAVE_SSE2)
	get_w		ebx,r11d,rax,eax,rdx,edx,r10,r10d
#endif

	movl		ebx,eax
	movl		ebx,ecx

	rorl		$7,eax
	rorl		$18,ebx
	shrl		$3,ecx
	xorl		eax,ebx
	xorl		ebx,ecx
	movl		ecx,r12d /* r12d = sig0 */

	/* sig1 = ROTR(W32[j-2],17) ^ ROTR(W32[j-2], 19)
		^ (W32[j-2] >> 10)				      */
	movl		$\j,r11d
	subl		$2,r11d
#ifdef HAVE_SSE4_1
	get_w		ebx,r11d,rax,eax,rdx,edx
#elif defined(HAVE_SSE2)
	get_w		ebx,r11d,rax,eax,rdx,edx,r10,r10d
#endif

	movl		ebx,eax
	movl		ebx,ecx

	rorl		$17,eax
	rorl		$19,ebx
	shrl		$10,ecx
	xorl		eax,ebx
	xorl		ebx,ecx /* ecx = sig1 */

	/* W32[j] = W32[j-16] + sig0 + W32[j-7] + sig1 */
	movl		$\j,r11d
	subl		$16,r11d
#ifdef HAVE_SSE4_1
	get_w		r13d,r11d,rax,eax,rdx,edx
#elif defined(HAVE_SSE2)
	get_w		r13d,r11d,rax,eax,rdx,edx,r10,r10d
#endif

	movl		$\j,r11d
	subl		$7,r11d
#ifdef HAVE_SSE4_1
	get_w		r14d,r11d,rax,eax,rdx,edx
#elif defined(HAVE_SSE2)
	get_w		r14d,r11d,rax,eax,rdx,edx,r10,r10d
#endif

	addl		r12d,r13d	/* t = W32[j-16] + sig0 */
	addl		r14d,r13d	/* t += W32[j-7] */
	addl		ecx,r13d	/* t += sig1 */

	/* W32[j] = t */
	movl		$\j,ebx
#ifdef HAVE_SSE4_1
	set_w		r13d,ebx,rax,eax,rdx,edx
#elif defined(HAVE_SSE2)
	set_w		r13d,ebx,rax,eax,rdx,edx,r10,r10d,r11
#endif
.endm

.macro dprint_show_A_state
#ifdef DEBUG_LEVEL_2
	/* printf("Hex values %d:\n"); */
	pusha64
	movl		j(rbp),esi
	xorl		eax,eax
	leaq		hex_values_header(rip),rdi
	call		printf@PLT
	popa64

	get_a		r10d
	movl		r10d,a(rdi)

	get_b		r10d,r8,r8d
	movl		r10d,b(rdi)

	get_c		r10d
	movl		r10d,c(rdi)

	get_d		r10d,r8,r8d
	movl		r10d,d(rdi)

	get_e		r10d
	movl		r10d,e(rdi)

	get_f		r10d,r8,r8d
	movl		r10d,f(rdi)
	get_g		r10d

	movl		r10d,g(rdi)

	get_h		r10d,r8,r8d
	movl		r10d,h(rdi)

	/* printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", a, b, c, d, e, f, g, h); */

	pusha64

	movl		e(rdi),r9d

	movl		d(rdi),r8d

	movl		c(rdi),ecx

	movl		b(rdi),edx

	/* arg a is deferred below */

	/* The padding is to align to at or next 16 bytes 8 * 3 = 24
	 * from args h, g, and f requiring 32 - 24 = 8 bytes of
	 * padding. 						      */
	subq		$8,rsp

	movl		h(rdi),esi
	pushq		rsi

	movl		g(rdi),esi
	pushq		rsi

	movl		f(rdi),esi
	pushq		rsi

	movl		a(rdi),esi

	/* The arg calling order.  The stack must be 16 byte aligned
	 * first.
	 *
	 * r9   e
	 * r8   d
	 * rcx  c
	 * rdx  b
	 * rsi  a
	 * push esi h
	 * push esi g
	 * push esi f
	 * rdi  hex_values_report(rip)
	 *
	 */

	movl		$0,eax
	leaq		hex_values_report(%rip),rdi
	call		printf@PLT
	addq		$32,rsp		// remove the 3 pushes & padding

	popa64
#endif
.endm

.macro dprint_show_j
#ifdef DEBUG_LEVEL_2
	pusha64
	movq		rax,rdx
	xorl		eax,eax
	leaq		print_j(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_show_h
#ifdef DEBUG_LEVEL_3
	pusha64
	leaq		str_h(rip),rsi
	movl		r8d,edx
	xorl		eax,eax
	leaq		print_hex8xl(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_show_sig1
#ifdef DEBUG_LEVEL_3
	pusha64
	leaq		str_sig1(rip),rsi
	movl		r11d,edx
	xorl		eax,eax
	leaq		print_hex8xl(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_show_ch
#ifdef DEBUG_LEVEL_3
	pusha64
	leaq		str_ch(rip),rsi
	movl		r9d,edx
	xorl		eax,eax
	leaq		print_hex8xl(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_show_k
#ifdef DEBUG_LEVEL_3
	pusha64
	leaq		str_k(rip),rsi
	movl		edx,edx
	xorl		eax,eax
	leaq		print_hex8xl(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_show_w
#ifdef DEBUG_LEVEL_3
	pusha64
	leaq		str_w32(rip),rsi
	movl		ebx,edx
	xorl		eax,eax
	leaq		print_hex8xl(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_show_t1
#ifdef DEBUG_LEVEL_3
	pusha64
	leaq		str_t1(rip),rsi
	movl		ecx,edx
	xorl		eax,eax
	leaq		print_hex8xl(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_show_sig0
#ifdef DEBUG_LEVEL_3
	pusha64
	leaq		str_sig0(rip),rsi
	movl		r11d,edx
	xorl		eax,eax
	leaq		print_hex8xl(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_show_maj
#ifdef DEBUG_LEVEL_3
	pusha64
	leaq		str_maj(rip),rsi
	movl		r15d,edx
	xorl		eax,eax
	leaq		print_hex8xl(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_show_t2
#ifdef DEBUG_LEVEL_3
	pusha64
	leaq		str_t2(rip),rsi
	movl		ebx,edx
	xorl		eax,eax
	leaq		print_hex8xl(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro yx_shlq_replace mm gpr
	movq		\mm,\gpr
	shlq		$32,\gpr
	movq		\gpr,\mm
.endm

.macro h_eq_g mm gpr
	yx_shlq_replace \mm,\gpr
.endm

.macro f_eq_e mm gpr
	yx_shlq_replace \mm,\gpr
.endm

.macro d_eq_c mm gpr
	yx_shlq_replace \mm,\gpr
.endm

.macro b_eq_a mm gpr
	yx_shlq_replace \mm,\gpr
.endm

.macro do_compression j k
	/* Compression function
	 * for (int j=0; j<64; j++):
	 *	u32 Ch, Maj, SIG0, SIG1, T1, T2;
	 *	Ch = (e & f) ^ ((~e) & g);
	 *	Maj = (a & b) ^ (a & c) ^ (b & c);
	 *	SIG0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
	 *	SIG1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
	 *	T1 = h + SIG1 + Ch + K[j] + W32[j];
	 *	T2 = SIG0 + Maj;
	 *
	 *	h = g;
	 *	g = f;
	 *	f = e;
	 *	e = d + T1;
	 *	d = c;
	 *	c = b;
	 *	b = a;
	 *	a = T1 + T2;					      */

	/* t1 = h */
	get_h		r8d,r8,r8d
	movl		r8d,ecx

	dprint_show_h

	/* SIG1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25) */
	get_e		r14d
	movl		r14d,r10d
	movl		r14d,r11d
	rorl		$6,r14d
	rorl		$11,r10d
	rorl		$25,r11d
	xorl		r14d,r10d
	xorl		r10d,r11d
	addl		r11d,ecx /* t1 += SIG1 */

	dprint_show_sig1

	/* Ch = (e & f) ^ ((~e) & g) */
	get_e		r14d
	get_g		r9d
	get_f		r15d,r8,r8d
	andl		r14d,r15d
#ifdef HAVE_BMI
	andnl		r9d,r14d,r9d
#else
	notl		r14d
	andl		r14d,r9d
#endif
	xorl		r15d,r9d
	addl		r9d,ecx  /* t1 += Ch */

	dprint_show_ch

	/* t1 += K[j] */
	addl		$\k,ecx

	dprint_show_k

	/* t1 += W32[j] */
	movl		$\j,r11d
#ifdef HAVE_SSE4_1
	get_w           ebx,r11d,rax,eax,rdx,edx
#elif defined(HAVE_SSE2)
	get_w           ebx,r11d,rax,eax,rdx,edx,r10,r10d
#endif

	dprint_show_w

	addl		ebx,ecx

	dprint_show_t1

	/* SIG0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22) */
	get_a		r14d
	movl		r14d,r10d
	movl		r14d,r11d
	rorl		$2,r14d
	rorl		$13,r10d
	rorl		$22,r11d
	xorl		r14d,r10d
	xorl		r10d,r11d
	movl		r11d,ebx /* t2 = SIG0 */

	dprint_show_sig0

	/* Maj = (a & b) ^ (a & c) ^ (b & c) */
	get_a		r10d
	get_b		r11d,r8,r8d
	movl		r11d,r14d
	get_c		r12d
	movl		r12d,r15d
	andl		r10d,r11d /* a & b */
	andl		r10d,r12d /* a & c */
	andl		r14d,r15d /* b & c */
	xorl		r11d,r12d
	xorl		r12d,r15d
	addl		r15d,ebx /* t2 += Maj */

	dprint_show_maj
	dprint_show_t2

	dprint_show_A_state

	/* t1 uses ecx, t2 uses ebx */

	/* h = g;
	 * g = f;
	 * f = e;
	 * e = d + T1;
	 * d = c;
	 * c = b;
	 * b = a;
	 * a = T1 + T2; */
	h_eq_g		mm3,r10

	get_f		r9d,r8,r8d
	set_g		r9d,r8,r8d,r10,r10d

	f_eq_e		mm2,r10

	get_d		r9d,r8,r8d
	movl		r9d,eax
	addl		ecx,eax
	set_e		eax,r8,r8d,r10,r10d

	d_eq_c		mm1,r10

	get_b		r9d,r8,r8d
	set_c		r9d,r8,r8d,r10,r10d

	b_eq_a		mm0,r10

	addl		ebx,ecx
	set_a		ecx,r8,r8d,r10,r10d
.endm

.macro print_m mi teax trbx tecx tedx tesi trdi tr8d tgpr0l
	pusha64
	movq		$0,\trbx
	movl		\mi(rdi,\trbx,4),\tgpr0l
	movl		\tgpr0l,\tr8d

	movq		$1,\trbx
	movl		\mi(rdi,\trbx,4),\tgpr0l
	movl		\tgpr0l,\tecx

	movq		$2,\trbx
	movl		\mi(rdi,\trbx,4),\tgpr0l
	movl		\tgpr0l,\tedx

	movq		$3,\trbx
	movl		\mi(rdi,\trbx,4),\tgpr0l
	movl		\tgpr0l,\tesi

	xorl		\teax,\teax
	leaq		mi_report(rip),\trdi
	call		printf@PLT
	popa64
.endm

/* Processes a message block. */
.macro _tsha256a_complete_message_block

	/* Expanding message blocks
	 * for (j = 16; j < 64; j++):
	 *	u32 sig0, sig1;
	 *	sig0 = (ROTR(W32[j-15],7) ^ ROTR(W32[j-15],18) ^ (W32[j-15] >> 3));
	 *	sig1 = ROTR(W32[j-2],17) ^ ROTR(W32[j-2], 19) ^ (W32[j-2] >> 10);
	 *	W32[j] = W32[j-16] + sig0 + W32[j-7] + sig1;
	 */
/* Unrolled do_compression generated by gen_asm_unroll_message_expansion.py */
	expand_message_blocks 16
	expand_message_blocks 17
	expand_message_blocks 18
	expand_message_blocks 19
	expand_message_blocks 20
	expand_message_blocks 21
	expand_message_blocks 22
	expand_message_blocks 23
	expand_message_blocks 24
	expand_message_blocks 25
	expand_message_blocks 26
	expand_message_blocks 27
	expand_message_blocks 28
	expand_message_blocks 29
	expand_message_blocks 30
	expand_message_blocks 31
	expand_message_blocks 32
	expand_message_blocks 33
	expand_message_blocks 34
	expand_message_blocks 35
	expand_message_blocks 36
	expand_message_blocks 37
	expand_message_blocks 38
	expand_message_blocks 39
	expand_message_blocks 40
	expand_message_blocks 41
	expand_message_blocks 42
	expand_message_blocks 43
	expand_message_blocks 44
	expand_message_blocks 45
	expand_message_blocks 46
	expand_message_blocks 47
	expand_message_blocks 48
	expand_message_blocks 49
	expand_message_blocks 50
	expand_message_blocks 51
	expand_message_blocks 52
	expand_message_blocks 53
	expand_message_blocks 54
	expand_message_blocks 55
	expand_message_blocks 56
	expand_message_blocks 57
	expand_message_blocks 58
	expand_message_blocks 59
	expand_message_blocks 60
	expand_message_blocks 61
	expand_message_blocks 62
	expand_message_blocks 63

	dprint_show_W_array

	/* Init state
	 * a = H0; b = H1; c = H2; d = H3;
	 * e = H4; f = H5; g = H6; h = H7;							  */
	init_abcdefgh

#ifdef TRASH
	movl		H0(rdi),eax
	set_a		eax,r10,r10d,r11,r11d

	movl		H1(rdi),eax
	set_b		eax,r10,r10d,r11,r11d

	movl		H2(rdi),eax
	set_c		eax,r10,r10d,r11,r11d

	movl		H3(rdi),eax
	set_d		eax,r10,r10d,r11,r11d

	movl		H4(rdi),eax
	set_e		eax,r10,r10d,r11,r11d

	movl		H5(rdi),eax
	set_f		eax,r10,r10d,r11,r11d

	movl		H6(rdi),eax
	set_g		eax,r10,r10d,r11,r11d

	movl		H7(rdi),eax
	set_h		eax,r10,r10d,r11,r11d
#endif

/* Unrolled do_compression generated by gen_asm_unroll_do_compression.py */
	do_compression 0,0x428a2f98
	do_compression 1,0x71374491
	do_compression 2,0xb5c0fbcf
	do_compression 3,0xe9b5dba5
	do_compression 4,0x3956c25b
	do_compression 5,0x59f111f1
	do_compression 6,0x923f82a4
	do_compression 7,0xab1c5ed5
	do_compression 8,0xd807aa98
	do_compression 9,0x12835b01
	do_compression 10,0x243185be
	do_compression 11,0x550c7dc3
	do_compression 12,0x72be5d74
	do_compression 13,0x80deb1fe
	do_compression 14,0x9bdc06a7
	do_compression 15,0xc19bf174
	do_compression 16,0xe49b69c1
	do_compression 17,0xefbe4786
	do_compression 18,0x0fc19dc6
	do_compression 19,0x240ca1cc
	do_compression 20,0x2de92c6f
	do_compression 21,0x4a7484aa
	do_compression 22,0x5cb0a9dc
	do_compression 23,0x76f988da
	do_compression 24,0x983e5152
	do_compression 25,0xa831c66d
	do_compression 26,0xb00327c8
	do_compression 27,0xbf597fc7
	do_compression 28,0xc6e00bf3
	do_compression 29,0xd5a79147
	do_compression 30,0x06ca6351
	do_compression 31,0x14292967
	do_compression 32,0x27b70a85
	do_compression 33,0x2e1b2138
	do_compression 34,0x4d2c6dfc
	do_compression 35,0x53380d13
	do_compression 36,0x650a7354
	do_compression 37,0x766a0abb
	do_compression 38,0x81c2c92e
	do_compression 39,0x92722c85
	do_compression 40,0xa2bfe8a1
	do_compression 41,0xa81a664b
	do_compression 42,0xc24b8b70
	do_compression 43,0xc76c51a3
	do_compression 44,0xd192e819
	do_compression 45,0xd6990624
	do_compression 46,0xf40e3585
	do_compression 47,0x106aa070
	do_compression 48,0x19a4c116
	do_compression 49,0x1e376c08
	do_compression 50,0x2748774c
	do_compression 51,0x34b0bcb5
	do_compression 52,0x391c0cb3
	do_compression 53,0x4ed8aa4a
	do_compression 54,0x5b9cca4f
	do_compression 55,0x682e6ff3
	do_compression 56,0x748f82ee
	do_compression 57,0x78a5636f
	do_compression 58,0x84c87814
	do_compression 59,0x8cc70208
	do_compression 60,0x90befffa
	do_compression 61,0xa4506ceb
	do_compression 62,0xbef9a3f7
	do_compression 63,0xc67178f2

	/* Update intermediate hash values
	 * H0 = a + H0; H1 = b + H1; H2 = c + H2; H3 = d + H3;
	 * H4 = e + H4; H5 = f + H5; H6 = g + H6; H7 = h + H7;
	 */

	get_a 		eax
	movl		H0(rdi),ebx
	addl		ebx,eax
	movl		eax,H0(rdi)

	get_b 		eax,r10,r10d
	movl		H1(rdi),ebx
	addl		ebx,eax
	movl		eax,H1(rdi)

	get_c 		eax
	movl		H2(rdi),ebx
	addl		ebx,eax
	movl		eax,H2(rdi)

	get_d 		eax,r10,r10d
	movl		H3(rdi),ebx
	addl		ebx,eax
	movl		eax,H3(rdi)

	get_e 		eax
	movl		H4(rdi),ebx
	addl		ebx,eax
	movl		eax,H4(rdi)

	get_f 		eax,r10,r10d
	movl		H5(rdi),ebx
	addl		ebx,eax
	movl		eax,H5(rdi)

	get_g 		eax
	movl		H6(rdi),ebx
	addl		ebx,eax
	movl		eax,H6(rdi)

	get_h 		eax,r10,r10d
	movl		H7(rdi),ebx
	addl		ebx,eax
	movl		eax,H7(rdi)

	/* Process next message block. */
	movl		$0,i_message(rdi)
	clear_W
.endm

.macro dprint_show_W_array
#ifdef DEBUG
	/* Print sse registers. */
	movdqa          xmm0,m0(rdi)
	movdqa          xmm1,m1(rdi)
	movdqa          xmm2,m2(rdi)
	movdqa          xmm3,m3(rdi)
	movdqa          xmm4,m4(rdi)
	movdqa          xmm5,m5(rdi)
	movdqa          xmm6,m6(rdi)
	movdqa          xmm7,m7(rdi)
	movdqa          xmm8,m8(rdi)
	movdqa          xmm9,m9(rdi)
	movdqa          xmm10,m10(rdi)
	movdqa          xmm11,m11(rdi)
	movdqa          xmm12,m12(rdi)
	movdqa          xmm13,m13(rdi)
	movdqa          xmm14,m14(rdi)
#ifdef HAVE_SSE4_1
	movdqa          xmm15,m15(rdi)
#elif defined(HAVE_SSE2)
	movq		mm4,m15l(rdi)
	movq		mm5,m15h(rdi)
#endif
	print_m		m0,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m1,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m2,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m3,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m4,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m5,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m6,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m7,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m8,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m9,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m10,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m11,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m12,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m13,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m14,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
	print_m		m15,eax,rbx,ecx,edx,esi,rdi,r8d,r10d
#endif
.endm

.macro dprint_show_finish
#ifdef DEBUG_LEVEL_2
	pusha64
	movl		finish(rbp),esi
	xorl		eax,eax
	leaq		print_hex8x(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_entered_event0
#ifdef DEBUG_LEVEL_2
	pusha64
	xorl		eax,eax
	leaq		str_event0(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_entered_event1
#ifdef DEBUG_LEVEL_2
	pusha64
	xorl		eax,eax
	leaq		str_event1(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_entered_event2
#ifdef DEBUG_LEVEL_2
	pusha64
	xorl		eax,eax
	leaq		str_event2(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_entered_event3
#ifdef DEBUG_LEVEL_2
	pusha64
	xorl		eax,eax
	leaq		str_event3(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_entered_event4
#ifdef DEBUG_LEVEL_2
	pusha64
	xorl		eax,eax
	leaq		str_event4(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_entered_event5
#ifdef DEBUG_LEVEL_2
	pusha64
	xorl		eax,eax
	leaq		str_event5(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm

.macro dprint_show_i_message
#ifdef DEBUG_LEVEL_2
	pusha64
	movl		i_message(rdi),esi
	xorl		eax,eax
	leaq		print_i_message(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm



/* FSM updater
 *
 * input:
 * 	struct tsha256*:rdi - state
 *	int finish:rsi - 0 for continue, 1 to finish
 *
 * output:
 *	return:rax - <0 for error, 0 for success
 *
 */
/* int tsha256a_update(struct tsha256 *state, u32 finish) */
// X86_64 calling convention: RDI, RSI, RDX, RCX, R8, R9, ([XYZ]MM0–7.), Stack R-TO-L
.type tsha256a_update, @function
tsha256a_update:
	pushq		rbp
	movq		rsp,rbp

	subq		$4,rsp /* padding to align to 16 bytes */
	subq		$8,rsp /* struct tsha256* */
	subq		$4,rsp /* u32 finish */
	subq		$4,rsp /* u32 ret */
	subq		$4,rsp /* u32 i */
	subq		$4,rsp /* u32 j */
	subq		$4,rsp /* u32 i_len */

	pushq		r15
	pushq		r14
	pushq		r13
	pushq		r12
	pushq		r11
	pushq		r10
	pushq		r9
	pushq		r8
	pushq		rdx
	pushq		rcx
	pushq		rbx

	movq		rdi,state(rbp)
	movl		esi,finish(rbp)
	movl		$0,ret(rbp)

	/* if (finish == 1 || state->i_message >= 64)
	 *	;
	 * else
	 *	return 0;						      */
	movl		finish(rbp),eax
	cmpl		$1,eax
	je		DO_FSM_UPDATE_Y
		/* || */
		movl		i_message(rdi),eax
		cmpl		$64,eax
		jge		DO_FSM_UPDATE_Y
		jmp		DO_FSM_UPDATE_N

DO_FSM_UPDATE_N:
			movl		$0,ret(rbp)
			jmp		OUT

DO_FSM_UPDATE_Y:
//			nop
//			jmp		E0


	/* if (state->event == TSHA256A_FSM_INPUT)
	 *	if (finish == 1):
	 *	 	state->event = TSHA256A_FSM_INPUT_UPDATE;	      */

E0:	movl		event(rdi),ecx
	cmpl		$TSHA256A_FSM_INPUT,ecx
	je		E0T
	jmp		E1

E0T:		dprint_entered_event0

		movl		finish(rbp),ecx
		cmpl		$1,ecx
		je		E0CT
		jmp		OUT

E0CT:			movl		$TSHA256A_FSM_INPUT_UPDATE,event(rdi)
			jmp		OUT

	/*
	 * else if (state->event == TSHA256A_FSM_INPUT_UPDATE):
	 *	if (finish == 1):
	 *		state->event = TSHA256A_FSM_APPEND_1BIT;
	 *	else:
	 *		_tsha256a_complete_message_block(state);
	 *		state->event = TSHA256A_FSM_INPUT;
	 */

E1:	movl		event(rdi),ecx
	cmp		$TSHA256A_FSM_INPUT_UPDATE,ecx
	je		E1T
	jmp		E2
E1T:
		dprint_entered_event1

		movl		finish(rbp),ecx
		cmpl		$1,ecx
		je		E1CT
		jmp		E1CF

E1CT:			movl		$TSHA256A_FSM_APPEND_1BIT,event(rdi)
			jmp		OUT
		/* else: */
E1CF:			_tsha256a_complete_message_block
			movl		$TSHA256A_FSM_INPUT,event(rdi)
			jmp		OUT


	/* Add "1" bit
	 * else if (state->event == TSHA256A_FSM_APPEND_1BIT):
	 *	if (state->i_message < 64):
	 *		W8[seq[state->i_message]] = (u8)0x80;
	 *		state->i_message++;
	 *		state->event = TSHA256A_FSM_APPEND_0_PADDING;
	 *	else:
	 *		_tsha256a_complete_message_block(state);
	 *		W8[seq[state->i_message]] = (u8)0x80;
	 *		state->i_message++;
	 *		state->event = TSHA256A_FSM_APPEND_0_PADDING;
	 */
E2:	movl		event(rdi),ecx
	cmpl		$TSHA256A_FSM_APPEND_1BIT,ecx
	je		E2T
	jmp		E3
E2T:
		dprint_entered_event2

		movl		i_message(rdi),ebx
		cmpl		$64,ebx
		jl		E2CT
		jmp		E2CF
E2CF:			_tsha256a_complete_message_block
		/* else: */
E2CT:			/* t1 = seq[state->i_message] */
			movl		i_message(rdi),ecx
			movl		seq(,rcx,4),r11d

			movb		$0x80,r10b

			/* W8[seq[state->i_message]] = (u8)0x80; */
#ifdef HAVE_SSE4_1
			insert_W_byte_sse4_1 r10d,r11d,rax,eax,rdx,edx
#elif defined(HAVE_SSE2)
			insert_W_byte_sse2 r10d,r11d,rax,eax,rdx,edx,r13,r13d,r14
#endif

			/* state->i_message++ */
			movl            i_message(rdi),ecx
			incl		ecx
			movl		ecx,i_message(rdi)

			/* state->event = TSHA256A_FSM_APPEND_0_PADDING */
			movl            event(rdi),ecx
			movl		$TSHA256A_FSM_APPEND_0_PADDING,event(rdi)
			jmp		OUT

	/*
	 * else if (state->event == TSHA256A_FSM_APPEND_0_PADDING):
	 *	if (state->i_message < 56):
	 *		state->event = TSHA256A_FSM_APPEND_LENGTH;
	 *	else
	 *		_tsha256a_complete_message_block(state);
	 *		state->event = TSHA256A_FSM_APPEND_0_PADDING;
	 */
E3:	movl		event(rdi),ecx
	cmpl		$TSHA256A_FSM_APPEND_0_PADDING,ecx
	je		E3T
	jmp		E4
E3T:
		dprint_entered_event3

		movl		i_message(rdi),eax
		cmpl		$56,eax
		jl		E3CT
		jmp		E3CF
E3CT:			movl		$TSHA256A_FSM_APPEND_LENGTH,event(rdi)
			jmp		OUT
		/* else: */
E3CF:			_tsha256a_complete_message_block
			movl		$TSHA256A_FSM_APPEND_0_PADDING,event(rdi)
			jmp		OUT

	/* Append message length
	 * else if (state->event == TSHA256A_FSM_APPEND_LENGTH)
	 *	if (state->i_message < 56):
	 *		u8 len8[L_SIZE];
	 *		u64 *len64 = (u64*)len8;
	 *		*len64 = state->msglen*8;
	 *		for(i_len = 0, i = 64 - L_SIZE ; i < 64 ; i++, i_len++):
	 *			W8[seq2[i_len]] = len8[i_len];
	 *		_tsha256a_complete_message_block(state);
	 *		state->event = TSHA256A_FSM_COMPLETE;
	 *	else:
	 *		state->event = TSHA256A_FSM_ERROR;
	 * else
	 *	state->event = TSHA256A_FSM_ERROR;
	 */
E4:	movl		event(rdi),eax
	cmpl		$TSHA256A_FSM_APPEND_LENGTH,eax
	je		E4T /* && */
	jmp		E4CF
E4T:
		dprint_entered_event4

		movl		i_message(rdi),eax
		cmpl		$56,eax
		jl		E4CT
		jmp		E4CF

E4CT:			set_length
			_tsha256a_complete_message_block
			movl		$TSHA256A_FSM_COMPLETE,event(rdi)


			jmp		OUT
		/* else: */
E4CF:			movl		$TSHA256A_FSM_ERROR,event(rdi)
//			jmp		OUT

OUT:
	movl		ret(rbp),eax

	popq		rbx
	popq		rcx
	popq		rdx
	popq		r8
	popq		r9
	popq		r10
	popq		r11
	popq		r12
	popq		r13
	popq		r14
	popq		r15

	addq		$32,rsp	/* pop out temporary variables + padding */

	movq		rbp,rsp
	popq		rbp
	ret


.macro dprint_show_enter_reset
#ifdef DEBUG_LEVEL_2
	pusha64
	xorl		eax,eax
	leaq		str_clearing_state(rip),rdi
	call		printf@PLT
	popa64
#endif
.endm


/* Reset state object and wipe sensitive data. */
/* int tsha256a_reset(struct tsha256 *state) */
.type tsha256a_reset, @function
tsha256a_reset:
	dprint_show_enter_reset

	pusha64
	xorl		eax,eax
	leaq		print_it_works(rip),rdi
	call		printf@PLT
	popa64


	/* Check for null pointer for state object. */
	cmpq		$0,rdi
	jz		RESET_NULLPTR_T
	jmp		RESET_NULLPTR_F

RESET_NULLPTR_T:
		movl		$-EINVAL,eax /* eax = -EINVAL */
		jmp		ROUT

RESET_NULLPTR_F:
		clear_A
		clear_W
		clear_state
		//clear_gpr
		movq		$0,i_message(rdi)

		init_H

		movl		$0,eax
//		jmp		ROUT
ROUT:
	ret

/* Wipe the state object and sensitive data. */
/* void tsha256a_close(struct tsha256 *state) */
.type tsha256a_close, @function
tsha256a_close:
	clear_A
	clear_W
	clear_state
	//clear_gpr
	ret

/* Read a single character. */
/* int tsha256a_getch(struct tsha256 *state, u8 c) */
.type tsha256a_getch, @function
tsha256a_getch:
	pushq		rbp
	movq		rsp,rbp

.set state,-20
.set ret,-24

	subq		$12,rsp /* padding for 16 byte alignment */
	subq		$8,rsp /* struct tsha256* */
	subq		$4,rsp /* u32 ret */

	pushq		rbx
	pushq		rcx
	pushq		rdx
	pushq		r8
	pushq		r9
	pushq		r10
	pushq		r11
	pushq		r12
	pushq		r13
	pushq		r14
	pushq		r15

	movq		rdi,state(rbp)
	movl            $0,ret(rbp)

	/* if (state == NULL):
	 *	ret = -EINVAL;
	 *	return ret;						      */
	cmpq		$0,rdi
	je		190f
	jmp		191f

190:	movl		$-EINVAL,ret(rbp)
	jmp		196f

	/* if (state->event != TSHA256A_FSM_INPUT):
	 *	return ret;						      */

191:	movl		event(rdi),eax
	cmpl		$TSHA256A_FSM_INPUT,eax
	jne		192f
	jmp		193f

192:	jmp		196f

	/* if (state->i_message < 64)
	 *	W8[seq[state->i_message]] = c;
	 *	state->i_message++;
	 *	state->msglen++;
	 *	ret = 1;						      */

	/* state->i_message < 64 */
193:	movl		i_message(rdi),ecx
	cmpl		$64,ecx
	jl		194f
	jmp		195f


194:		/* t0 = c:rsi */
		movq		rsi,rax
		movb		al,r10b

		/* t1 = seq[state->i_message] */
		movl		i_message(rdi),ecx
		movl		seq(,rcx,4),r11d

		/* W8[seq[state->i_message]] = c; */
#ifdef HAVE_SSE4_1
		insert_W_byte_sse4_1 r10d,r11d,rax,eax,rdx,edx
#elif defined(HAVE_SSE2)
		insert_W_byte_sse2 r10d,r11d,rax,eax,rdx,edx,r13,r13d,r14
#endif

		/* state->i_message++ */
		movl		i_message(rdi),ecx
		incl		ecx
		movl		ecx,i_message(rdi)

		/* state->msglen++ */
		movl		msglen(rdi),ecx
		incl		ecx
		movl		ecx,msglen(rdi)

		movl            $1,ret(rbp)

		jmp		196f

	/* else: */
		/* state->event = TSHA256A_FSM_INPUT_UPDATE; */
195:		movl		$TSHA256A_FSM_INPUT_UPDATE,event(rdi)

196:


	movl		ret(rbp),eax

	popq		r15
	popq		r14
	popq		r13
	popq		r12
	popq		r11
	popq		r10
	popq		r9
	popq		r8
	popq		rdx
	popq		rcx
	popq		rbx

	addq		$24,rsp /* pop out temporary variables and padding */

	movq		rbp,rsp
	popq		rbp
	ret

/* u32* tsha256a_get_hashcode(struct tsha256 *state) */
.type tsha256a_get_hashcode, @function
tsha256a_get_hashcode:
	leaq		digest(rdi),rax
	ret
