/*
 * tsha512/256b - An assembly based SHA-512/256 implementation in x86_64 assembly
 *                      using avx2, sse2 and mmx registers.
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
 * For this to be effective, preemption should be disabled and the sse/mmx register
 * files should not be copied to RAM.  In other words, this implementation should
 * be in kernel space with active CPU scheduler interaction, setting preemption,
 * flags in order for it to work properly.
 *
 * This implementation is a work in progress and inspired by TRESOR.
 * It's designed to keep a sensitive message (aka the key) away from touching
 * memory for DMA attack.  Primarly will used for fscrypt with TRESOR.  The b
 * suffix indicates the alternative to the implementation used in the TRESOR
 * patches.
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
 *	Queue-shuffle based design for this implementation SHA-512/256
 *	do_expansion and do_expression are combined
 *
 *      Register assignment places ease of coding over efficiency while
 *      gaining some benefits of parallelism.
 *
 *      Queue register flow:
 *      w16 -> w15 -> w14 -> w13 -> w12 -> w11 -> w10 -> w9 -> w8 -> w7 ...
 *      ... -> w6 -> w5 -> w4 -> w3 -> w2 -> w1 -> w0
 *
 *	w0 can be skipped
 *
 *	w indices / w array (new design):
 *       w1  w0			xmm0	W64[j-15]	W64[j-16]
 *       w3  w2			xmm1
 *       w5  w4			xmm2
 *       w7  w6			xmm3
 *       w9  w8			xmm4	W64[j-7]
 *       w11 w10		xmm5
 *       w13 w12		xmm6
 *       w15 w14		xmm7			W64[j-2]
 *       w17 w16		xmm8			W64[j]
 *       t   t			xmm9
 *       t   t			xmm10
 *       t   t			xmm11
 *       t   t			xmm12
 *       t   t			xmm13
 *       t   t			xmm14
 *
 *	Length:
 *       Lh  Ll                 xmm15
 *
 *	A array:
 *      a			mm0
 *	b			mm1
 *	c			mm2
 *	d			mm3
 *	e			mm4
 *	f			mm5
 *	g			mm6
 *      h			mm7
 *
 *	Message bit *L*ength:
 *	xmm15
 *
 *	Temporary variables:
 *       t   t			xmm9
 *       t   t			xmm10
 *       t   t			xmm11
 *       t   t			xmm12
 *       t   t			xmm13
 *       t   t			xmm14
 *
 */

.file "tsha512t256a.S"

#if defined(HAVE_SSE4_1)
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
	.quad 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
	.quad 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118
	.quad 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
	.quad 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694
	.quad 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
	.quad 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
	.quad 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4
	.quad 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70
	.quad 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
	.quad 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b
	.quad 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30
	.quad 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8
	.quad 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
	.quad 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
	.quad 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec
	.quad 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b
	.quad 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
	.quad 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b
	.quad 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
	.quad 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817


H0_1:	.align 16
	.long	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
H0_2:	.align 16
	.long	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

/* Indices and sequence for inserting the message. */
seq:
	.long  7,  6,  5,  4,  3,  2,  1,  0
	.long 15, 14, 13, 12, 11, 10,  9,  8
	.long 23, 22, 21, 20, 19, 18, 17, 16
	.long 31, 30, 29, 28, 27, 26, 25, 24
	.long 39, 38, 37, 36, 35, 34, 33, 32
	.long 47, 46, 45, 44, 43, 42, 41, 40
	.long 55, 54, 53, 52, 51, 50, 49, 48
	.long 63, 62, 61, 60, 59, 58, 57, 56
	.long 71, 70, 69, 68, 67, 66, 65, 64
	.long 79, 78, 77, 76, 75, 74, 73, 72
	.long 87, 86, 85, 84, 83, 82, 81, 80
	.long 95, 94, 93, 92, 91, 90, 89, 88
	.long 103, 102, 101, 100, 99, 98, 97, 96
	.long 111, 110, 109, 108, 107, 106, 105, 104
	.long 119, 118, 117, 116, 115, 114, 113, 112
	.long 127, 126, 125, 124, 123, 122, 121, 120

/* Indices and sequence for inserting the Big Endian (BE) length (L). */
/* End of sub-array index positon: 56 57 58 59 60 61 62 63 */
/* char[0] MSB when printing le u64 */
/* char[7] LSB when printing le u64 */

seq2:
	.long 120, 121, 122, 123, 124, 125, 126, 127   /* 127 is msb, 120 is mid */
	.long 112, 113, 114, 115, 116, 117, 118, 119   /* 119 is mid. 112 is msb */

/*	    b         a		*/
mask0:	.align 16
.octa	0x0000000000000000ffffffffffffffff
mask1:	.align 16
.octa	0xffffffffffffffff0000000000000000

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

str_event0: .asciz "event0:  TSHA512T256_FSM_INPUT\n"
str_event1: .asciz "event1:  TSHA512T256_FSM_INPUT_UPDATE\n"
str_event2: .asciz "event2:  TSHA512T256_FSM_APPEND_1BIT\n"
str_event3: .asciz "event2:  TSHA512T256_FSM_APPEND_0_PADDING\n"
str_event4: .asciz "event2:  TSHA512T256_FSM_APPEND_LENGTH\n"
str_event5: .asciz "event2:  TSHA512T256_FSM_COMPLETE\n"
str_event255: .asciz "event255:  TSHA512T256_FSM_ERROR\n"

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
str_w64: .asciz "w64"
#endif

.set TSHA512T256_FSM_INPUT,0
.set TSHA512T256_FSM_INPUT_UPDATE,1
.set TSHA512T256_FSM_APPEND_1BIT,2
.set TSHA512T256_FSM_APPEND_0_PADDING,3
.set TSHA512T256_FSM_APPEND_LENGTH,4
.set TSHA512T256_FSM_COMPLETE,5
.set TSHA512T256_FSM_ERROR,255

.set EINVAL,1

.text
.global tsha512t256a_update
.global tsha512t256a_getch
.global tsha512t256a_reset
.global tsha512t256a_close
.global tsha512t256a_get_hashcode

.set local_variables_size, 52 /* in bytes */

/*
struct tsha512t256 {
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

.set MESSAGE_SIZE_BYTES,128

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

/* relative to struct *tsha512t256a */
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

.macro get_a w
	movq		mm0,\w
.endm

.macro set_a w
	movq		\w,mm0
.endm

.macro get_b w
	movq		mm1,\w
.endm

.macro set_b w
	movq		\w,mm1
.endm

.macro get_c w
	movq		mm2,\w
.endm

.macro set_c w
	movq		\w,mm2
.endm

.macro get_d w
	movq		mm3,\w
.endm

.macro set_d w
	movq		\w,mm3
.endm

.macro get_e w
	movq		mm4,\w
.endm

.macro set_e w
	movq		\w,mm4
.endm

.macro get_f w
	movq		mm5,\w
.endm

.macro set_f w
	movq		\w,mm5
.endm

.macro get_g w
	movq		mm6,\w
.endm

.macro set_g w
	movq		\w,mm6
.endm

.macro get_h w
	movq		mm7,\w
.endm

.macro set_h w
	movq		\w,mm7
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
	pextrq          $\ci,\xmm,\w
.endm

.macro _set_w w ci xmm
	pinsrq          $\ci,\w,\xmm
.endm
#elif defined(HAVE_SSE2)
/* ci must be 0,8 */
.macro _get_w w ci xmm txmm
	.if \ci == 0
		movq            \xmm,\w
	.else
		movdqa          \xmm,\txmm
		psrldq          $\ci,\txmm
		movq            \txmm,\w
	.endif
.endm

/* ci must be 0,8 */
.macro _set_w w ci xmm txmm mask
	.if \ci == 0
		movq            \w,\txmm
		pand		\mask(rip),\xmm
		pxor		\txmm,\xmm
	.else
		movq            \w,\txmm
		pslldq          $\ci,\txmm
		pand		\mask(rip),\xmm
		pxor		\txmm,\xmm
	.endif
.endm

#endif // HAVE_SSE4_1

.macro next_w
	psrldq		$8,xmm0
	_get_w		\tgpr,0,xmm1,xmm14
	_set_w		\tgpr,8,xmm0,xmm14,mask1
	psrldq		$8,xmm1
	_get_w		\tgpr,0,xmm2,xmm14
	_set_w		\tgpr,8,xmm1,xmm14,mask1
	psrldq		$8,xmm2
	_get_w		\tgpr,0,xmm3,xmm14
	_set_w		\tgpr,8,xmm2,xmm14,mask1
	psrldq		$8,xmm3
	_get_w		\tgpr,0,xmm4,xmm14
	_set_w		\tgpr,8,xmm3,xmm14,mask1
	psrldq		$8,xmm4
	_get_w		\tgpr,0,xmm5,xmm14
	_set_w		\tgpr,8,xmm4,xmm14,mask1
	psrldq		$8,xmm5
	_get_w		\tgpr,0,xmm6,xmm14
	_set_w		\tgpr,8,xmm5,xmm14,mask1
	psrldq		$8,xmm6
	_get_w		\tgpr,0,xmm7,xmm14
	_set_w		\tgpr,8,xmm6,xmm14,mask1
	psrldq		$8,xmm7
	_get_w		\tgpr,0,xmm8,xmm14
	_set_w		\tgpr,8,xmm7,xmm14,mask1
.endm

// Combined message expansion and message compression
.macro msg_exp_comp k trax trbx trcx tr8 tr9 tr10 tr11 tr12 tr13 tr14 tr15
	/* Expanding message blocks
	 * for (j = 16; j < MESSAGE_SIZE_BYTES; j++): # Loop is unrolled to minimize loop overhead
	 *	u32 sig0:r12, sig1:rcx;
	 *	sig0 = ROTRQ(W64[j-15]:w1,7) ^ ROTRQ(W64[j-15]:w1,18)
	 *		^ (W64[j-15]:w1 >> 3);
	 *	sig1 = ROTRQ(W64[j-2]:w14,17) ^ ROTRQ(W64[j-2]:w14, 19)
	 *		^ (W64[j-2]:w14 >> 10);
	 *	W64[j]:w16 = W64[j-16]:w0 + sig0 + W64[j-7]:w9 + sig1;
	 */

	/***********************************************************/


	/* You cannot do simd independent rotations with different rotate
	 * values at the same time, yet it should be offered on the
	 * processor. */

	/* ROTRQ(W64[j-15]:w1, 1) ^ ROTRQ(W64[j-15]:w1, 8) ^ (W64[j-15]:w1  >>  7) */
	_get_w		\trbx,$8,xmm0,xmm14	// W64[j-15]:w1
	movq		\trbx,\trax
	movq		\trbx,\trcx
	rorq		$1,\trax
	rorq		$8,\trbx
	shlq		$7,\trcx
	xorq		\trax,\trbx
	xorq		\trbx,\trcx
	movq		\trcx,\tr12	/* sig0 === r12 */

	/* ROTRQ(W64[j-2]:w14, 19) ^ ROTRQ(W64[j-2]:w14, 61) ^   (W64[j-2]:w14 >> 6) */
	_get_w		\trbx,$0,xmm7,xmm14	// W64[j-2]:w14
	movq		\trbx,\trax
	movq		\trbx,\trcx
	rorq		$19,\trax
	rorq		$61,\trbx
	shlq		$6,\trcx
	xorq		\trax,\trbx
	xorq		\trbx,\trcx	/* sig1 === rcx */

	_get_w		\tr13,$0,xmm0,xmm14	// W64[j-16]:w0
	_get_w		\tr14,$8,xmm4,xmm14	// W64[j-7]:w9
	addq		\tr12,\tr13
	addq		\tr14,\tr13
	addq		\trcx,\tr13

	_set_w		\tr13,$0,xmm8,xmm14	// W64[j]:w16 = r13

	/* Compression function
	 * for (int j=0; j<MESSAGE_SIZE_BYTES; j++): # Loop is unrolled to minimize loop overhead
	 *	u32 Ch:r9, Maj:r15, SIG0:r11, SIG1:r11, T1:rcx, T2:rbx;
	 *	Ch = (e & f) ^ ((~e) & g);
	 *	Maj = (a & b) ^ (a & c) ^ (b & c);
	 *	SIG0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
	 *	SIG1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
	 *	T1 = h + SIG1 + Ch + K[j] + W64[j]:w16;
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

	/* T1 = h + SIG1 + Ch + k + W64[j]:w16 */

	get_h		\tr8
	movq		\tr8,\trcx		/* T1 = h */

	/* SIG1 = ROTRQ(e,14) ^ ROTRQ(e,18) ^ ROTRQ(e,41)  */
	get_e		\tr14
	movq		\tr14,\tr10
	movq		\tr14,\tr11
	rorq		$14,\tr14
	rorq		$18,\tr10
	rorq		$41,\tr11
	xorq		\tr14,\tr10
	xorq		\tr10,\tr11		/* SIG1 = r11 */
	addq		\tr11,\trcx		/* T1 = T1 + SIG1 */

	/* Ch = (e & f) ^ ((~e) & g) */
	get_e		\tr14
	get_g		\tr9
	get_f		\tr15
	andq		\tr14,\tr15		/* r15 = e & f */
#ifdef	HAVE_BMI
	andnq		\tr9,\tr14,\tr9
#else
	notq		\tr14
	andq		\tr14,\tr9		/* r9 = ~e & g */
#endif
	xorq		r15,\tr9		/* Ch = r9 */
	addq		\tr9,\trcx		/* T1 = T1 + Ch */

	movq		\k,\tr10
	addq		\tr10,\trcx		/* T1 = T1 + k */

	_get_w		\tebx,$0,xmm8,xmm14	// W64[j]:w16
	addq		\tebx,\trcx		/* T1 = T1 + W64[j]:w16 */

	/* SIG0 = ROTRQ(a,28) ^ ROTRQ(a,34) ^ ROTRQ(a,39) */
	get_a		\tr14
	movq		\tr14,\tr10
	movq		\tr14,\tr11
	rorq		$28,\tr14
	rorq		$32,\tr10
	rorq		$39,\tr11
	xorq		\tr14,\tr10
	xorq		\tr10,\tr11
	addq		\tr11,\trbx		/* T2 = SIG0 = rbx */

	/* Maj = (a & b) ^ (a & c) ^ (b & c)  */
	// gpr version is more efficient than simd 9 vs 14 instructions
	get_a		\tr10
	get_b		\tr11
	movq		\tr11,\tr14
	get_c		\tr12
	movq		\tr12,\tr15

	andq		\tr10,\tr11
	andq		\tr10,\tr12
	andq		\tr14,\tr15
	xorq		\tr11,\tr12
	movq		\tr12,\tr15		/* Maj = r15 */


	addq		\tr15,\trbx		/* T2 = T2 + Maj */


	/*
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
	*/

	get_g		\tr9
	set_h		\tr9

	get_f		\tr9
	set_g		\tr9

	get_e		\tr9
	set_f		\tr9

	set_d		\tr9
	movq		\tr9,\trax
	addq		\trcx,\trax
	set_e		\trax

	get_c		\tr9
	set_d		\tr9

	get_b		\tr9
	set_c		\tr9

	get_a		\tr9
	get_b		\tr9

	addq		\trbx,\trcx
	get_a		\trcx
.endm

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

.endm
#endif


/* Local variable positions on the stack.  See tsha512t256a_update for details. */
.set state,-8
.set finish,-12
.set ret,-16
.set i,-20
.set j,-24
.set i_len,-28

.macro set_length
/*	for(i_len = 0, i = MESSAGE_SIZE_BYTES - L_SIZE ; i < MESSAGE_SIZE_BYTES ; i++, i_len++):
 *		W8[seq2[i_len]] = len8[i_len];		      */

	movq		msglen(rdi),rax

	salq		$3,rax /* state->msglen*8 */
	movq		rax,mm6	/* len8:mm6 */

	/* i_len = 0 ; i_len is index of byte in mm6 */
	movl		$0,i_len(rbp)

	/* i = MESSAGE_SIZE_BYTES - L_SIZE */
	movl		$MESSAGE_SIZE_BYTES,ebx
	subl		$8,ebx /* L_SIZE */
	movl		ebx,i(rbp)

	/* i < MESSAGE_SIZE_BYTES */
200:	cmpl		$MESSAGE_SIZE_BYTES,ebx
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
	leaq		str_w64(rip),rsi
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
.macro _tsha512t256a_complete_message_block

	/* Expanding message blocks
	 * for (j = 16; j < MESSAGE_SIZE_BYTES; j++):
	 *	u32 sig0, sig1;
	 *	sig0 = (ROTR(W64[j-15]:w1,7) ^ ROTR(W64[j-15]:w1,18) ^ (W64[j-15]:w1 >> 3));
	 *	sig1 = ROTR(W64[j-2]:w14,17) ^ ROTR(W64[j-2]:w14, 19) ^ (W64[j-2]:w14 >> 10);
	 *	W64[j]:w16 = W64[j-16]:w0 + sig0 + W64[j-7]:w9 + sig1;
	 */
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
	/* insert here */


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
 * 	struct tsha512t256*:rdi - state
 *	int finish:rsi - 0 for continue, 1 to finish
 *
 * output:
 *	return:rax - <0 for error, 0 for success
 *
 */
/* int tsha512t256a_update(struct tsha512t256 *state, u32 finish) */
// X86_64 calling convention: RDI, RSI, RDX, RCX, R8, R9, ([XYZ]MM0–7.), Stack R-TO-L
.type tsha512t256a_update, @function
tsha512t256a_update:
	pushq		rbp
	movq		rsp,rbp

	subq		$4,rsp /* padding to align to 16 bytes */
	subq		$8,rsp /* struct tsha512t256* */
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

	/* if (finish == 1 || state->i_message >= MESSAGE_SIZE_BYTES)
	 *	;
	 * else
	 *	return 0;						      */
	movl		finish(rbp),eax
	cmpl		$1,eax
	je		DO_FSM_UPDATE_Y
		/* || */
		movl		i_message(rdi),eax
		cmpl		$MESSAGE_SIZE_BYTES,eax
		jge		DO_FSM_UPDATE_Y
		jmp		DO_FSM_UPDATE_N

DO_FSM_UPDATE_N:
			movl		$0,ret(rbp)
			jmp		OUT

DO_FSM_UPDATE_Y:
//			nop
//			jmp		E0


	/* if (state->event == TSHA512T256_FSM_INPUT)
	 *	if (finish == 1):
	 *	 	state->event = TSHA512T256_FSM_INPUT_UPDATE;	      */

E0:	movl		event(rdi),ecx
	cmpl		$TSHA512T256_FSM_INPUT,ecx
	je		E0T
	jmp		E1

E0T:		dprint_entered_event0

		movl		finish(rbp),ecx
		cmpl		$1,ecx
		je		E0CT
		jmp		OUT

E0CT:			movl		$TSHA512T256_FSM_INPUT_UPDATE,event(rdi)
			jmp		OUT

	/*
	 * else if (state->event == TSHA512T256_FSM_INPUT_UPDATE):
	 *	if (finish == 1):
	 *		state->event = TSHA512T256_FSM_APPEND_1BIT;
	 *	else:
	 *		_tsha512t256a_complete_message_block(state);
	 *		state->event = TSHA512T256_FSM_INPUT;
	 */

E1:	movl		event(rdi),ecx
	cmp		$TSHA512T256_FSM_INPUT_UPDATE,ecx
	je		E1T
	jmp		E2
E1T:
		dprint_entered_event1

		movl		finish(rbp),ecx
		cmpl		$1,ecx
		je		E1CT
		jmp		E1CF

E1CT:			movl		$TSHA512T256_FSM_APPEND_1BIT,event(rdi)
			jmp		OUT
		/* else: */
E1CF:			_tsha512t256a_complete_message_block
			movl		$TSHA512T256_FSM_INPUT,event(rdi)
			jmp		OUT


	/* Add "1" bit
	 * else if (state->event == TSHA512T256_FSM_APPEND_1BIT):
	 *	if (state->i_message < MESSAGE_SIZE_BYTES):
	 *		W8[seq[state->i_message]] = (u8)0x80;
	 *		state->i_message++;
	 *		state->event = TSHA512T256_FSM_APPEND_0_PADDING;
	 *	else:
	 *		_tsha512t256a_complete_message_block(state);
	 *		W8[seq[state->i_message]] = (u8)0x80;
	 *		state->i_message++;
	 *		state->event = TSHA512T256_FSM_APPEND_0_PADDING;
	 */
E2:	movl		event(rdi),ecx
	cmpl		$TSHA512T256_FSM_APPEND_1BIT,ecx
	je		E2T
	jmp		E3
E2T:
		dprint_entered_event2

		movl		i_message(rdi),ebx
		cmpl		$MESSAGE_SIZE_BYTES,ebx
		jl		E2CT
		jmp		E2CF
E2CF:			_tsha512t256a_complete_message_block
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

			/* state->event = TSHA512T256_FSM_APPEND_0_PADDING */
			movl            event(rdi),ecx
			movl		$TSHA512T256_FSM_APPEND_0_PADDING,event(rdi)
			jmp		OUT

	/*
	 * else if (state->event == TSHA512T256_FSM_APPEND_0_PADDING):
	 *	if (state->i_message < 56):
	 *		state->event = TSHA512T256_FSM_APPEND_LENGTH;
	 *	else
	 *		_tsha512t256a_complete_message_block(state);
	 *		state->event = TSHA512T256_FSM_APPEND_0_PADDING;
	 */
E3:	movl		event(rdi),ecx
	cmpl		$TSHA512T256_FSM_APPEND_0_PADDING,ecx
	je		E3T
	jmp		E4
E3T:
		dprint_entered_event3

		movl		i_message(rdi),eax
		cmpl		$56,eax
		jl		E3CT
		jmp		E3CF
E3CT:			movl		$TSHA512T256_FSM_APPEND_LENGTH,event(rdi)
			jmp		OUT
		/* else: */
E3CF:			_tsha512t256a_complete_message_block
			movl		$TSHA512T256_FSM_APPEND_0_PADDING,event(rdi)
			jmp		OUT

	/* Append message length
	 * else if (state->event == TSHA512T256_FSM_APPEND_LENGTH)
	 *	if (state->i_message < 56):
	 *		u8 len8[L_SIZE];
	 *		u128 *len128 = (u128*)len8;
	 *		*len128 = state->msglen*8;
	 *		for(i_len = 0, i = MESSAGE_SIZE_BYTES - L_SIZE ; i < MESSAGE_SIZE_BYTES ; i++, i_len++):
	 *			W8[seq2[i_len]] = len8[i_len];
	 *		_tsha512t256a_complete_message_block(state);
	 *		state->event = TSHA512T256_FSM_COMPLETE;
	 *	else:
	 *		state->event = TSHA512T256_FSM_ERROR;
	 * else
	 *	state->event = TSHA512T256_FSM_ERROR;
	 */
E4:	movl		event(rdi),eax
	cmpl		$TSHA512T256_FSM_APPEND_LENGTH,eax
	je		E4T /* && */
	jmp		E4CF
E4T:
		dprint_entered_event4

		movl		i_message(rdi),eax
		cmpl		$56,eax
		jl		E4CT
		jmp		E4CF

E4CT:			set_length
			_tsha512t256a_complete_message_block
			movl		$TSHA512T256_FSM_COMPLETE,event(rdi)


			jmp		OUT
		/* else: */
E4CF:			movl		$TSHA512T256_FSM_ERROR,event(rdi)
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
/* int tsha512t256a_reset(struct tsha512t256 *state) */
.type tsha512t256a_reset, @function
tsha512t256a_reset:
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
/* void tsha512t256a_close(struct tsha512t256 *state) */
.type tsha512t256a_close, @function
tsha512t256a_close:
	clear_A
	clear_W
	clear_state
	//clear_gpr
	ret

/* Read a single character. */
/* int tsha512t256a_getch(struct tsha512t256 *state, u8 c) */
.type tsha512t256a_getch, @function
tsha512t256a_getch:
	pushq		rbp
	movq		rsp,rbp

.set state,-20
.set ret,-24

	subq		$12,rsp /* padding for 16 byte alignment */
	subq		$8,rsp /* struct tsha512t256* */
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

	/* if (state->event != TSHA512T256_FSM_INPUT):
	 *	return ret;						      */

191:	movl		event(rdi),eax
	cmpl		$TSHA512T256_FSM_INPUT,eax
	jne		192f
	jmp		193f

192:	jmp		196f

	/* if (state->i_message < MESSAGE_SIZE_BYTES)
	 *	W8[seq[state->i_message]] = c;
	 *	state->i_message++;
	 *	state->msglen++;
	 *	ret = 1;						      */

	/* state->i_message < MESSAGE_SIZE_BYTES */
193:	movl		i_message(rdi),ecx
	cmpl		$MESSAGE_SIZE_BYTES,ecx
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
		/* state->event = TSHA512T256_FSM_INPUT_UPDATE; */
195:		movl		$TSHA512T256_FSM_INPUT_UPDATE,event(rdi)

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

/* u32* tsha512t256a_get_hashcode(struct tsha512t256 *state) */
.type tsha512t256a_get_hashcode, @function
tsha512t256a_get_hashcode:
	leaq		digest(rdi),rax
	ret
