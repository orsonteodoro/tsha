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

/* SSE2 optimized functions */

#ifndef TSHA512T256_SSE2
#define TSHA512T256_SSE2

#if defined (HAVE_SSE2)
#  define GET_WR(W,XMM)								\
	asm (	"movq            %1,%q0"					\
		: "=r" (W),							\
		: "x" (XMM));

#  define GET_WL(W,XMM,TXMM)							\
	asm (	"movdqa          %2,%1\n\t"					\
		"psrldq          $8,%1\n\t"					\
		"movq            %1,%q0"					\
		: "=r" (W),							\
		  "+x" (TXMM)							\
		: "x" (XMM));

#  define INSERT_BYTE(CI,C,XMM,TXMM)						\
	asm (	"movd		%k2,%1\n\t"					\
		"pslldq		%3,%1\n\t"					\
		"pxor		%1,%0"						\
		: "=x" (XMM),							\
		  "+x" (TXMM)							\
		: "r" (C),							\
		  "i" (CI));

#  define INSERT_BYTE_ALT(CI,C,MM,GPR0,GPR1)					\
	asm (	"movl		%k3,%k1\n\t"					\
		"shlq		%4,%q1\n\t"					\
		"movq		%0,%q2\n\t"					\
		"xorq		%q1,%q2\n\t"					\
		"movq		%q2,%0"						\
		: "+x" (MM),							\
		  "+r" (GPR0),							\
		  "+r" (GPR1)							\
		: "r" (C),							\
		  "i" (CI));

#  define SET_WR(W,XMM,TXMM,MASK)						\
	asm (	"movq            %q2,%1\n\t"					\
		"pand            %4,%0\n\t"					\
		"pxor            %1,%0"						\
		: "+x" (XMM),							\
		  "+x" (TXMM),							\
		: "r" (W),							\
		  "m" (MASK));

#  define SET_WL(W,XMM,TXMM,MASK)						\
	asm (	"movq            %q2,%1\n\t"					\
		"pslldq          $8,%1\n\t"					\
		"pand            %4,%0\n\t"					\
		"pxor            %1,%0"						\
		: "+x" (XMM),							\
		  "+x" (TXMM),							\
		: "r" (W),							\
		  "m" (MASK));

#  ifdef HAVE_SSE4_1
#    define GET_W0(W)								\
		GET_W(W,0,xmm0)
#    define GET_W1(W)								\
		GET_W(W,1,xmm0)
#    define GET_W9(W)								\
		GET_W(W,1,xmm4)
#    define GET_W14(W)								\
		GET_W(W,0,xmm7)
#    define GET_W16(W)								\
		GET_W(W,0,xmm8)
#    define SET_W16(W)								\
		SET_W(W,0,xmm8)
#  else
#    define GET_W0(W)								\
		GET_WR(W,xmm0)
#    define GET_W1(W)								\
		GET_WL(W,xmm0)
#    define GET_W9(W)								\
		GET_WR(W,xmm4)
#    define GET_W14(W)								\
		GET_WR(W,xmm7)
#    define SET_W16(W)								\
		SET_WR(W,xmm8,xmm14,mask1)
#  endif // HAVE_SSE4_1

#  ifdef HAVE_SSE4_1
#    define NEXT_W()								\
	asm(	"psrldq          $8,xmm0\n\t"					\
		:								\
		:								\
		: "xmm0");							\
	GET_W(r10,xmm1);							\
	SET_W(r10,xmm0);							\
	asm(	"psrldq          $8,xmm1\n\t"					\
		:								\
		:								\
		: "xmm1");							\
	GET_W(r10,xmm2);							\
	SET_W(r10,xmm1);							\
	asm(	"psrldq          $8,xmm2\n\t"					\
		:								\
		:								\
		: "xmm2");							\
	GET_W(r10,xmm3);							\
	SET_W(r10,xmm2);							\
	asm(	"psrldq          $8,xmm3\n\t"					\
		:								\
		:								\
		: "xmm3");							\
	GET_W(r10,xmm4);							\
	SET_W(r10,xmm3);							\
	asm(	"psrldq          $8,xmm4\n\t"					\
		:								\
		:								\
		: "xmm4");							\
	GET_W(r10,xmm5);							\
	SET_W(r10,xmm4);							\
	asm(	"psrldq          $8,xmm5\n\t"					\
		:								\
		:								\
		: "xmm5");							\
	GET_W(r10,xmm6);							\
	SET_W(r10,xmm5);							\
	asm(	"psrldq          $8,xmm6\n\t"					\
		:								\
		:								\
		: "xmm6");							\
	GET_W(r10,xmm7);							\
	SET_W(r10,xmm6);							\
	asm(	"psrldq          $8,xmm7\n\t"					\
		:								\
		:								\
		: "xmm7");							\
	GET_W(r10,xmm8);							\
	SET_W(r10,xmm7);							\
#  else
#    define NEXT_W()								\
	asm(	"psrldq          $8,xmm0\n\t"					\
		:								\
		:								\
		: "xmm0");							\
	GET_WR(r10,xmm1);							\
	SET_WL(r10,xmm0,xmm14,mask1);						\
	asm(	"psrldq          $8,xmm1\n\t"					\
		:								\
		:								\
		: "xmm1");							\
	GET_WR(r10,xmm2);							\
	SET_WL(r10,xmm1,xmm14,mask1);						\
	asm(	"psrldq          $8,xmm2\n\t"					\
		:								\
		:								\
		: "xmm2");							\
	GET_WR(r10,xmm3);							\
	SET_WL(r10,xmm2,xmm14,mask1);						\
	asm(	"psrldq          $8,xmm3\n\t"					\
		:								\
		:								\
		: "xmm3");							\
	GET_WR(r10,xmm4);							\
	SET_WL(r10,xmm3,xmm14,mask1);						\
	asm(	"psrldq          $8,xmm4\n\t"					\
		:								\
		:								\
		: "xmm4");							\
	GET_WR(r10,xmm5);							\
	SET_WL(r10,xmm4,xmm14,mask1);						\
	asm(	"psrldq          $8,xmm5\n\t"					\
		:								\
		:								\
		: "xmm5");							\
	GET_WR(r10,xmm6);							\
	SET_WL(r10,xmm5,xmm14,mask1);						\
	asm(	"psrldq          $8,xmm6\n\t"					\
		:								\
		:								\
		: "xmm6");							\
	GET_WR(r10,xmm7);							\
	SET_WL(r10,xmm6,xmm14,mask1);						\
	asm(	"psrldq          $8,xmm7\n\t"					\
		:								\
		:								\
		: "xmm7");							\
	GET_WR(r10,xmm8);							\
	SET_WL(r10,xmm7,xmm14,mask1);						\

void _insert_W_byte(u64 bi, u64 c)
{
	register u64 gpr0 asm ("r10");
	register u64 gpr1 asm ("r11");
	//todo
}

#endif // defined (HAVE_SSE2)
#endif // TSHA512T256_SSE2
