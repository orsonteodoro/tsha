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

/* SSE4.1 optimized functions */

#ifndef TSHA512T256_SSE4_1
#define TSHA512T256_SSE4_1

#ifdef HAVE_SSE4_1
#  define GET_W(W,CI,XMM)							\
	asm (	"pextrq          %2,%1,%q0"					\
		: "=r" (W)							\
		: "x" (XMM),							\
		  "i" (CI));

#  define INSERT_BYTE(CI,C,XMM)						\
	asm (	"pinsrb		%2,%k1,%0"					\
		: "=x" (XMM)							\
		: "r" (C)							\
		: "i" (CI)

#  define SET_W(W,CI,XMM)							\
	asm (	"pinsrq          %2,%q1,%0"					\
		: "=x" (XMM)							\
		: "r" (W),							\
		  "i" (CI));

#  define NEXT_W()								\
	asm(	"psrldq          $8,xmm0\n\t"					\
		:								\
		:								\
		: "xmm0");							\
	GET_W(r10,0,xmm1);							\
	SET_W(r10,1,xmm0);							\
	asm(	"psrldq          $8,xmm1\n\t"					\
		:								\
		:								\
		: "xmm1");							\
	GET_W(r10,0,xmm2);							\
	SET_W(r10,1,xmm1);							\
	asm(	"psrldq          $8,xmm2\n\t"					\
		:								\
		:								\
		: "xmm2");							\
	GET_W(r10,0,xmm3);							\
	SET_W(r10,1,xmm2);							\
	asm(	"psrldq          $8,xmm3\n\t"					\
		:								\
		:								\
		: "xmm3");							\
	GET_W(r10,0,xmm4);							\
	SET_W(r10,1,xmm3);							\
	asm(	"psrldq          $8,xmm4\n\t"					\
		:								\
		:								\
		: "xmm4");							\
	GET_W(r10,0,xmm5);							\
	SET_W(r10,1,xmm4);							\
	asm(	"psrldq          $8,xmm5\n\t"					\
		:								\
		:								\
		: "xmm5");							\
	GET_W(r10,0,xmm6);							\
	SET_W(r10,1,xmm5);							\
	asm(	"psrldq          $8,xmm6\n\t"					\
		:								\
		:								\
		: "xmm6");							\
	GET_W(r10,0,xmm7);							\
	SET_W(r10,1,xmm6);							\
	asm(	"psrldq          $8,xmm7\n\t"					\
		:								\
		:								\
		: "xmm7");							\
	GET_W(r10,0,xmm8);							\
	SET_W(r10,1,xmm7);							\

void _insert_W_byte(u64 bi, u64 c)
{
	//todo
}

#endif // defined (HAVE_SSE4_1)
#endif // TSHA512T256_SSE4_1
