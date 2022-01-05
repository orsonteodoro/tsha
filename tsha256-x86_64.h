/*
 * tsha256 - A register based Secure Hashing Algorithm 2 implementation
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

#ifndef TSHA256_X86_64
#define TSHA256_X86_64

#ifdef ALG_PLAIN
#  ifdef USE_ASM
register u128 xmm0 asm ("xmm0");
register u128 xmm1 asm ("xmm1");
register u128 xmm2 asm ("xmm2");
register u128 xmm3 asm ("xmm3");
register u128 xmm4 asm ("xmm4");
register u128 xmm5 asm ("xmm5");
register u128 xmm6 asm ("xmm6");
register u128 xmm7 asm ("xmm7");
register u128 xmm8 asm ("xmm8");
register u128 xmm9 asm ("xmm9");
register u128 xmm10 asm ("xmm10");
register u128 xmm11 asm ("xmm11");
register u128 xmm12 asm ("xmm12");
register u128 xmm13 asm ("xmm13");
register u128 xmm14 asm ("xmm14");
register u128 xmm15 asm ("xmm15");

register u64 mm0 asm ("mm0");
register u64 mm1 asm ("mm1");
register u64 mm2 asm ("mm2");
register u64 mm3 asm ("mm3");
register u64 mm4 asm ("mm4");
register u64 mm5 asm ("mm5");
register u64 mm6 asm ("mm6");
register u64 mm7 asm ("mm7");

register u64 rax asm ("rax");
register u64 rbx asm ("rbx");
register u64 rcx asm ("rcx");
register u64 rdx asm ("rdx");

register u32 eax asm ("eax");
register u32 ebx asm ("ebx");
register u32 ecx asm ("ecx");
register u32 edx asm ("edx");

register u64 r8 asm ("r8");
register u64 r9 asm ("r9");
register u64 r10 asm ("r10");
register u64 r11 asm ("r11");
register u64 r12 asm ("r12");
register u64 r13 asm ("r13");
register u64 r14 asm ("r14");
register u64 r15 asm ("r15");

register u32 r8d asm ("r8");
register u32 r9d asm ("r9");
register u32 r10d asm ("r10");
register u32 r11d asm ("r11");
register u32 r12d asm ("r12");
register u32 r13d asm ("r13");
register u32 r14d asm ("r14");
register u32 r15d asm ("r15");

#      ifdef HAVE_BMI
#	 define PANDN0								\
		"andnq		 %q1,%q0,%q1\n\t"
#      else
#	 define PANDN0								\
		"notq            %q0\n\t"					\
		"andq            %q0,%q1\n\t"
#      endif

#      ifdef DEBUG

/* printf clobbers xmm, so push and pop xmm registers. */
#        define POPAGPR64()							\
	asm(	"popq		%%rax\n\t"					\
		"popq		%%rbx\n\t"					\
		"popq		%%rcx\n\t"					\
		"popq		%%rdx\n\t"					\
		"popq		%%rsi\n\t"					\
		"popq		%%rdi"						\
		:								\
		:								\
		: "rax",							\
		  "rbx",							\
		  "rcx",							\
		  "rdx",							\
		  "rsi",							\
		  "rdi");

#        define PUSHAGPR64()							\
	asm(	"pushq		%%rax\n\t"					\
		"pushq		%%rbx\n\t"					\
		"pushq		%%rcx\n\t"					\
		"pushq		%%rdx\n\t"					\
		"pushq		%%rsi\n\t"					\
		"pushq		%%rdi"						\
		:								\
		:								\
		: "rax",							\
		  "rbx",							\
		  "rcx",							\
		  "rdx",							\
		  "rsi",							\
		  "rdi");
#      endif // DEBUG

/* Clears a, b, c, d, e, f, g, h and tmp variables */
#    define CLEAR_A()								\
	asm (	"pxor		%%mm0,%%mm0\n\t"				\
	 	"pxor		%%mm1,%%mm1\n\t"				\
	 	"pxor		%%mm2,%%mm2\n\t"				\
	 	"pxor		%%mm3,%%mm3\n\t"				\
	 	"pxor		%%mm4,%%mm4\n\t"				\
	 	"pxor		%%mm5,%%mm5\n\t"				\
	 	"pxor		%%mm6,%%mm6\n\t"				\
	 	"pxor		%%mm7,%%mm7"					\
		: : :								\
		  "mm0",							\
		  "mm1",							\
		  "mm2",							\
		  "mm3",							\
		  "mm4",							\
		  "mm5",							\
		  "mm6",							\
		  "mm7");

#    define CLEAR_GPR()								\
	asm (	"xorq		%%rax,%%rax\n\t"				\
		"xorq		%%rbx,%%rbx\n\t"				\
		"xorq		%%rcx,%%rcx\n\t"				\
		"xorq		%%rdx,%%rdx\n\t"				\
		"xorq		%%r8,%%r8\n\t"					\
		"xorq		%%r9,%%r9\n\t"					\
		"xorq		%%r10,%%r10\n\t"				\
		"xorq		%%r11,%%r11\n\t"				\
		"xorq		%%r12,%%r12\n\t"				\
		"xorq		%%r13,%%r13\n\t"				\
		"xorq		%%r14,%%r14\n\t"				\
		"xorq		%%r15,%%r15"					\
		: : :								\
		  "rax",							\
		  "rbx",							\
		  "rcx",							\
		  "rdx",							\
		  "r8",								\
		  "r9",								\
		  "r10",							\
		  "r11",							\
		  "r12",							\
		  "r13",							\
		  "r14",							\
		  "r15");

/* Clears w0 - w63 */
#    define CLEAR_W()								\
	asm ( 	"pxor		%%xmm0,%%xmm0\n\t"				\
		"pxor		%%xmm1,%%xmm1\n\t"				\
		"pxor		%%xmm2,%%xmm2\n\t"				\
		"pxor		%%xmm3,%%xmm3\n\t"				\
		"pxor		%%xmm4,%%xmm4\n\t"				\
		"pxor		%%xmm5,%%xmm5\n\t"				\
		"pxor		%%xmm6,%%xmm6\n\t"				\
		"pxor		%%xmm7,%%xmm7\n\t"				\
		"pxor		%%xmm8,%%xmm8\n\t"				\
		"pxor		%%xmm9,%%xmm9\n\t"				\
		"pxor		%%xmm10,%%xmm10\n\t"				\
		"pxor		%%xmm11,%%xmm11\n\t"				\
		"pxor		%%xmm12,%%xmm12\n\t"				\
		"pxor		%%xmm13,%%xmm13\n\t"				\
		"pxor		%%xmm14,%%xmm14\n\t"				\
		"pxor		%%xmm15,%%xmm15"				\
		: : :								\
		  "xmm0",							\
		  "xmm1",							\
		  "xmm2",							\
		  "xmm3",							\
		  "xmm4",							\
		  "xmm5",							\
		  "xmm6",							\
		  "xmm7",							\
		  "xmm8",							\
		  "xmm9",							\
		  "xmm10",							\
		  "xmm11",							\
		  "xmm12",							\
		  "xmm13",							\
		  "xmm14",							\
		  "xmm15");


#    define DUMP_XMM(A,XMM)							\
	asm (	"movdqu          %1,%0"						\
		: "=m" (A)							\
		: "x" (XMM));

#    define DUMP_MM2(A,MM0,MM1)							\
	asm (	"movq		%1,0%V0\n\t"					\
		"movq		%2,8%V0"					\
		: "=m" (A)							\
		: "y" (MM0),							\
		  "y" (MM1));

#    define GET_ACEG(W,MM)							\
	asm (	"movd		%1,%k0"						\
		: "=r" (W)							\
		: "y" (MM));


#    define GET_BDFH(W,MM,GPR)							\
	asm (	"movq		%2,%q1\n\t"					\
		"shrq		$32,%q1\n\t"					\
		"movl		%k1,%k0"					\
		: "=r" (W),							\
		  "+r" (GPR)							\
		: "y" (MM));

#    define INIT_ABCDEFGH(H0,H2,H4,H6)						\
	asm(	"movq		%0,%%mm0\n\t"					\
		"movq		%1,%%mm1\n\t"					\
		"movq		%2,%%mm2\n\t"					\
		"movq		%3,%%mm3"					\
		:								\
		: "m" (H0),							\
		  "m" (H2),							\
		  "m" (H4),							\
		  "m" (H6)							\
		: "mm0",							\
		  "mm1",							\
		  "mm2",							\
		  "mm3");

#    define INIT_H(XMM,HASH,A0,A1)						\
	asm (	"movdqa          %2,%0\n\t"					\
		"movdqa          %0,0%V1\n\t"					\
		"movdqa          %3,%0\n\t"					\
		"movdqa          %0,16%V1\n\t"					\
		"pxor            %0,%0"						\
		: "+x" (XMM),							\
		  "=m" (HASH)							\
		: "m" (A0),							\
		  "m" (A1));

#    define ROTRL(V,AMT)							\
	asm(	"rorl		%k1,%k0"					\
		: "=r" (V)							\
		: "i"  (AMT));


#    define SET_ACEG(W,MM,GPR0,GPR1,MASK)					\
	asm (	"movq		%0,%q1\n\t"					\
		"andq		%4,%q1\n\t"					\
		"movl		%k3,%k2\n\t"					\
		"shlq		$0,%q2\n\t"					\
		"xorq		%q2,%q1\n\t"					\
		"movq		%q1,%0"						\
		: "+y" (MM),							\
		  "+r" (GPR0),							\
		  "+r" (GPR1)							\
		: "r"  (W),							\
		  "m"  (MASK));



#    define SET_BDFH(W,MM,GPR0,GPR1,MASK)					\
	asm (	"movq		%0,%q1\n\t"	 				\
		"andq		%4,%q1\n\t" 					\
		"movl		%k3,%k2\n\t" 					\
		"shlq		$32,%q2\n\t"					\
		"xorq		%q2,%q1\n\t"					\
		"movq		%q1,%0"						\
		: "+y" (MM),							\
		  "+r" (GPR0),							\
		  "+r" (GPR1)							\
		: "r" (W),							\
		  "m" (MASK));

#    define SET_XMM(XMM,I32_3,I32_2,I32_1,I32_0,TXMM,GPR)			\
	asm (	"movl		 %k2,%k6\n\t"					\
		"movd		 %q6,%1\n\t"					\
		"pslldq		 $4,%0\n\t"					\
		"pxor		 %1,%0\n\t"					\
		"movl		 %k3,%k6\n\t"					\
		"movd		 %q6,%1\n\t"					\
		"pslldq		 $4,%0\n\t"					\
		"pxor		 %1,%0\n\t"					\
		"movl		 %k4,%k6\n\t"					\
		"movd		 %q6,%1\n\t"					\
		"pslldq		 $4,%0\n\t"					\
		"pxor		 %1,%0\n\t"					\
		"movl		 %k5,%k6\n\t"					\
		"movd		 %q6,%1\n\t"					\
		"pslldq		 $4,%0\n\t"					\
		"pxor		 %1,%0"						\
		: "=x" (XMM),							\
		  "+x" (TXMM)							\
		: "ir" (I32_3),							\
		  "ir" (I32_2),							\
		  "ir" (I32_1),							\
		  "ir" (I32_0),							\
		  "r" (GPR));

u128 __attribute__((used)) mask0 = 0x00000000ffffffff;
u128 __attribute__((used)) mask1 = 0xffffffff00000000;

u32 get_a(void)
{
	register u32 w asm ("eax");
	GET_ACEG(w,mm0);
	return w;
}

void set_a(u32 w)
{
	register u32 gpr0 asm ("rsi");
	register u32 gpr1 asm ("rdx");
	SET_ACEG(w,mm0,gpr0,gpr1,mask1);
}

u32 get_c(void)
{
	register u32 w asm ("eax");
	GET_ACEG(w,mm1);
	return w;
}

void set_c(u32 w)
{
	register u32 gpr0 asm ("rsi");
	register u32 gpr1 asm ("rdx");
	SET_ACEG(w,mm1,gpr0,gpr1,mask1);
}

u32 get_e(void)
{
	register u32 w asm ("eax");
	GET_ACEG(w,mm2);
	return w;
}

void set_e(u32 w)
{
	register u32 gpr0 asm ("rsi");
	register u32 gpr1 asm ("rdx");
	SET_ACEG(w,mm2,gpr0,gpr1,mask1);
}

u32 get_g(void)
{
	register u32 w asm ("eax");
	GET_ACEG(w,mm3);
	return w;
}

void set_g(u32 w)
{
	register u32 gpr0 asm ("rsi");
	register u32 gpr1 asm ("rdx");
	SET_ACEG(w,mm3,gpr0,gpr1,mask1);
}


u32 get_b(void)
{
	register u32 w asm ("eax");
	register u32 gpr0 asm ("rdx");
	GET_BDFH(w,mm0,gpr0);
	return w;
}

void set_b(u32 w)
{
	register u32 gpr0 asm ("rsi");
	register u32 gpr1 asm ("rdx");
	SET_BDFH(w,mm0,gpr0,gpr1,mask0);
}


u32 get_d(void)
{
	register u32 w asm ("eax");
	register u32 gpr0 asm ("rsi");
	GET_BDFH(w,mm1,gpr0);
	return w;
}

void set_d(u32 w)
{
	register u32 gpr0 asm ("rsi");
	register u32 gpr1 asm ("rdx");
	SET_BDFH(w,mm1,gpr0,gpr1,mask0);
}


u32 get_f(void)
{
	register u32 w asm ("eax");
	register u32 gpr0 asm ("rsi");
	GET_BDFH(w,mm2,gpr0);
	return w;
}

void set_f(u32 w)
{
	register u32 gpr0 asm ("rsi");
	register u32 gpr1 asm ("rdx");
	SET_BDFH(w,mm2,gpr0,gpr1,mask0);
}

u32 get_h(void)
{
	register u32 w asm ("eax");
	register u32 gpr0 asm ("rsi");
	GET_BDFH(w,mm3,gpr0);
	return w;
}

void set_h(u32 w)
{
	register u32 gpr0 asm ("rsi");
	register u32 gpr1 asm ("rdx");
	SET_BDFH(w,mm3,gpr0,gpr1,mask0);
}
#  endif // USE_ASM

#  if defined(DEBUG) && defined(USE_ASM)
#    define debug_printf(format, ...)						\
	do {									\
		u8 __attribute__ ((aligned (16))) da[512];			\
		PUSHAGPR64();							\
		_fxsave64(da);							\
		printf(format, ##__VA_ARGS__);					\
		_fxrstor64(da);							\
		POPAGPR64();							\
	} while(0)
#  endif // DEBUG

#endif // ALG_PLAIN

#endif // TSHA256_X86_64
