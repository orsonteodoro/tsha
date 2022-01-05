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

/* For the assembly module implementation */

#ifndef TSHA512T256_ASM
#define TSHA512T256_ASM

#ifdef ALG_ASM
#  define CPP_ASMLINKAGE
#  define asmlinkage CPP_ASMLINKAGE __attribute__((regparm(0)))
asmlinkage s32 tsha512t256a_update(struct tsha512 *state, u32 finish);
asmlinkage s32 tsha512t256a_reset(struct tsha512 *state);
asmlinkage s32 tsha512t256a_close(struct tsha512 *state);
asmlinkage s32 tsha512t256a_getch(struct tsha512 *state, u8 c);
asmlinkage u64* tsha512t256a_get_hashcode(struct tsha512 *state);
#endif // ALG_ASM

#endif // TSHA512T256_ASM
