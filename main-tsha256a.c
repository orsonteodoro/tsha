/*
 * tsha256a - A register based Secure Hashing Algorithm 2 implementation (assembly)
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

   It used as the basis for the assembly only tsha256a
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
#define ALG_ASM

#include "tsha256.h"
#include "tsha256-asm.h"

#if defined(DEBUG)
#  define debug_printf(format, ...)						\
	do {									\
		printf(format, ##__VA_ARGS__);					\
	} while(0)
#  else
#    define debug_printf(format, ...)
#endif // DEBUG

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

		ret = tsha256a_reset(&state);

		i = 0;
		while (i < bytes)
		{
			s32 bytes_read = 0;
			bytes_read = tsha256a_getch(&state, message[i]);
			if (bytes_read < 0)
			{
				tsha256a_close(&state);
				ret = -EINVAL;
				goto ERROR;
			}

			i += bytes_read;

			if (state.event == TSHA256_FSM_INPUT_UPDATE)
				tsha256a_update(&state, 0);
		}
		do {
			tsha256a_update(&state, 1);
		} while (state.event != TSHA256_FSM_COMPLETE
			&& state.event != TSHA256_FSM_ERROR);
		u32 *hashcode = tsha256a_get_hashcode(&state);
		memcpy(digest, hashcode, DIGEST_SIZE_BYTES);
		tsha256a_close(&state);

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
	s64 i;
	u32 bytes;
	u32 digest[DIGEST_SIZE_WORDS];
	if (argc)
	if (argc == 2) {
		bytes = strlen(argv[1]);
		ret = tsha256a_reset(&state);
		i = 0;
		while (i < bytes)
		{
			s32 bytes_read = 0;
			bytes_read = tsha256a_getch(&state, argv[1][i]);
			if (bytes_read < 0)
			{
				tsha256a_close(&state);
				ret = -EINVAL;
				goto DONE_ARGV;
			}

			i += bytes_read;
			if (state.event == TSHA256_FSM_INPUT_UPDATE)
				tsha256a_update(&state,0);
		}
		do {
			tsha256a_update(&state,1);
		} while (state.event != TSHA256_FSM_COMPLETE
			&& state.event != TSHA256_FSM_ERROR);
		u32 *hashcode = tsha256a_get_hashcode(&state);
		memcpy(digest, hashcode, DIGEST_SIZE_BYTES);
		tsha256a_close(&state);
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
