#!/usr/bin/python3
#
# Near Jump, Jump Table Generator for sha256b
#
# Copyright (c) 2021-2022 Orson Teodoro <orsonteodoro@hotmail.com>.  All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

answer = ""
L = []

def gen_insert_W_byte_sse2_table_sha256():
	global answer
	line = 2000
	mmi = 3
	jt_label = "insert_byte_sse2_jt\\@"
	for bi in range(256):
		L.append(line)
		if bi <= 239:
			block = \
".L" + str(line) + "\\@:" \
"	insert_byte " + str(bi % 16) + ",\\c,xmm" + str(int(bi / 16)) + ",xmm15\n" \
"	jmp		.Llast\\@\n"
			line += 1
			answer = answer + block
		if bi >= 240:
			if bi % 8 == 0:
				mmi += 1
			block = \
".L" + str(line) + "\\@:" \
"	insert_byte_alt " + str(bi % 8) +",\\c,mm" + str(mmi) + ",\\gpr0q,\\gpr0l,\\gpr1q\n" \
"	jmp		.Llast\\@\n"
			line += 1
			answer = answer + block
	print("/* Insertion jump table for SSE2 */")
	print(".section .rodata")
	print(".align 4")
	print(jt_label +  ":")
	for e in L:
		print(".long	.L" + str(e) + "\\@-" + jt_label)
	print(".long	.L" + str(line) + "\\@-" + jt_label)
	print(".text")
	answer = answer.replace("last",str(line))
	print(answer)
	print(".L" + str(line) + "\\@:")

def gen_insert_W_byte_sse4_1_table_sha512_256():
	global answer
	line = 2500
	jt_label = "insert_byte_sse4_1_jt\\@"
	for bi in range(256):
		L.append(line)
		block = \
".L" + str(line) + "\\@:" \
"	insert_byte " + str(bi % 16) + ",\\c,xmm" + str(int(bi / 16)) + "\n" \
"	jmp		.Llast\\@\n"
		line += 1
		answer = answer + block

	print("/* Insertion jump table for SSE4.1 */")
	print(".section .rodata")
	print(".align 4")
	print(jt_label + ":")
	for e in L:
		print(".long	.L" + str(e) + "\\@-" + jt_label)
	print(".long	.L" + str(line) + "\\@-" + jt_label)
	print(".text")
	answer = answer.replace("last",str(line))
	print(answer)
	print(".L" + str(line) + "\\@:")

def gen_insert_W_byte_sse2_table_sha512_256():
	global answer
	line = 2000
	mmi = 3
	jt_label = "insert_byte_sse2_jt\\@"
	for bi in range(256):
		L.append(line)
		if bi <= 239:
			block = \
".L" + str(line) + "\\@:" \
"	insert_byte " + str(bi % 16) + ",\\c,xmm" + str(int(bi / 16)) + ",xmm15\n" \
"	jmp		.Llast\\@\n"
			line += 1
			answer = answer + block
		if bi >= 240:
			if bi % 8 == 0:
				mmi += 1
			block = \
".L" + str(line) + "\\@:" \
"	insert_byte_alt " + str(bi % 8) +",\\c,mm" + str(mmi) + ",\\gpr0q,\\gpr0l,\\gpr1q\n" \
"	jmp		.Llast\\@\n"
			line += 1
			answer = answer + block
	print("/* Insertion jump table for SSE2 */")
	print(".section .rodata")
	print(".align 4")
	print(jt_label +  ":")
	for e in L:
		print(".long	.L" + str(e) + "\\@-" + jt_label)
	print(".long	.L" + str(line) + "\\@-" + jt_label)
	print(".text")
	answer = answer.replace("last",str(line))
	print(answer)
	print(".L" + str(line) + "\\@:")

def gen_insert_W_byte_sse4_1_table_sha256():
	global answer
	line = 2500
	jt_label = "insert_byte_sse4_1_jt\\@"
	for bi in range(256):
		L.append(line)
		block = \
".L" + str(line) + "\\@:" \
"	insert_byte " + str(bi % 16) + ",\\c,xmm" + str(int(bi / 16)) + "\n" \
"	jmp		.Llast\\@\n"
		line += 1
		answer = answer + block

	print("/* Insertion jump table for SSE4.1 */")
	print(".section .rodata")
	print(".align 4")
	print(jt_label + ":")
	for e in L:
		print(".long	.L" + str(e) + "\\@-" + jt_label)
	print(".long	.L" + str(line) + "\\@-" + jt_label)
	print(".text")
	answer = answer.replace("last",str(line))
	print(answer)
	print(".L" + str(line) + "\\@:")


def gen_get_w_sse4_1_table_sha256():
	global answer
	line = 3000
	jt_label = "get_w_sse4_1_jt\\@"
	for wi in range(64):
		L.append(line)
		block = \
".L" + str(line) + "\\@:" \
"	_get_w \\w," + str(wi % 4) + ",xmm" + str(int(wi / 4)) + "\n" \
"	jmp		.Llast\\@\n"
		line += 1
		answer = answer + block

	print("/* Get wi jump table for SSE4.1 */")
	print(".section .rodata")
	print(".align 4")
	print(jt_label + ":")
	for e in L:
		print(".long	.L" + str(e) + "\\@-" + jt_label)
	print(".long	.L" + str(line) + "\\@-" + jt_label)
	print(".text")
	answer = answer.replace("last",str(line))
	print(answer)
	print(".L" + str(line) + "\\@:")

def gen_set_w_sse4_1_table_sha256():
	global answer
	line = 3500
	jt_label = "set_w_sse4_1_jt\\@"
	for wi in range(64):
		L.append(line)
		block = \
".L" + str(line) + "\\@:" \
"	_set_w \\w," + str(wi % 4) + ",xmm" + str(int(wi / 4)) + "\n" \
"	jmp		.Llast\\@\n"
		line += 1
		answer = answer + block

	print("/* Set wi jump table for SSE4.1 */")
	print(".section .rodata")
	print(".align 4")
	print(jt_label + ":")
	for e in L:
		print(".long	.L" + str(e) + "\\@-" + jt_label)
	print(".long	.L" + str(line) + "\\@-" + jt_label)
	print(".text")
	answer = answer.replace("last",str(line))
	print(answer)
	print(".L" + str(line) + "\\@:")

def gen_get_w_sse2_table_sha256():
	global answer
	line = 4000
	mmi = 3
	jt_label = "get_w_sse2_jt\\@"
	for wi in range(64):
		block = ""
		L.append(line)
		if wi <= 59:
			block = \
".L" + str(line) + "\\@:" \
"	_get_w \\w," + str((wi % 4)*4) + ",xmm" + str(int(wi / 4)) + ",xmm15\n" \
"	jmp		.Llast\\@\n"
		if wi >= 60:
			parity = wi % 2
			if parity == 0:
				mmi += 1
				block = \
".L" + str(line) + "\\@:" \
"	_get_w_alt_c0 \\w,mm" + str(mmi) + "\n" \
"	jmp		.Llast\\@\n"
			else:
				block = \
".L" + str(line) + "\\@:" \
"	_get_w_alt_c1 \\w,mm" + str(mmi) + ",\\gpr0q,\\gpr0l\n" \
"	jmp		.Llast\\@\n"

		answer = answer + block
		line += 1


	print("/* Get wi jump table for SSE2 */")
	print(".section .rodata")
	print(".align 4")
	print(jt_label + ":")
	for e in L:
		print(".long	.L" + str(e) + "\\@-" + jt_label)
	print(".long	.L" + str(line) + "\\@-" + jt_label)
	print(".text")
	answer = answer.replace("last",str(line))
	print(answer)
	print(".L" + str(line) + "\\@:")

def gen_set_w_sse2_table_sha256():
	global answer
	line = 4500
	mmi = 3
	jt_label = "set_w_sse2_jt\\@"
	for wi in range(64):
		block = ""
		L.append(line)
		if wi <= 59:
			block = \
".L" + str(line) + "\\@:" \
"	_set_w \\w," + str((wi % 4)*4) + ",xmm" + str(int(wi / 4)) + ",xmm15,\\gpr0l\n" \
"	jmp		.Llast\\@\n"
		if wi >= 60:
			parity = wi % 2
			if parity == 0:
				mmi += 1
				block = \
".L" + str(line) + "\\@:" \
"	_set_w_alt \\w,0,mm" + str(mmi) + ",\\gpr0q,\\gpr0l,\\gpr1q\n" \
"	jmp		.Llast\\@\n"
			else:
				block = \
".L" + str(line) + "\\@:" \
"	_set_w_alt \\w,32,mm" + str(mmi) + ",\\gpr0q,\\gpr0l,\\gpr1q\n" \
"	jmp		.Llast\\@\n"

		answer = answer + block
		line += 1


	print("/* Set wi jump table for SSE2 */")
	print(".section .rodata")
	print(".align 4")
	print(jt_label + ":")
	for e in L:
		print(".long	.L" + str(e) + "\\@-" + jt_label)
	print(".long	.L" + str(line) + "\\@-" + jt_label)
	print(".text")
	answer = answer.replace("last",str(line))
	print(answer)
	print(".L" + str(line) + "\\@:")


###############################################################################################


def gen_get_w_sse4_1_table_sha512_256():
	global answer
	line = 3000
	jt_label = "get_w_sse4_1_jt\\@"
	for wi in range(64):
		L.append(line)
		block = \
".L" + str(line) + "\\@:" \
"	_get_w \\w," + str(wi % 4) + ",xmm" + str(int(wi / 4)) + "\n" \
"	jmp		.Llast\\@\n"
		line += 1
		answer = answer + block

	print("/* Get wi jump table for SSE4.1 */")
	print(".section .rodata")
	print(".align 4")
	print(jt_label + ":")
	for e in L:
		print(".long	.L" + str(e) + "\\@-" + jt_label)
	print(".long	.L" + str(line) + "\\@-" + jt_label)
	print(".text")
	answer = answer.replace("last",str(line))
	print(answer)
	print(".L" + str(line) + "\\@:")

def gen_set_w_sse4_1_table_sha512_256():
	global answer
	line = 3500
	jt_label = "set_w_sse4_1_jt\\@"
	for wi in range(64):
		L.append(line)
		block = \
".L" + str(line) + "\\@:" \
"	_set_w \\w," + str(wi % 4) + ",xmm" + str(int(wi / 4)) + "\n" \
"	jmp		.Llast\\@\n"
		line += 1
		answer = answer + block

	print("/* Set wi jump table for SSE4.1 */")
	print(".section .rodata")
	print(".align 4")
	print(jt_label + ":")
	for e in L:
		print(".long	.L" + str(e) + "\\@-" + jt_label)
	print(".long	.L" + str(line) + "\\@-" + jt_label)
	print(".text")
	answer = answer.replace("last",str(line))
	print(answer)
	print(".L" + str(line) + "\\@:")

def gen_get_w_sse2_table_sha512_256():
	global answer
	line = 4000
	mmi = 3
	jt_label = "get_w_sse2_jt\\@"
	for wi in range(64):
		block = ""
		L.append(line)
		if wi <= 59:
			block = \
".L" + str(line) + "\\@:" \
"	_get_w \\w," + str((wi % 4)*4) + ",xmm" + str(int(wi / 4)) + ",xmm15\n" \
"	jmp		.Llast\\@\n"
		if wi >= 60:
			parity = wi % 2
			if parity == 0:
				mmi += 1
				block = \
".L" + str(line) + "\\@:" \
"	_get_w_alt_c0 \\w,mm" + str(mmi) + "\n" \
"	jmp		.Llast\\@\n"
			else:
				block = \
".L" + str(line) + "\\@:" \
"	_get_w_alt_c1 \\w,mm" + str(mmi) + ",\\gpr0q,\\gpr0l\n" \
"	jmp		.Llast\\@\n"

		answer = answer + block
		line += 1


	print("/* Get wi jump table for SSE2 */")
	print(".section .rodata")
	print(".align 4")
	print(jt_label + ":")
	for e in L:
		print(".long	.L" + str(e) + "\\@-" + jt_label)
	print(".long	.L" + str(line) + "\\@-" + jt_label)
	print(".text")
	answer = answer.replace("last",str(line))
	print(answer)
	print(".L" + str(line) + "\\@:")

def gen_set_w_sse2_table_sha512_256():
	global answer
	line = 4500
	mmi = 3
	jt_label = "set_w_sse2_jt\\@"
	for wi in range(64):
		block = ""
		L.append(line)
		if wi <= 59:
			block = \
".L" + str(line) + "\\@:" \
"	_set_w \\w," + str((wi % 4)*4) + ",xmm" + str(int(wi / 4)) + ",xmm15,\\gpr0l\n" \
"	jmp		.Llast\\@\n"
		if wi >= 60:
			parity = wi % 2
			if parity == 0:
				mmi += 1
				block = \
".L" + str(line) + "\\@:" \
"	_set_w_alt \\w,0,mm" + str(mmi) + ",\\gpr0q,\\gpr0l,\\gpr1q\n" \
"	jmp		.Llast\\@\n"
			else:
				block = \
".L" + str(line) + "\\@:" \
"	_set_w_alt \\w,32,mm" + str(mmi) + ",\\gpr0q,\\gpr0l,\\gpr1q\n" \
"	jmp		.Llast\\@\n"

		answer = answer + block
		line += 1


	print("/* Set wi jump table for SSE2 */")
	print(".section .rodata")
	print(".align 4")
	print(jt_label + ":")
	for e in L:
		print(".long	.L" + str(e) + "\\@-" + jt_label)
	print(".long	.L" + str(line) + "\\@-" + jt_label)
	print(".text")
	answer = answer.replace("last",str(line))
	print(answer)
	print(".L" + str(line) + "\\@:")


def main():
	print("---")
#	gen_insert_W_byte_sse4_1_table_sha256()

	print("---")
#	gen_insert_W_byte_sse2_table_sha256()

	print("---")
#	gen_insert_W_byte_sse4_1_table_sha512_256()

	print("---")
	gen_insert_W_byte_sse2_table_sha512_256()

	print("---")
#	gen_get_w_sse4_1_table_sha256()

	print("---")
#	gen_set_w_sse4_1_table_sha256()

	print("---")
#	gen_get_w_sse2_table_sha256()

	print("---")
#	gen_set_w_sse2_table_sha256()

	print("---")
#	gen_get_w_sse4_1_table_sha512_256()

	print("---")
#	gen_set_w_sse4_1_table_sha512_256()

	print("---")
#	gen_get_w_sse2_table_sha512_256()

	print("---")
#	gen_set_w_sse2_table_sha512_256()

if __name__ == "__main__":
	main()
