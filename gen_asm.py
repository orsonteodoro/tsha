#!/usr/bin/python3
#
# Binary Search Jump Code Generator for GAS Assembly programs
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

# The efficiency of this O(n)
#
# It may be used in processors that are not capable of loading jump tables
# that cannot load a list of offsets.  It is recommend to use
# gen_asm_reljump.py instead for O(1) efficiency with 2 clock cycle jumps.

c = 0
answer=""

pivot_to_label_mapping = dict()

#		print("cmp$"+str(int(p))+",eax"+"\n", end="")
def gen_recursive_conditional(l,r,minl,maxr):
	global answer
	global pivot_to_label_map
	global c

	p = int((l+r)/2)


	# reject inconsistent

	if r < minl:
		return -1

	if l > maxr:
		return -1

	if l > r:
		return -1

	if r < l:
		return -1

	# consistent only from this point

	cond =\
str(c)+ ":		cmp $" + str(int(p)) + ",eax\n"
#	print("c:" + str(c) + ",p=" + str(p))

	future_left_pivot = int((l + (p-1))/2)
	future_right_pivot = int(((p+1) + r)/2)

	if future_left_pivot != p:
		cond +=\
		"		jl		jl:" + str(future_left_pivot) + "::o" + str(c) +":\n"
	if future_right_pivot != p:
		cond +=\
		"		jg		jg:" + str(future_right_pivot) + "::o" + str(c) + ":\n"

		# equals condition
	cond +=\
	"		INSERT()\n"\
	"		jmp		out\n"

	pivot_to_label_mapping[p] = c

	c+=1

	answer = answer + cond

	gen_recursive_conditional(l,p-1,minl,maxr)
	gen_recursive_conditional(p+1,r,minl,maxr)

def remap_jmps():
	global pivot_to_label_mapping
	global answer
	for k in pivot_to_label_mapping.keys():
		answer = answer.replace("jl:" + str(k) + ":", ":"+str(pivot_to_label_mapping[k]))
		answer = answer.replace("jg:" + str(k) + ":", ":"+str(pivot_to_label_mapping[k]))
	pass

	for origin in pivot_to_label_mapping.values():
		for to in pivot_to_label_mapping.values():
			if to < origin:
				postfix = "b"
			else:
				postfix = "f"
			print("to="+str(to)+",origin="+str(origin)+",postfix="+postfix)
			answer = answer.replace(":"+str(to) + ":o" + str(origin) + ":", str(to) + postfix)
	pass




def main():
	global answer
	print("gen_recursive_conditional start")
	gen_recursive_conditional(0,255,0,255)
	answer = answer.replace("out", str(c) + "f")
	print("gen_recursive_conditional done")

	print("remap_jumps start")
	remap_jmps()
	print("remap_jumps done")

	print(answer, end="")

if __name__ == "__main__":
	main()
