#!/bin/bash
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

# Case generator

get_w_sse4_1() {
	echo "---"
	for wi in $(seq 0 63) ; do
		RI=$((${wi} / 4))
		CI=$((${wi} % 4))
		echo -e "case ${wi}: GET_W(w,${CI},xmm${RI}); break;"
	done
}

get_w_sse4_1

get_w_sse2() {
	echo "---"
	MMR=3
	for wi in $(seq 0 63) ; do
		if (( ${wi} <= 59 )) ; then
			RI=$((${wi} / 4))
			CI=$(($((${wi} % 4)) * 4))
			echo -e "case ${wi}: GET_W(w,${CI},xmm${RI},xmm15); break;"
		fi
		if (( ${wi} >= 60 )) ; then
			PARITY=$(( ${wi} % 2 ))
			if (( ${PARITY} == 0 )) ; then
				MMR=$((${MMR} + 1))
				echo -e "case ${wi}: GET_W_ALT_C0(w,mm${MMR}); break;"
			else
				echo -e "case ${wi}: GET_W_ALT_C1(w,mm${MMR},gpr); break;"
			fi
		fi
	done
}

get_w_sse2

set_w_sse4_1() {
	echo "---"
	for wi in $(seq 0 63) ; do
		RI=$((${wi} / 4))
		CI=$((${wi} % 4))
		echo -e "case ${wi}: SET_W(w,${CI},xmm${RI}); break;"
	done
}

set_w_sse4_1

set_w_sse2() {
	echo "---"
	echo "---"
	MMR=3
	for wi in $(seq 0 63) ; do
		if (( ${wi} <= 59 )) ; then
			RI=$((${wi} / 4))
			CI=$(($((${wi} % 4)) * 4))
			echo -e "case ${wi}: SET_W(w,${CI},xmm${RI},xmm15,gpr0); break;"
		fi
		if (( ${wi} >= 60 )) ; then
			PARITY=$(( ${wi} % 2 ))
			if (( ${PARITY} == 0 )) ; then
				MMR=$((${MMR} + 1))
				echo -e "case ${wi}: SET_W_ALT(w,0,mm${MMR},gpr0,gpr1); break;"
			else
				echo -e "case ${wi}: SET_W_ALT(w,32,mm${MMR},gpr0,gpr1); break;"
			fi
		fi
	done
}

set_w_sse2


insert_W_byte_sse4_1() {
	echo "---"
	for wi in $(seq 0 255) ; do
		RI=$((${wi} / 16))
		CI=$((${wi} % 16))
		echo -e "case ${wi}: INSERT_BYTE(${CI},c,xmm${RI}); break;"
	done
}

insert_W_byte_sse4_1


insert_W_byte_sse2() {
	echo "---"
	MMR=3
	for wi in $(seq 0 255) ; do
		if (( ${wi} <= 239 )) ; then
			RI=$((${wi} / 16))
			CI=$((${wi} % 16))
			echo -e "case ${wi}: INSERT_BYTE(${CI},c,xmm${RI}); break;"
		fi
		if (( ${wi} >= 240 )) ; then
			CI=$((${wi} % 8))
			if (( ${CI} == 0 )) ; then
				MMR=$((${MMR} + 1))
			fi
			echo -e "case ${wi}: INSERT_BYTE_ALT(${CI},c,mm${MMR},gpr0,gpr1); break;"
		fi
	done
}

insert_W_byte_sse2
