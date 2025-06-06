/*
 * Copyright 2002-2019 Intel Corporation.
 * 
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 * 
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

	.intel_syntax noprefix
	.text
# RTN of size 200000 tickled a bug in symbol handling	
.globl big
	.type	big, @function
big:
	.space 200000
	
.globl main
	.type	main, @function
main:
	call xlat
	mov ecx, 16
loop1:
	nop
	loop  loop1

	mov ecx, 16
	mov eax, 0
	cmp eax,0
loop2:
	nop
	loope  loop2

	mov ecx, 16
	mov eax, 1
	cmp eax, 0	
loop3:	
	nop
	loopne  loop3

	mov eax, 0
	ret

xlat:
	movb [table+0],0
	movb [table+1],1
	movb [table+2],2
	movb [table+256+0],7
	movb [table+256+1],8
	movb [table+256+2],9
	lea ebx,[table]
	mov eax,256+1
	xlat
	ret
	
.data
table:
	.space 512
	
	
	
		
