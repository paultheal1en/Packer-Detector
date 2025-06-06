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
.globl main
.type	main, function
main:
	call test1
	mov eax, 0
	ret

.globl test1
.type   test1, function
test1:
	xor eax, eax
	cmp eax, 0
	je bye
	# the following code will never executed

    # INS_FullRegRContain & INS_MemoryIndexReg test
    add byte ptr [eax + ecx*4], al

    # INS_IsInterrupt test
    int 0x80

    # INS_IsRDTSC test
    rdtsc

    # INS_IsXchg test
    xchg ebx, edi

    # INS_IsSysret test
    sysret

    # INS_IsDirectFarJump test
    # instead of "ljmp 0xabcd:0x14":
    .byte 0xea
    .byte 0x14
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0xcd
    .byte 0xab

bye:
	ret

.data
val: .long 10

