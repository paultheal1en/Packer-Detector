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

/*
 * This test verifies Pin's handling of two weird instructions:
 * "call *%rsp" and "jmp *%rsp".
 */

	.text
.global SetAppFlags_asm
.type SetAppFlags_asm, @function


SetAppFlags_asm:

    push %rbp
	mov  %rsp, %rbp
    pushfq
    pop %rax
    or %rcx, %rax
    push %rax
    popfq
    leave
    ret


.global ClearAcFlag_asm
.type ClearAcFlag_asm, @function
ClearAcFlag_asm: 

    
    pushfq
    pop %rcx
    and $0xfffbffff, %rcx
    push %rcx
    popfq
    ret

    .align 4
.globl GetFlags_asm
.type GetFlags_asm, @function
GetFlags_asm:
    pushfq
    pop %rax
    ret
