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

    .text
.globl One
    .type   One, @function
One:
    /*
     * We force the thread to get an ASYNC_BREAK on this instruction, which is the
     * target of an indirect jump.
     */
    jmp     *%rdi

    /*
     * The tool should change the PC to Two() when the ASYNC_BREAK occurs, so the
     * rest of this function should be skipped.
     */
    movl    $1, %eax
    ret


.globl Two
    .type   Two, @function
Two:
    movl    $2, %eax
    ret


.globl GetValue
    .type   GetValue, @function
GetValue:
    call    *%rdi
    ret


.globl Breakpoint
    .type   Breakpoint, @function
Breakpoint:
    mov     $0, %rax
.L1:
    add     $1, %rax
    cmp     $99999999, %rax
    jbe     .L1

    /*
     * The debugger places a breakpoint here, but the tool intercepts the BREAKPOINT event.
     * If the breakpoint triggers before the other thread enters the One() function, the tool
     * squashes the breakpoint and moves the PC back to the start of Breakpoint().  The delay
     * loop waits a while, and then the breakpoint re-triggers.  This repeats until the other
     * thread is at the first instruction in One(), so the breakpoint is guaranteed to trigger
     * when the other thread is at that instruction.
     */
.globl BreakpointLocation
    .type   BreakpointLocation, @function
BreakpointLocation:
    nop

    ret
