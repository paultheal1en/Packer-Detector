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
    .align 4
.globl loadYmm0
loadYmm0:
    mov     4(%esp), %ecx

    /*
     * This is "VMOVDQU ymm0, YMMWORD PTR [ecx]".  We directly specify the machine code,
     * so this test runs even when the compiler doesn't support AVX512.
     */
    .byte   0xc5, 0xfe, 0x6f, 0x01

.globl loadYmm0Breakpoint
loadYmm0Breakpoint:         /* Debugger puts a breakpoint here */
    ret

.globl loadZmm0
loadZmm0:
    mov     4(%esp), %ecx

    /*
     * This is "VMOVUPD zmm0, ZMMWORD PTR [ecx]".  We directly specify the machine code,
     * so this test runs even when the compiler doesn't support AVX512.
     */
    .byte   0x62, 0xf1, 0xfd, 0x48, 0x10, 0x01

.globl loadZmm0Breakpoint
loadZmm0Breakpoint:         /* Debugger puts a breakpoint here */
    ret

.globl loadK0
loadK0:
    mov     4(%esp), %ecx

    /*
     * This is "KMOVW k0, WORD PTR [ecx]".  We directly specify the machine code,
     * so this test runs even when the compiler doesn't support AVX512.
     */
    .byte   0xc5, 0xf8, 0x90, 0x01

.globl loadK0Breakpoint
loadK0Breakpoint:         /* Debugger puts a breakpoint here */
    ret
