; Copyright 2002-2019 Intel Corporation.
; 
; This software is provided to you as Sample Source Code as defined in the accompanying
; End User License Agreement for the Intel(R) Software Development Products ("Agreement")
; section 1.L.
; 
; This software and the related documents are provided as is, with no express or implied
; warranties, other than those that are expressly stated in the License.

PUBLIC SupportsAvx512f

.code
SupportsAvx512f PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    mov     rax, 1
    cpuid
    and ecx, 0018000000h
    cmp ecx, 0018000000h
    jne $lNOT_SUPPORTED
    mov ecx, 0

    BYTE 00Fh
    BYTE 001h
    BYTE 0D0h
    and eax, 0e6h
    cmp eax, 0e6h
    jne $lNOT_SUPPORTED
    mov ecx, 0
    mov     rax, 7
    cpuid
    and ebx, 010000h
    cmp ebx, 010000h
    jne $lNOT_SUPPORTED
    mov rax, 1
    jmp $lDONE3
$lNOT_SUPPORTED:
    mov rax, 0
$lDONE3:
    pop    rsi
    pop    rdx
    pop    rcx
    pop    rbx

    mov     rsp, rbp
    pop     rbp
    ret
SupportsAvx512f ENDP

end
