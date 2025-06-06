; Copyright 2002-2019 Intel Corporation.
; 
; This software is provided to you as Sample Source Code as defined in the accompanying
; End User License Agreement for the Intel(R) Software Development Products ("Agreement")
; section 1.L.
; 
; This software and the related documents are provided as is, with no express or implied
; warranties, other than those that are expressly stated in the License.

include asm_macros.inc

PROLOGUE

PUBLIC CheckFlags

.code

CheckFlags PROC
    BEGIN_STACK_FRAME
    push    GDI_REG
    push    GSI_REG
    ; Set the ZF and OF flags.
    mov     RETURN_REG, 2147483648
    shl     RETURN_REG, 32
    shl     RETURN_REG, 1
    ; Save the flags register before the analysis routine.
    NATIVE_SIZE_SUFFIX pushf
    pop     GDI_REG
    mov     RETURN_REG, PARAM1
    mov     [RETURN_REG], edi
    ; The tool will create an artificial RTN here and add instrumentation.
    ; Save the flags register after the analysis routine.
    NATIVE_SIZE_SUFFIX pushf
    pop     GSI_REG
    mov     RETURN_REG, PARAM2
    mov     [RETURN_REG], esi
    ; Compare the flags before and after the analysis routine.
    cmp     esi, edi
    jnz     endcheckflags
    ; GAX is not zero since it holds a valid address on the stack. If the flags are identical, indicate success.
    mov     RETURN_REG, 0
endcheckflags:
    pop     GSI_REG
    pop     GDI_REG
    END_STACK_FRAME
    ret
CheckFlags ENDP

end
