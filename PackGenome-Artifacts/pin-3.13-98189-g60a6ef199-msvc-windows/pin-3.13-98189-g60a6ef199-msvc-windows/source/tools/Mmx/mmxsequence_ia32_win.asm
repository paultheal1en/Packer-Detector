; Copyright 2002-2019 Intel Corporation.
; 
; This software is provided to you as Sample Source Code as defined in the accompanying
; End User License Agreement for the Intel(R) Software Development Products ("Agreement")
; section 1.L.
; 
; This software and the related documents are provided as is, with no express or implied
; warranties, other than those that are expressly stated in the License.

PUBLIC MMXSequence

.386
.XMM
.model flat, c

.code 
MMXSequence PROC
    
    movd        mm0, dword ptr [esp+4]    
    movd        mm1, dword ptr [esp+8] 
    movq        mm7, qword ptr [esp+4]
    movd        mm3, dword ptr [esp+12]   
    pxor        mm2, mm2
    punpcklbw   mm0, mm2
    punpcklbw   mm1, mm2
    punpcklbw   mm3, mm2
    movq        mm5, mm3
    psrlw       mm5, 6
    pcmpeqw     mm4, mm4
    psllw       mm4, 10
    paddw       mm3, mm5
    psubw       mm4, mm3
    pmullw      mm2, mm4
    pmullw      mm1, mm3
    pmullw      mm1, mm3
    psrlw       mm1, 9
    packuswb    mm1, mm1
    mov         ecx, dword ptr [esp+16]
    movq        qword ptr [ecx] , mm7
    movd        eax, mm1
    emms
    ret

MMXSequence ENDP

end
