; Copyright 2002-2019 Intel Corporation.
; 
; This software is provided to you as Sample Source Code as defined in the accompanying
; End User License Agreement for the Intel(R) Software Development Products ("Agreement")
; section 1.L.
; 
; This software and the related documents are provided as is, with no express or implied
; warranties, other than those that are expressly stated in the License.

PUBLIC SegAccessRtn


.686
.model flat, c
COMMENT // replacement memory operands with segment registers
ASSUME NOTHING
.code
SegAccessRtn PROC
	push ebp
	mov  ebp, esp
	push ecx
	mov  eax, DWORD PTR [ebp+8h]
	mov  DWORD PTR fs:[10h], eax
	mov  eax, DWORD PTR fs:[10h]
	mov  ecx, 10h
	mov  eax, DWORD PTR fs:[ecx]
	mov  DWORD PTR fs:[14h], 100
	mov  ecx, 10h
	add  eax, DWORD PTR fs:[ecx + 4]	
	pop  ecx
	leave
	ret
	 

SegAccessRtn ENDP

SegAccessStrRtn PROC

	push ebp
	mov  ebp, esp
	push esi
	
	mov  eax, DWORD PTR [ebp+8h]
	mov  DWORD PTR fs:[14h], eax
	mov  esi, 14h
	lods DWORD PTR fs:[esi]
	
	pop esi
	leave
	ret

SegAccessStrRtn ENDP

dummy PROC
    nop
dummy ENDP

end






