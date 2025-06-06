; Copyright 2002-2019 Intel Corporation.
; 
; This software is provided to you as Sample Source Code as defined in the accompanying
; End User License Agreement for the Intel(R) Software Development Products ("Agreement")
; section 1.L.
; 
; This software and the related documents are provided as is, with no express or implied
; warranties, other than those that are expressly stated in the License.

PUBLIC TestAccessViolations


.686
.model flat, c
.XMM

.code


TestAccessViolations PROC
    push ebx
    push ebp
    push edi
    push esi 
    xor ebx, ebx
    xor edx, edx

    mov eax, 1234h
    mov ecx, 2345h
    mov ebp, 0abcdh
    mov edi, 0bcdeh
    mov esi, 0cdefh

    cmpxchg8b QWORD PTR [edx]
    
    cmp eax, 1234h
    jne ErrorLab
    cmp ecx, 2345h
    jne ErrorLab
    cmp ebx, 0
    jne ErrorLab
    cmp edx, 0
    jne ErrorLab
    cmp ebp, 0abcdh
    jne ErrorLab
    cmp edi, 0bcdeh
    jne ErrorLab
    cmp esi, 0cdefh
    jne ErrorLab
    

    mov eax, 3456h
    mov ecx, 4567h

    xlat
    
    cmp eax, 3456h
    jne ErrorLab
    cmp ecx, 4567h
    jne ErrorLab
    cmp ebx, 0
    jne ErrorLab
    cmp edx, 0
    jne ErrorLab
    cmp ebp, 0abcdh
    jne ErrorLab
    cmp edi, 0bcdeh
    jne ErrorLab
    cmp esi, 0cdefh
    jne ErrorLab


    mov eax, 5678h
    mov ecx, 6789h

    cmpxchg8b QWORD PTR [ebx]

    cmp eax, 5678h
    jne ErrorLab
    cmp ecx, 6789h
    jne ErrorLab
    cmp ebx, 0
    jne ErrorLab
    cmp edx, 0
    jne ErrorLab
    cmp ebp, 0abcdh
    jne ErrorLab
    cmp edi, 0bcdeh
    jne ErrorLab
    cmp esi, 0cdefh
    jne ErrorLab

    mov eax, 1
    jmp RetLab

ErrorLab:
    mov eax, 0
RetLab:
    pop esi
    pop edi
    pop ebp
    pop ebx	
    ret
TestAccessViolations ENDP
    

end
