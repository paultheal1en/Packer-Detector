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
.global cmpxchg8_base
cmpxchg8_base:
    push %ebp
    mov %esp, %ebp
    push %ebx
    push %ecx
    push %edx
    push %esi

    mov 8(%ebp), %esi
    mov $0x1, %eax
    mov $0x1, %edx
    mov $0x2, %ebx
    mov $0x2, %ecx

    cmpxchg8b (%esi)
    jz success1

fail1:
    mov $0, %eax
    jmp end1

success1:
    mov $1, %eax

end1:
    pop %esi
    pop %edx
    pop %ecx
    pop %ebx
    leave
    ret

.global cmpxchg8_plus8
cmpxchg8_plus8:
    push %ebp
    mov %esp, %ebp
    push %ebx
    push %ecx
    push %edx
    push %esi

    mov 8(%ebp), %esi
    mov $0x1, %eax
    mov $0x1, %edx
    mov $0x2, %ebx
    mov $0x2, %ecx

    cmpxchg8b 8(%esi)
    jz success2

fail2:
    mov $0, %eax
    jmp end2

success2:
    mov $1, %eax

end2:
    pop %esi
    pop %edx
    pop %ecx
    pop %ebx
    leave
    ret

.global cmpxchg8_esp
cmpxchg8_esp:
    push %ebp
    mov %esp, %ebp
    push %ebx
    push %ecx
    push %edx
    push %esi

    mov $0x1, %eax
    mov $0x1, %edx
	
    lea  8(%esp),%esp
    mov %eax,(%esp)
    mov %edx,4(%esp)
	
    mov $0x2, %ebx
    mov $0x2, %ecx

    cmpxchg8b (%esp)
    jz success3

fail3:
    mov $0, %eax
    jmp end3

success3:
    mov $1, %eax

end3:
    lea  -8(%esp),%esp
    pop %esi
    pop %edx
    pop %ecx
    pop %ebx
    leave
    ret
	
