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
.global ToolRaiseAccessInvalidAddressException
.type ToolRaiseAccessInvalidAddressException, @function
.global ToolCatchAccessInvalidAddressException
.type ToolCatchAccessInvalidAddressException, @function
.global ToolIpAccessInvalidAddressException
.type ToolIpAccessInvalidAddressException, @function

ToolRaiseAccessInvalidAddressException:
    push %ebp
    mov %esp, %ebp
    push %esi
    push %edi
    mov 0x8(%ebp), %eax # addresses array
    mov 0xc(%ebp), %esi # value
    mov (%eax), %edi
try_again:
ToolIpAccessInvalidAddressException:
    mov %esi, (%edi) # *addr = value - if addr is invalid, exception is raised
    pop %edi
    pop %esi
    leave
    ret

ToolCatchAccessInvalidAddressException:
    mov 4(%eax), %edi
    jmp try_again
    

.text
# void ToolRaiseIntDivideByZeroException(catch_ptr, exception_code)

.global ToolRaiseIntDivideByZeroException
.global ToolIpIntDivideByZeroException
.type ToolRaiseIntDivideByZeroException, @function
.global ToolCatchIntDivideByZeroException

ToolRaiseIntDivideByZeroException:
    push %ebp
    mov %esp, %ebp
    push %ebx # save ebx
    push %esi #save esi
    mov 0x8(%ebp), %ebx # fptr
    mov 0xc(%ebp), %esi # except code
    push %esi
    xor %eax, %eax
ToolIpIntDivideByZeroException:
    idiv %eax
ToolCatchIntDivideByZeroException:
    pop %eax
    pop %esi
    pop %ebx
    leave
    ret
    
    
