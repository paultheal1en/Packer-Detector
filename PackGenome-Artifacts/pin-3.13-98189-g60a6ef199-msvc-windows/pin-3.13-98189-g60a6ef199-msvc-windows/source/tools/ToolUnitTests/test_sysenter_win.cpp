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
 This tests that after emulation of sysenter, Pin causes ring3 execution to continue at
 the instruction located at KiFastSystemCallRet: rather than the instruction following sysenter.
 Note: The instruction at KiFastSystemCallRet: is ret
 */

int main()
{
    __asm mov eax, 0x0777 // 777 is an invalid syscall number
	// push the address that the ret instruction KiFastSystemCallRet will use as a
	// return address onto the stack
    __asm push inst_to_execute_after_sysenter
	// copy esp into edx as required by sysenter
    __asm mov edx, esp
    __asm _emit 0fh  // 0F34 = sysenter
    __asm _emit 34h
	// next 2 instructions should NOT be executed
	__asm xor ecx,ecx
	__asm mov ecx,[ecx]
	// the instruction at KiFastSystemCallRet is ret, and that ret will return to the following
	// instruction
    __asm inst_to_execute_after_sysenter:
    __asm mov eax, 0x0  // instruction that the ret at KiFastSystemCallRet: will return to
}
