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

 
// Encapsulating all floating point operations within the Pintool
// replacement function inside "fxsave; emms" and "fxrstor" causes
// a seg fault.
//
// Robert reproduced this problem on vs-lin64-3. The problem is
// that the stack pointer is not properly aligned in the replacement
// routine and you get a segv trying to save an xmm to memory.
//
// (gdb) x/i$pc
// 0x2a96429676:	movaps XMMWORD PTR [rax-0x7f],xmm0
// (gdb) p/x $rax-0x7f
// $2 = 0x2a9816b8b8
//
// At the entry point, it should be 8 mod 16, but it is 0 mod 16. 

#include <stdio.h>

void print (int x);

void print(int x)
{
    printf("old print: %d\n", x);
}


int main(void)
{
    print(3.3);
    fprintf(stdout, "main:%6.2f\n", 3.3);

    return 0;
}
