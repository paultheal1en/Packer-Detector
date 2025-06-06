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

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#ifdef TARGET_WINDOWS
// declare all functions as exported so pin can find them,
// must be all functions since only way to find end of one function is the begining of the next
// Another way is to compile application with debug info (Zi) - pdb file, but that causes probelms
// in the running of the script 
#define EXPORT_SYM __declspec( dllexport )
#else
#define EXPORT_SYM
#endif


EXPORT_SYM
void foobar(int a, int b)
{
}

EXPORT_SYM
void baz(int arg1, int arg2, int arg3)
{
    printf("Arg1 %x\n",arg1);
    printf("Arg2 %x\n",arg2);
    printf("Arg3 %x\n",arg3);
    if (arg1 != 4
        || arg2 != 5
        || arg3 != 6)
        exit(1);
}

EXPORT_SYM
int main()
{
    foobar(0x0eadbeef,0x0eedfeed);
    baz(1,2,3);
    return 0;
}
