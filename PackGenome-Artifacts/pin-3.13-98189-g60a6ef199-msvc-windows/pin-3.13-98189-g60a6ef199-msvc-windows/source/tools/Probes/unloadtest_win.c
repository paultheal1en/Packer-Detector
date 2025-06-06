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

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

void Load(char * name, int expect)
{
    int val;
    
    HMODULE handle;
    int (*sym)();
    
    handle = LoadLibrary(name);
    if (handle == 0)
    {
        fprintf(stderr,"Load of %s failed\n",name);
        fflush(stderr);
        exit(1);
    }
    
    sym = (int(*)())GetProcAddress(handle, "one");
    fprintf(stderr, "Address of sym is %p\n",sym);
    fflush(stderr);
    
    if (sym == 0)
    {
        fprintf(stderr,"GetProcAddress() of %s failed\n",name);
        fflush(stderr);
        exit(1);
    }
    
    val = sym();
    if (val != expect)
    {
        fprintf(stderr, "Error: Bad value returned.\n");
        fflush(stderr);
        exit(1);
    } 
}

int main()
{
    
    Load("one.dll", 1);
    Load("two.dll", 2);

    Load("one.dll", 1);
    Load("two.dll", 2);

        
    return 0;
}

