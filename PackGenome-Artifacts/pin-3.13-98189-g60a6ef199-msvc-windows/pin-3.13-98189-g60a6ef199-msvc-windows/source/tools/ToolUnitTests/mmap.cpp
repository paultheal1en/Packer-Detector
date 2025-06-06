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

//
// Pin doesn't allow calling PIN API functions before the tool's "main"
// function is been called. But mmap has special handling. This test
// calls mmap from a constructor of a static object, hence it is called
// when the tool is loaded (i.e. before pin has a chance to call "main").
//

#include <iostream>
#include <errno.h>
#include <sys/mman.h>
#include "pin.H"

static void *gptr = 0;

class TestMMap {
public:
    TestMMap() 
    {
        gptr = mmap(0, 4*1024, PROT_READ, MAP_PRIVATE|MAP_ANON, -1, 0);
    }
};

static TestMMap testMmap;


int main(INT32 argc, CHAR **argv)
{
    PIN_Init(argc, argv);

    void *p = mmap(0, 4*1024, PROT_READ, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (p == MAP_FAILED || gptr == MAP_FAILED)
    {
        std::cerr << "mmap has failed" << std::endl;
        return 1;
    }

    if (gptr == 0)
    {
        std::cerr << "ctor was not called" << std::endl;
        return 1;
    }

    PIN_StartProgram();
    return 0;
}
