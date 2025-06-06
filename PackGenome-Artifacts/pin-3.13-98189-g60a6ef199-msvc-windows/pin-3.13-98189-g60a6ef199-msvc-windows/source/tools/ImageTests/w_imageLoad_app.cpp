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
#include <stdlib.h>
#include <errno.h>
#include <windows.h>
#include <string>
#include <iostream>

#define EXPORT_SYM extern "C" __declspec( dllexport )

EXPORT_SYM int AfterAttach();

const char * FIRST_DLL_NAME = "my_dll.dll";

const char * SECOND_DLL_NAME = "my_dll_1.dll";

enum ExitType {
    RES_SUCCESS = 0,  //0
    RES_LOAD_FAILED,  //1
};


/**************************************************/

void WindowsOpen(const char* filename)
{
    HMODULE hdll = LoadLibrary(filename);
    if(hdll == NULL)
    {
        fflush(stderr);
        exit(RES_LOAD_FAILED);
    }
    FreeLibrary(hdll);
}

int AfterAttach()
{
    // Pin sets an anslysis function here to notify the application when Pin attaches to it.
    return 0;
}


int main()
{
    WindowsOpen(FIRST_DLL_NAME);
    while(!AfterAttach())
    {
        Sleep(1*1000);
    }
    WindowsOpen(SECOND_DLL_NAME);
    return RES_SUCCESS;
}
