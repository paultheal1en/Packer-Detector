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

#define _WIN32_WINNT  0x0400 

#include <Windows.h>
#include <stdio.h>
#define EXPORT_SYM __declspec( dllexport ) 

int beenHere = 0;

// perform recursive APC - 
// add APC to the thread queue and go to alertable sleep
extern "C" 
EXPORT_SYM
VOID CALLBACK My_APCProc(ULONG_PTR dwParam)
{
    beenHere++;
    if(dwParam == 1)
    {
        return;
    }
    QueueUserAPC(My_APCProc, GetCurrentThread() , dwParam - 1);
    DWORD status = SleepEx(INFINITE , true);
    printf("SleepEx status = 0x%x \n" ,status);
    fflush(stdout);
}

int QueueApc()
{ 
    int recursiveDepth = 10;
    QueueUserAPC(My_APCProc, GetCurrentThread() , recursiveDepth);
    DWORD status = SleepEx(INFINITE , true);
    printf("SleepEx status = 0x%x \n" ,status);
    printf("Number of visits in My_APCProc = %d \n" ,beenHere);
    fflush(stdout);
    return 0;
}

int main()
{
    QueueApc();
    return 0;
}