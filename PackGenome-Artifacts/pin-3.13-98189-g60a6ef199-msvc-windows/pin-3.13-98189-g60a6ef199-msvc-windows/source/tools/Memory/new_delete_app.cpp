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

#ifdef TARGET_WINDOWS
#include <windows.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "../Utils/threadlib.h"
#include "atomic.hpp"

#define NUM_TH 16
#define LOOPS 5000000

volatile size_t numThreads = 0;

void *compute(void *ptr)
{
    size_t newptr = (size_t) ptr;
    size_t i = 0, start_count = newptr;

#ifdef TARGET_IA32
    printf("Thread start %ld %ld\n", newptr, start_count);
#else
    printf("Thread start %lld %lld\n", newptr, start_count);
#endif

    ATOMIC::OPS::Increment<size_t>(&numThreads, 1);

    for (i = 0; i < start_count; i++)
        newptr += (i + newptr);

    printf("Thread end %lld\n", newptr);
    return (void*) newptr;
}

THREAD_HANDLE threads[MAXTHREADS];

int main()
{

    for (int i = 0; i < NUM_TH; i++)
        CreateOneThread(&threads[i], compute, (void*) (LOOPS + i));

    while (numThreads != NUM_TH)
    {
        DelayCurrentThread(10);
    }
    printf("All threads started running\n");
    fflush(stdout);

    for (int i = 0; i < NUM_TH; i++)
        JoinOneThread(threads[i]);

    exit(0);
}

