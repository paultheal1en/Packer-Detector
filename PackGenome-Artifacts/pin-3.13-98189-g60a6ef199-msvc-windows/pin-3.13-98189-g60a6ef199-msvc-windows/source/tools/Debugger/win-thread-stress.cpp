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
 * A stress test for threads on Windows.  Create a bunch of threads and let them
 * exit at the same time.
 */

#include <windows.h>
#include <iostream>

static DWORD WINAPI Child(LPVOID);

HANDLE GoEvent;
const unsigned NumThreads = 50;


int main()
{
    GoEvent = CreateEvent(0, TRUE, FALSE, 0);
    if (!GoEvent)
    {
        std::cerr << "Unable to create GO event\n";
        return 1;
    }

    HANDLE *threadHandles = new HANDLE[NumThreads];
    for (unsigned i = 0;  i < NumThreads;  i++)
    {
        HANDLE h = CreateThread(0, 0, Child, 0, 0, 0);
        if (!h)
        {
            std::cerr << "Unable to create child thread\n";
            return 1;
        }
        threadHandles[i] = h;
    }

    // All the threads are waiting on this event.  Tell them all to go simultaneously.
    //
    if (!SetEvent(GoEvent))
    {
        std::cerr << "Error from SetEvent\n";
        return 1;
    }

    DWORD ret = WaitForMultipleObjects(NumThreads, threadHandles, TRUE, INFINITE);
    if (ret != WAIT_OBJECT_0)
    {
        std::cerr << "Failure while waiting for child threads to terminate\n";
        return 1;
    }

    delete threadHandles;
    return 0;
}

static DWORD WINAPI Child(LPVOID)
{
    WaitForSingleObject(GoEvent, INFINITE);
    return 0;
}
