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

/*!
 *  This application branch into the vsyscall area (used only in 64 bits)
 *  Used for testing Pin handling when application branch into that area
 */

#include <iostream>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>
using std::cout;
using std::endl;

#define VSYSCALL_GETTIMEOFDAY_ADDRESS   0xffffffffff600000

struct timeval startTime, endTime;

typedef long (*vsyscall_gettimeofday_t)(struct timeval*, struct timezone*);
const vsyscall_gettimeofday_t vgtod = (vsyscall_gettimeofday_t)(VSYSCALL_GETTIMEOFDAY_ADDRESS);

//vsyscall time address is 0xffffffffff600400
//vsyscall getcpu address is 0xffffffffff600800

int main( int argc, char *argv[] )
{
    int ret = 0;

    ret = vgtod(&startTime, NULL);
    assert(ret==0);

    sleep(1);
    ret = vgtod(&endTime, NULL);
    assert(ret==0);

    long time_spent = ((endTime.tv_sec * 1000000 + endTime.tv_usec) - (startTime.tv_sec * 1000000 + startTime.tv_usec));
    cout << time_spent << endl;

    // Done.
    cout << "APP: Application completed successfully." << endl;
    return 0;
}
