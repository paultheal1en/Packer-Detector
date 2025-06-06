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

#include <sched.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>

extern int Add2( int, int );

int a[100000];
int n = 10;

void * hello(void * arg)
{
    int i,j;
    
    for (j = 0; j < 1000; j++)
    {
        for (i = 0; i < n; i++)
        {
            a[i] = 1;
        }
        usleep(1); //This will give up thread control
    }

    return 0;
}


#define MAXTHREADS 1000

int threads_started;

int main(int argc, char *argv[])
{
    int numthreads = 0;
    int i;
    pthread_t threads[MAXTHREADS];
    
#if defined(i386)
    asm("pusha;popa");
#endif    

    numthreads = 20;
    assert(numthreads < MAXTHREADS);
    
    for (threads_started = 0; threads_started < numthreads; threads_started++)
    {
        printf("Creating thread\n");
        fflush(stdout);
        pthread_create(threads+threads_started, 0, hello, 0);
        fflush(stdout);
    }

    for (i = 0; i < numthreads; i++)
    {
        pthread_join(threads[i], 0);
        printf("Joined %d, sum=%d\n", i, Add2(i,i));
    }
    printf("All threads joined\n");

    return 0;
}

