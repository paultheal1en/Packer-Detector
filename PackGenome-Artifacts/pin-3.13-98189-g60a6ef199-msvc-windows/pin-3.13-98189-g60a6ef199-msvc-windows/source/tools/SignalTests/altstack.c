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
 * This test verifies that the application can set up an alternate stack for
 * its signal handler.
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

char Stack[SIGSTKSZ];

static void Handle(int);


int main()
{
    struct sigaction act;
    stack_t ss;

    ss.ss_sp = Stack;
    ss.ss_size = sizeof(Stack);
    ss.ss_flags = 0;
    if (sigaltstack(&ss, 0) != 0)
    {
        fprintf(stderr, "Unable to set alternate stack\n");
        return 1;
    }
    printf("Alternate stack is %p - %p\n", Stack, &Stack[SIGSTKSZ]);

    act.sa_handler = Handle;
    act.sa_flags = SA_ONSTACK;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGUSR1, &act, 0) != 0)
    {
        fprintf(stderr, "Unable to set up USR1 handler\n");
        return 1;
    }

    raise(SIGUSR1);
    return 0;
}


static void Handle(int sig)
{
    char *sp = (char *)&sig;

    printf("Got signal %d with SP=%p\n", sig, sp);
    if (sp < Stack || sp > &Stack[SIGSTKSZ])
    {
        fprintf(stderr, "Handler not running on alternate stack\n");
        exit(1);
    }
}
