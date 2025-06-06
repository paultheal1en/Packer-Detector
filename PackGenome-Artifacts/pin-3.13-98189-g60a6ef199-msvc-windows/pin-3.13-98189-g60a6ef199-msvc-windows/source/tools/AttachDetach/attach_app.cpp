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

/* ===================================================================== */
/*! @file
 *
 * This application starts Pin and waits for it to attach. Unlike mt_attach
 * this application does not do any multi-threading, which is useful for
 * testing startup stuff.
 */

#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <assert.h>
#include <pthread.h>
using std::list;
using std::string;


static intptr_t secondaryThread = 0;

/* Pin doesn't kill the process if if failed to attach, exit on SIGALRM */
void ExitOnAlarm(int sig)
{
    fprintf(stderr, "Pin is not attached, exit on SIGALRM\n");
	exit(0);
}

extern "C" int PinAttached()
{
	return 0;
}

void PrintArguments(char **inArgv)
{
    fprintf(stderr, "Going to run: ");
    for(unsigned int i=0; inArgv[i] != 0; ++i)
    {
        fprintf(stderr, "%s ", inArgv[i]);
    }
    fprintf(stderr, "\n");
}

/*
 * Expected command line: <this exe> [-th_num NUM] -pin $PIN -pinarg <pin args > -t tool <tool args>
 */

void ParseCommandLine(int argc, char *argv[], list < string>* pinArgs)
{
    string pinBinary;
    for (int i=1; i<argc; i++)
    {
        string arg = string(argv[i]);
        if (arg == "-secondary-threads")
        {
            secondaryThread = (intptr_t)atoi(argv[++i]);
        }
        else if (arg == "-pin")
        {
            pinBinary = argv[++i];
        }
        else if (arg == "-pinarg")
        {
            for (int parg = ++i; parg < argc; parg++)
            {
                pinArgs->push_back(string(argv[parg]));
                ++i;
            }
        }
    }
    assert(!pinBinary.empty());
    pinArgs->push_front(pinBinary);
}

void StartPin(list <string>* pinArgs)
{
    pid_t appPid = getpid();
    pid_t child = fork();
    if (child != 0)
        return;

    /* here is the child */
    // sleeping to give the parent time to diminish its privileges.
    sleep(2);
    printf("resumed child \n");

    // start Pin from child
    char **inArgv = new char*[pinArgs->size()+10];

    // Pin binary in the first
    list <string>::iterator pinArgIt = pinArgs->begin();
    string pinBinary = *pinArgIt;
    pinArgIt++;

    // build pin arguments:
    unsigned int idx = 0;
    inArgv[idx++] = (char *)pinBinary.c_str();
    inArgv[idx++] = (char*)"-pid";
    inArgv[idx] = (char *)malloc(10);
    sprintf(inArgv[idx++], "%d", appPid);

    for (; pinArgIt != pinArgs->end(); pinArgIt++)
    {
        inArgv[idx++]= (char *)pinArgIt->c_str();
    }
    inArgv[idx] = 0;

    PrintArguments(inArgv);

    execvp(inArgv[0], inArgv);
    fprintf(stderr, "ERROR: execv %s failed\n", inArgv[0]);

    exit(1);
}

extern "C" void* ThreadMain(void* arg)
{
    return NULL;
}

int main(int argc, char * argv[])
{
    int i;
	
    list <string> pinArgs;

    ParseCommandLine(argc, argv, &pinArgs);

    StartPin(&pinArgs);

    /* Exit in 20 sec */
    signal(SIGALRM, ExitOnAlarm);
    alarm(20);

    printf("Before pause, waiting on PinAttached\n");

    while (!PinAttached())
    {
        sched_yield();
        sleep(2);
    }
    pthread_t* threads = new pthread_t[secondaryThread];
    for (intptr_t i = 0; i < secondaryThread; i++)
    {
        pthread_create(&threads[i], NULL, ThreadMain, (void*)i);
    }
    for (intptr_t i = 0; i < secondaryThread; i++)
    {
        void* value;
        pthread_join(threads[i], &value);
        assert((intptr_t)value == i);
    }
    printf("After pause\n");

    return 0;
}
/*
 *  eof
 */
