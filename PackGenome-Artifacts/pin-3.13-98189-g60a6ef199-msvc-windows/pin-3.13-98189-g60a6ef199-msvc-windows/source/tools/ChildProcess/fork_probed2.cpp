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

#include "pin.H"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
using std::ios_base;
using std::ofstream;
using std::cerr;
using std::string;
using std::endl;

/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "fork_probed2.out", "specify file name");

ofstream Out;

void (*free_memory_ptr)(void) = NULL;

/* ===================================================================== */

INT32 Usage()
{
    cerr <<
        "This pin tool tests probe replacement.\n"
        "\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}

pid_t activeProcessId = 0;
pid_t parentPid = 0;

void BeforeFork(UINT32 childPid, void *data)
{
    parentPid = PIN_GetPid();
    Out << "TOOL: Before fork.." << endl;
}

void AfterForkInParent(UINT32 childPid, void *data)
{
    activeProcessId = PIN_GetPid();
    Out << "TOOL: After fork in parent." << endl;
}

void AfterForkInChild(UINT32 childPid, void *data)
{
    activeProcessId = PIN_GetPid();
    Out << "TOOL: After fork in child." << endl;
    ASSERTX(NULL != free_memory_ptr);
    free_memory_ptr();
}

BOOL FollowChild(CHILD_PROCESS childProcess, VOID * userData)
{
    if (PIN_GetPid() == parentPid)
    {
        Out << "TOOL: At follow child callback in parent process." << endl;
    }
    else
    {
        Out << "TOOL: At follow child callback in child process." << endl;
    }
    // Pin replaces vfork with fork. In this case the global variable
    // activeProcessId will receive the right value
    if (activeProcessId != PIN_GetPid())
    {
        fprintf(stderr, "vfork works incorrectly with -follow_execv\n");
        exit(-1);
    }
    return TRUE;
}

VOID Image(IMG img, VOID* arg)
{
    if (IMG_IsMainExecutable(img))
    {
        RTN free_memory_rtn = RTN_FindByName(img, "free_memory");
        ASSERTX(RTN_Valid(free_memory_rtn));
        free_memory_ptr = (void(*)(void))RTN_Address(free_memory_rtn);
    }
}

int main(int argc, CHAR *argv[])
{
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    string outFileName = KnobOutputFile.Value() + string("_") + decstr(PIN_GetPid());
    Out.open(outFileName.c_str(), ios_base::app);
    if (!Out.is_open()) 
    {
        cerr << "Can't open file " <<  outFileName << endl;
        exit(-1);
    }
    cerr << "Open file " <<  outFileName << endl;

    IMG_AddInstrumentFunction(Image, NULL);
    PIN_AddForkFunctionProbed(FPOINT_BEFORE, BeforeFork, 0);
    PIN_AddForkFunctionProbed(FPOINT_AFTER_IN_CHILD, AfterForkInChild, 0);
    PIN_AddForkFunctionProbed(FPOINT_AFTER_IN_PARENT, AfterForkInParent, 0);
    PIN_AddFollowChildProcessFunction(FollowChild, 0);

    PIN_StartProgramProbed();

    return 0;
}
