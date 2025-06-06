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

#include <iostream>
#include <fstream>
#include <assert.h>
#include "pin.H"


#include "instrumentation_order_app.h"
using std::ofstream;
using std::string;
using std::endl;

// A knob for defining the output file name
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "instrumentation_order20.out",
                            "specify file name for instrumentation order output");

// ofstream object for handling the output.
ofstream outstream;


static VOID WatchRtnReplacement(const CONTEXT *context, THREADID tid, AFUNPTR origWatchRtn, int origArg)
{
    
    outstream << "WatchRtnReplacement" << endl;
    PIN_CallApplicationFunction(context, tid, CALLINGSTD_DEFAULT, origWatchRtn, NULL,
                                PIN_PARG(int), origArg, PIN_PARG_END());
}


void Emit(char const* message)
{
    outstream << message << endl;
}

static VOID Instruction(INS ins, VOID *v)
{
    RTN rtn = INS_Rtn(ins);
    
    if (!RTN_Valid(rtn) || RTN_Name(rtn) != watch_rtn)
    {
        return;
    }

    if (INS_Address(ins) == RTN_Address(rtn)) 
    {
        // Pin does not support issuing an RTN_ReplaceSignature from the INS instrumentation callback
        // This will cause Pin to terminate with an error

        PROTO proto_watch_rtn 
            = PROTO_Allocate(PIN_PARG(void), CALLINGSTD_DEFAULT, "watch_rtn", PIN_PARG(int), PIN_PARG_END());

        RTN_ReplaceSignature(rtn, AFUNPTR(WatchRtnReplacement),
            IARG_PROTOTYPE, proto_watch_rtn,
            IARG_CONST_CONTEXT,
            IARG_THREAD_ID,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_END);
    }

}


static VOID Fini(INT32 code, VOID *v)
{
    outstream.close();
}

int main(int argc, char * argv[])
{
    PIN_InitSymbols();
    PIN_Init(argc, argv);

    outstream.open(KnobOutputFile.Value().c_str());

    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
