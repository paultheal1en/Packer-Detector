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
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "instrumentation_order12.out",
                            "specify file name for instrumentation order output");

// ofstream object for handling the output.
ofstream outstream;


void Emit(char const* message)
{
    outstream << message << endl;
}

static VOID Trace(TRACE trace, VOID *v)
{
    RTN rtn = TRACE_Rtn(trace);
    
    if (!RTN_Valid(rtn) || RTN_Name(rtn) != watch_rtn)
    {
        return;
    }

    if (TRACE_Address(trace) == RTN_Address(rtn)) 
    {
        INS ins = BBL_InsHead(TRACE_BblHead(trace));
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Emit),
                             IARG_PTR, "Trace instrumentation3", IARG_END);
        TRACE_InsertCall(trace, IPOINT_BEFORE, AFUNPTR(Emit),
                             IARG_PTR, "Trace instrumentation1", IARG_END);
        BBL_InsertCall(TRACE_BblHead(trace), IPOINT_BEFORE, AFUNPTR(Emit),
                             IARG_PTR, "Trace instrumentation2", IARG_END);
        printf("Trace Instrumenting %s\n", watch_rtn);
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

    TRACE_AddInstrumentFunction(Trace, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
