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
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "instrumentation_order19.out",
                            "specify file name for instrumentation order output");

// ofstream object for handling the output.
ofstream outstream;


void Emit(char const* message)
{
    outstream << message << endl;
}

static VOID Rtn(RTN rtn, VOID *v)
{
    if (!RTN_Valid(rtn) || RTN_Name(rtn) != watch_rtn)
    {
        return;
    }
    printf("Rtn Instrumenting %s\n", watch_rtn);
    RTN_Open(rtn);
    INS ins = RTN_InsHeadOnly(rtn);
    ASSERTX (INS_Valid(ins));
    
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Emit),
                             IARG_PTR, "RTN instrumentation2",  IARG_CALL_ORDER, CALL_ORDER_FIRST+3, IARG_END);
    RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(Emit),
                             IARG_PTR, "RTN instrumentation1",  IARG_CALL_ORDER, CALL_ORDER_FIRST+3, IARG_END);
    RTN_Close(rtn);
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

    RTN_AddInstrumentFunction(Rtn, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
