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

/*
 * Demonstrate the multiversioning of traces to support specialization of
 * instrumentation
 *
 * There will be two instrumented copies of watch_rtn
 * The decision about what type of instrumentation to execute depends on the 
 * value of the first argument to this rtn. 
 *
 */

#include "instrumentation_order_app.h"
using std::ofstream;
using std::string;
using std::endl;

enum 
{
    VERSION_BASE,
    VERSION_1,
    VERSION_2
};

// A knob for defining the output file name
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "special_case2.out",
                            "specify file name for special case output");

// ofstream object for handling the output.
ofstream outstream;


/*
 * If the first argument is >= 0, return 1, indicating we should switch to
 * heavyweight instrumentation
 */
static int select_version(int arg)
{
    outstream << "In watch_rtn, arg: " << arg << endl;
    return arg;
}

static REG version_reg;

void Emit(char const* message)
{
    outstream << message << endl;
}

static VOID Trace(TRACE trace, VOID *v)
{
    RTN rtn = TRACE_Rtn(trace);
    
    ADDRINT version = TRACE_Version(trace);
    // If we are not in watch_rtn, switch back to base version
    if (!RTN_Valid(rtn) || RTN_Name(rtn) != watch_rtn)
    {
        if (version != VERSION_BASE)
            BBL_SetTargetVersion(TRACE_BblHead(trace), VERSION_BASE);
        return;
    }

    if (TRACE_Address(trace) == RTN_Address(rtn)) {
        INS ins = BBL_InsHead(TRACE_BblHead(trace));
        if (version == VERSION_BASE) 
        {
            // version_reg is used to select the version, use the first
            // argument of watch_rtn to set it
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(select_version),
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_RETURN_REGS, version_reg,
                           IARG_END);
            // IF we are in the base version, decide if we should go to the
            // other versions
        
            INS_InsertVersionCase(ins, version_reg, 10, VERSION_1, IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_END);
            INS_InsertVersionCase(ins, version_reg, 20, VERSION_2, IARG_CALL_ORDER, CALL_ORDER_LAST, IARG_END);
            printf ("Instrumentation at %p\n", reinterpret_cast<void *>(INS_Address(ins)));
        }
    }

    INS ins = BBL_InsHead(TRACE_BblHead(trace));
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) 
    {
        // Instrumentation depends on version
        // These instrumentations occur before the preceeding version instrumentation
        // (i.e. the instrumentation inserted by the above INS_InsertVersionCase calls)
        // This is due to the above INS_InsertVersionCase calls using IARG_CALL_ORDER, CALL_ORDER_LAST
        // to be inseted last - i.e. following the instrumentation done here
        switch(version) {
          case VERSION_BASE:
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Emit),
                             IARG_PTR, "version base", IARG_END);
            break;
          case VERSION_1:
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Emit),
                             IARG_PTR, "version 1", IARG_END);
            break;
          case VERSION_2:
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Emit),
                             IARG_PTR, "version 2", IARG_END);
            break;
          default:
            assert(0);
            break;
        }
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

    // Scratch register used to select
    // instrumentation version.
    version_reg = PIN_ClaimToolRegister();

    TRACE_AddInstrumentFunction(Trace, 0);

    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
