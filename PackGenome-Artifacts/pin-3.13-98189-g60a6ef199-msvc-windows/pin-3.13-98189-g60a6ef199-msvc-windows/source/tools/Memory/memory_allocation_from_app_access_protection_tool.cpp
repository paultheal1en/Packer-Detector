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

// This tool is used by the memory_-allocation_access_protection.test.
// It checks the correctness of the APIs: PIN_CheckReadAccessProtection and PIN_CheckWriteAccessProtectionaccess.
// when the mmap function is called by the application.

#include "pin.H"
#include <iostream>
#include <fstream>
using std::ios;
using std::dec;
using std::hex;
using std::string;
using std::endl;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "app_memory_access_protection_tool.out",
                            "specify trace file name");

/* ===================================================================== */

VOID MmapAfter(ADDRINT ret)
{
    TraceFile << dec << PIN_CheckReadAccess((void * )ret);
    TraceFile << dec << PIN_CheckWriteAccess((void * )ret);
    TraceFile << endl;
}

/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */

VOID Image(IMG img, VOID *v)
{
    if(IMG_IsMainExecutable(img))
    {
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        {
            for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
            {
                if (RTN_Name(rtn) == "_NotifyPinAfterMmap" || RTN_Name(rtn) == "NotifyPinAfterMmap")
                {
                    RTN_Open(rtn);
                    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MmapAfter,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
                    RTN_Close(rtn);
                }
            }
         }
    }
}
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    // Initialize pin & symbol manager
    PIN_InitSymbols();
    PIN_Init(argc,argv);

    TraceFile.open(KnobOutputFile.Value().c_str());
    TraceFile << hex;
    TraceFile.setf(ios::showbase);

    // Register Image to be called to instrument functions.
    IMG_AddInstrumentFunction(Image,0);
    //RTN_AddInstrumentFunction(InstrumentRoutine, 0);
    // Never returns
    PIN_StartProgram();
    return 0;
}
