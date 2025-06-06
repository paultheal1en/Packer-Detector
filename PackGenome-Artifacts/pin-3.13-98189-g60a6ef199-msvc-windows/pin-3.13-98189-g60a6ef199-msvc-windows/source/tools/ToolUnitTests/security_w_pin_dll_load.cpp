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
 * This tool verifies that change of current working directory by application
 * doesn't affect DLL search algorithm in subsequent loading of DLLs by Pin loader.
 * Search directories list for Pin loader remains persistent and determined
 * by Pin launcher before applications start to run instrumented.
 */

#include "pin.H"
#include <string>
#include <iostream>

#include <link.h>
#include <dlfcn.h>

using std::string;
using std::endl;
using std::flush;
using std::cerr;

/* ===================================================================== */

int afterSetCurrentDirectory(void)
{
    cerr <<  "Load dynamic_secondary_dll.dll" << endl;
    void * dllHandle = dlopen("dynamic_secondary_dll.dll", RTLD_NOW);
    if (NULL == dllHandle)
    {
        cerr << "Failure loading dynamic_secondary_dll.dll : " << dlerror() << endl << flush;
        return 1;
    }
    return 0;
    // Returns 1 on failure, 0 on success.
}

static VOID imageLoad(IMG img, VOID *v)
{
    if (IMG_IsMainExecutable(img))
    {
        cerr <<  "Instrument AfterSetCurrentDirectory function" << endl;
        RTN rtn = RTN_FindByName(img, "AfterSetCurrentDirectory");
        if (RTN_Valid(rtn))
        {
            if (!PIN_IsProbeMode())
            {
                // JIT mode
                RTN_Replace(rtn, AFUNPTR(afterSetCurrentDirectory));
                return;
            }
            else if (RTN_IsSafeForProbedReplacement(rtn))
            {
                // Probe mode
                RTN_ReplaceProbed(rtn, AFUNPTR(afterSetCurrentDirectory));
                return;
            }
        }
        cerr <<  "AfterSetCurrentDirectory function is not found or unsafe to instrument" << endl << flush;
        PIN_ExitProcess(2);
    }
}

int main(int argc, char * argv[])
{
    PIN_InitSymbols();

    // Initialize Pin
    PIN_Init(argc, argv);

    IMG_AddInstrumentFunction(imageLoad, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
