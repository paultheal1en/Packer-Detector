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
#include <iostream>
#include <fstream>
#include "tool_macros.h"
using std::hex;
using std::dec;
using std::cerr;
using std::endl;
using std::cout;


/* ===================================================================== */
/* Global variables */
/* ===================================================================== */

static void (*pf_exit)(int status);


/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

INT32 Usage()
{
    cerr <<
        "This pin tool replaces exit using probes.\n"
        "\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}

/* ===================================================================== */
/* Replacement Routines */
/* ===================================================================== */

void my_exit(int code)
{
    cout << "inside my_exit" << endl;
    
    
    // calls the original function that was saved in pf_exit at the time of replacement
   if (pf_exit)
        (pf_exit)(code);
}


/* ===================================================================== */
/* Instrumentation Routines */
/* ===================================================================== */

// Called every time a new image is loaded
// Look for routines that we want to probe
VOID ImageLoad(IMG img, VOID *v)
{
    RTN exitRtn = RTN_FindByName(img, C_MANGLE("exit"));

    if (RTN_Valid(exitRtn))
    {
        if ( ! RTN_IsSafeForProbedReplacement( exitRtn ) )
        {
            cout << "Cannot replace exit with my_exit in " << IMG_Name(img) << endl;
        }
        else 
        {
            // Save the function pointer that points to the new location of
            // the entry point of the original exit in this image.


            pf_exit = (void (*)(int)) RTN_ReplaceProbed(exitRtn, AFUNPTR(my_exit));        

            cout << "Inserted probe for exit() in:"  << IMG_Name(img) << " at address " << hex << RTN_Address(exitRtn) << dec << endl;
            cout << "Relocated entry point is at address " << hex << (ADDRINT)pf_exit << dec << endl;
        }
        
    }
}

/* ===================================================================== */

int main(int argc, CHAR *argv[])
{
    
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    IMG_AddInstrumentFunction(ImageLoad, 0);
    
    PIN_StartProgramProbed();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
