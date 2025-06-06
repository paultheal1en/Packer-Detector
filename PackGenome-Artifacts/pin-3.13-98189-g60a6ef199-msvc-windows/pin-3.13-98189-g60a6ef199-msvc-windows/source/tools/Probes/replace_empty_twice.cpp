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
  Replace an original function with a custom function defined in the tool. The
  new function can have either the same or different signature from that of its
  original function.
*/

/* ===================================================================== */
#include "pin.H"
#include <stdlib.h>
#include <iostream>


/* ===================================================================== */
static void (*pf1_bar)(int);
static void (*pf2_bar)(int);

/* ===================================================================== */
VOID Boo1()
{
    // This replacement routine does nothing
	cout << "Boo1 is called" << endl;
}

VOID Boo2(int param)
{
	cout << "Boo2 is called" << endl;
	(*pf2_bar)(param);
}

/* ===================================================================== */
VOID ImageLoad(IMG img, VOID *v)
{
    cout << IMG_Name(img) << endl;

    RTN rtn = RTN_FindByName(img, "Bar");
    if (RTN_Valid(rtn))
    {
        if ( ! RTN_IsSafeForProbedReplacement( rtn ) )
        {
            cout << "Cannot replace " << RTN_Name(rtn) << " in " << IMG_Name(img) << endl;
            exit(1);
        }
        
        cout << "Replacing " << RTN_Name(rtn) << " in " << IMG_Name(img) << endl;

        pf1_bar = (void (*)(int))RTN_ReplaceProbed(rtn, AFUNPTR(Boo1));
        pf2_bar = (void (*)(int))RTN_ReplaceProbed(rtn, AFUNPTR(Boo2));
    }    
}

/* ===================================================================== */
int main(INT32 argc, CHAR *argv[])
{
    PIN_InitSymbols();

    PIN_Init(argc, argv);

    IMG_AddInstrumentFunction(ImageLoad, 0);
    
    PIN_StartProgramProbed();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
