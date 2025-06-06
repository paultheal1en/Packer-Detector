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
#include <iostream>
using std::cout;
using std::endl;


/* ===================================================================== */

int myBlue( CONTEXT * ctxt, AFUNPTR pf_Blue, int one, int two )
{
    cout << " myBlue: Jitting Blue7()" << endl;

    int res;
    
    PIN_CallApplicationFunction( ctxt, PIN_ThreadId(),
                                 CALLINGSTD_DEFAULT, pf_Blue, NULL,
                                 PIN_PARG(int), &res,
                                 PIN_PARG(int), one,
                                 PIN_PARG(int), two,
                                 PIN_PARG_END() );
    
    cout << " myBlue: Returned from Blue7(); res = " << res << endl;

    return res;
}

/* ===================================================================== */

int myBar( CONTEXT * ctxt, AFUNPTR pf_Bar, int one, int two, int stop )
{
    cout << " myBar: Jitting Bar7()" << endl;
    
    int res;
    
    PIN_CallApplicationFunction( ctxt, PIN_ThreadId(),
                                 CALLINGSTD_DEFAULT, pf_Bar, NULL,
                                 PIN_PARG(int), &res,
                                 PIN_PARG(int), one,
                                 PIN_PARG(int), two,
                                 PIN_PARG(int), stop,
                                 PIN_PARG_END() );
    
    cout << " myBar: Returned from Bar7(); res = " << res << endl;

    return res;
}


/* ===================================================================== */
VOID ImageLoad(IMG img, VOID *v)
{
    PROTO protoBar = PROTO_Allocate( PIN_PARG(int), CALLINGSTD_DEFAULT,
                                      "Bar7", PIN_PARG(int), PIN_PARG(int),
                                      PIN_PARG(int), PIN_PARG_END() );
    
    PROTO protoBlue = PROTO_Allocate( PIN_PARG(int), CALLINGSTD_DEFAULT,
                                       "Blue7", PIN_PARG(int), PIN_PARG(int),
                                       PIN_PARG_END() );
    
    RTN rtn = RTN_FindByName(img, "Bar7");
    if (RTN_Valid(rtn))
    {
        cout << " Replacing " << RTN_Name(rtn) << " in " << IMG_Name(img) << endl;

        RTN_ReplaceSignature(
            rtn, AFUNPTR(myBar),
            IARG_PROTOTYPE, protoBar,
            IARG_CONTEXT,
            IARG_ORIG_FUNCPTR,
            IARG_UINT32, 1,
            IARG_UINT32, 2,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
            IARG_END);
    }    

    rtn = RTN_FindByName(img, "Blue7");
    if (RTN_Valid(rtn))
    {
        cout << " Replacing " << RTN_Name(rtn) << " in " << IMG_Name(img) << endl;

        RTN_ReplaceSignature(
            rtn, AFUNPTR(myBlue),
            IARG_PROTOTYPE, protoBlue,
            IARG_CONTEXT,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_END);
    }    

    PROTO_Free( protoBar );
    PROTO_Free( protoBlue );
}

/* ===================================================================== */
int main(INT32 argc, CHAR *argv[])
{
    PIN_InitSymbols();

    PIN_Init(argc, argv);

    IMG_AddInstrumentFunction(ImageLoad, 0);
    
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
