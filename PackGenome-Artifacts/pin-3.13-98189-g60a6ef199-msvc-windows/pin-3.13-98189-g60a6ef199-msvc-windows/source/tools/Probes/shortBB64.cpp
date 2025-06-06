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

//
// This tool replaces routine "foo"
// that has two basic blocks in prolog bytes being replaced by probe.
// Check proper translation of the copied original bytes
//


#include "pin.H"
#include <iostream>


//--------------------------------------------------------------------------------------------------
typedef  int (*fooType)( int val );
int FooProbe(fooType fooWithoutReplacement, int val)
{
    return fooWithoutReplacement(val);
}

/* ===================================================================== */
// Called every time a new image is loaded
// Look for routines that we want to probe

VOID ImageLoad(IMG img, VOID *v)
{
    RTN fooRtn = RTN_FindByName(img, "foo");

    if (RTN_Valid(fooRtn) && RTN_IsSafeForProbedReplacement(fooRtn))
    {
        PROTO s_protoFoo = PROTO_Allocate( PIN_PARG(int), CALLINGSTD_DEFAULT,
             "foo", PIN_PARG(int), PIN_PARG_END() );
        AFUNPTR fff = RTN_ReplaceSignatureProbed(fooRtn, AFUNPTR(FooProbe),
                                    IARG_PROTOTYPE, s_protoFoo,
                                     IARG_ORIG_FUNCPTR,
                                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                     IARG_END);
		PROTO_Free(s_protoFoo);
    }
}

/* ===================================================================== */

int main(int argc, CHAR *argv[])
{
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return -1;
    }

    IMG_AddInstrumentFunction(ImageLoad, 0);
    
    PIN_StartProgramProbed();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
