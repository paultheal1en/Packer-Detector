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

/*! @file
  Replace an original function with a custom function defined in the tool.
  Its purpose is to check delivery of original SP value.
*/

/* ===================================================================== */
#include "pin.H"


/* ===================================================================== */
// Replaces original function. Returns 0 if all SP values are valid.
int check_sp_value( void* arg0,
                    ADDRINT gsp, ADDRINT esp, ADDRINT sp )
{
    ADDRINT orig_sp = (ADDRINT)arg0;

    if ((orig_sp == gsp) &&
        ((unsigned int)orig_sp == esp) &&
        ((unsigned short)orig_sp == sp))
    {
        return 0;
    }
    return 1;
}


/* ===================================================================== */
VOID ImageLoad(IMG img, VOID *v)
{
    if (!IMG_IsMainExecutable(img))
    {
        return;
    }

    const char * name = "check_sp_value";
 
    RTN rtn = RTN_FindByName(img, name);
    if (RTN_Valid(rtn))
    {
        PROTO proto = PROTO_Allocate(PIN_PARG(int),
                                     CALLINGSTD_DEFAULT,  name,
                                     PIN_PARG(void*),
                                     PIN_PARG_END() );

        if ( ! PIN_IsProbeMode() )
        {
            RTN_ReplaceSignature(
                rtn, AFUNPTR(check_sp_value),
                IARG_PROTOTYPE, proto,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_REG_VALUE, REG_ESP,
                IARG_REG_VALUE, REG_SP,
                IARG_END);
        }
        else if (RTN_IsSafeForProbedReplacement(rtn))
        {
            RTN_ReplaceSignatureProbed(
                rtn, AFUNPTR(check_sp_value),
                IARG_PROTOTYPE, proto,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_REG_VALUE, REG_ESP,
                IARG_REG_VALUE, REG_SP,
                IARG_END);
        }

        PROTO_Free( proto);
    }
}

/* ===================================================================== */
int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    PIN_Init(argc, argv);

    IMG_AddInstrumentFunction(ImageLoad, 0);
    
    if ( PIN_IsProbeMode() )
        PIN_StartProgramProbed();
    else
        PIN_StartProgram();
    
    return 0;
}
/* ===================================================================== */
/* eof */
/* ===================================================================== */
