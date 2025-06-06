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

// This tool is used to test performance affects of inserting a call in probe mode


#include <stdio.h>
#include "pin.H"
using std::string;

VOID AtRtn()
{
}

























VOID Image(IMG img, VOID * v)
{
    if ( (IMG_Name(img).find("ntdll.dll") != string::npos) ||
       (IMG_Name(img).find("NTDLL.DLL") != string::npos) ||
       (IMG_Name(img).find("NTDLL.dll") != string::npos) ) 

    {
        return;
    }
    if ( (IMG_Name(img).find("MSVCR") != string::npos) ||
       (IMG_Name(img).find("msvcr") != string::npos) ) 

    { // _NLG_Return2 causes problems
        return;
    }
   
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {


            if (RTN_Name(rtn).find(".text") != string::npos) 
            {
                continue;
            }

            BOOL canBeProbed = RTN_IsSafeForProbedReplacement(rtn);
            if (canBeProbed)
            {
                RTN_InsertCallProbed( rtn, IPOINT_BEFORE,  AFUNPTR(AtRtn),  IARG_END);
            }
        }
    }
}

int main(int argc, char **argv)
{
    PIN_Init(argc, argv);
    PIN_InitSymbols();

    IMG_AddInstrumentFunction(Image, 0);

    PIN_StartProgramProbed();
    return 0;
}
