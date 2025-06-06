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
#include "pin.H"
using std::endl;

UINT64 before = 0;
UINT64 after = 0;
UINT64 noFallThrough = 0;

VOID docount_before(BOOL hasFallTrough)
{
    before++;
    if ( ! hasFallTrough) noFallThrough++;
}

VOID docount_after()
{
    after++;
}

VOID Trace(TRACE trace, VOID *v)
{
    INS ins;
    
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            BOOL validForIpointAfter = INS_IsValidForIpointAfter(ins);
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(docount_before), IARG_UINT32, validForIpointAfter, IARG_END);
            if (validForIpointAfter)
            {
                INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(docount_after), IARG_END);
            }
        }
    }
}

VOID Fini(INT32 code, VOID *v)
{
    std::cerr << "Count before: " << before << endl;
    std::cerr << "Count after: " << after << endl;
    std::cerr << "Count no fall-through: " << noFallThrough << endl;
}


int main(INT32 argc, CHAR **argv)
{
    PIN_Init(argc, argv);
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);
    
    // Never returns
    PIN_StartProgram();
    
    return 0;
}
