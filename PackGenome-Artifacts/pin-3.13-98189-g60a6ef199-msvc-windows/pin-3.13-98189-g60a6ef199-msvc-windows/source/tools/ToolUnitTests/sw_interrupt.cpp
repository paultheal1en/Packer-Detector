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
 * This test tool instruments every instruction of the sw_interrupt_app program
 * to check correctness of the context recovery for software interrupts.
 */

#include "pin.H"
#include <string>
#include <iostream>

using std::cerr;
using std::endl;
using std::hex;

/*!
 * Context change callback.
 */
static void OnContextChange(THREADID threadIndex, 
                  CONTEXT_CHANGE_REASON reason, 
                  const CONTEXT *ctxtFrom,
                  CONTEXT *ctxtTo,
                  INT32 info, 
                  VOID *v)
{
    if (reason == CONTEXT_CHANGE_REASON_EXCEPTION)
    {
        UINT32 exceptionCode = info;
        ADDRINT exceptAddr = PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
        cerr << "CONTEXT_CHANGE_REASON_EXCEPTION: " << 
            "Exception code " << hex << exceptionCode << "." <<
            "Context IP " << hex << exceptAddr << "." <<
            endl; 
    }
}

/*!
 * Instruction analysis routine.
 */
static ADDRINT insCount;
static VOID Count(INS ins, VOID *)
{
    insCount++;
}

/*!
 * Instruction instrumentation routine.
 */
static VOID InstrumentInstruction(INS ins, VOID *)
{
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Count, IARG_END);
}

/*!
 * The main procedure of the tool.
 */
int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    PIN_Init(argc, argv);

    INS_AddInstrumentFunction(InstrumentInstruction, 0);
    PIN_AddContextChangeFunction(OnContextChange, 0);

    PIN_StartProgram();
    return 0;
}
