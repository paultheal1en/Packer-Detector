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
 * This tool inserts a lot of useless instrumentation just to put
 * pressure on the Pin register allocator.
 */

#include <pin.H>


static const unsigned NUM_SCRATCH = 4;
static REG ScratchRegs[NUM_SCRATCH];

static void InstrumentIns(INS, VOID *);
static ADDRINT MakePressure(ADDRINT, ADDRINT, ADDRINT, ADDRINT, ADDRINT);


int main(int argc, char * argv[])
{
    PIN_Init(argc, argv);

    for (unsigned i = 0;  i < NUM_SCRATCH;  i++)
        ScratchRegs[i] = PIN_ClaimToolRegister();

    INS_AddInstrumentFunction(InstrumentIns, 0);

    PIN_StartProgram();
    return 0;
}

static void InstrumentIns(INS ins, VOID *)
{
    REG retReg = ScratchRegs[INS_Address(ins) % NUM_SCRATCH];

    IARGLIST args = IARGLIST_Alloc();
    for (unsigned i = 0;  i < NUM_SCRATCH;  i++)
        IARGLIST_AddArguments(args, IARG_REG_VALUE, ScratchRegs[i], IARG_END);

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(MakePressure),
        IARG_RETURN_REGS, retReg,
        IARG_REG_VALUE, REG_STACK_PTR,
        IARG_IARGLIST, args,
        IARG_END);
    IARGLIST_Free(args);
}

static ADDRINT MakePressure(ADDRINT sp, ADDRINT s0, ADDRINT s1, ADDRINT s2, ADDRINT s3)
{
    return sp + s0 + s1 + s2 + s3;
}
