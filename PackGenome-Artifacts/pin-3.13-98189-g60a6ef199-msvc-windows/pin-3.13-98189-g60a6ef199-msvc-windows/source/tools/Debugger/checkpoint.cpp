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
 * A sample tool that extends GDB by adding "checkpoint" and "resume" commands.
 * This is a very simple example that works only for single-threaded applications.
 */

#include "pin.H"
#include "memlog.hpp"
using std::string;

static CONTEXT Registers;
static MEMLOG MemLog;
static BOOL isCheckpointing = FALSE;


static VOID Instruction(INS, VOID *);
static VOID OnMemWrite(ADDRINT, ADDRINT);
static BOOL DebugInterpreter(THREADID, CONTEXT *, const string &, string *, VOID *);


int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))
        return 1;

    PIN_AddDebugInterpreter(DebugInterpreter, 0);
    INS_AddInstrumentFunction(Instruction, 0);

    PIN_StartProgram();
    return 0;
}


static VOID Instruction(INS ins, VOID *)
{
    if (INS_IsMemoryWrite(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)OnMemWrite,
            IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
    }
}


static VOID OnMemWrite(ADDRINT addr, ADDRINT size)
{
    if (isCheckpointing)
        MemLog.Record(addr, size);
}


static BOOL DebugInterpreter(THREADID, CONTEXT *ctxt, const string &cmd, string *, VOID *)
{
    if (cmd == "checkpoint")
    {
        PIN_SaveContext(ctxt, &Registers);
        isCheckpointing = TRUE;
        return TRUE;
    }
    if (cmd == "restore")
    {
        PIN_SaveContext(&Registers, ctxt);
        MemLog.Restore();
        return TRUE;
    }
    return FALSE;
}
