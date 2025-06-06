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

#include <fstream>
#include <iostream>
#include <cstdlib>
#include "pin.H"

KNOB<std::string> KnobWhere(KNOB_MODE_WRITEONCE, "pintool",
    "where", "", "Name of function where breakpoint is triggered.  If not specified, stop at first instruction.");
KNOB<BOOL> KnobWaitForDebugger(KNOB_MODE_WRITEONCE, "pintool",
    "wait_for_debugger", "0", "Wait for debugger to connect");
KNOB<std::string> KnobPort(KNOB_MODE_WRITEONCE, "pintool",
    "port", "", "Output file where TCP information is written");
KNOB<BOOL> KnobUseIargConstContext(KNOB_MODE_WRITEONCE, "pintool",
                                   "const_context", "0", "use IARG_CONST_CONTEXT");


BOOL FoundWhere = FALSE;
BOOL IsFirstBreakpoint = TRUE;

static void InstrumentRtn(RTN, VOID *);
static void InstrumentIns(INS, VOID *);
static void DoBreakpoint(CONTEXT *, THREADID);
static void OnExit(INT32, VOID *);


int main(int argc, char * argv[])
{
    PIN_Init(argc, argv);
    PIN_InitSymbols();

    if (!KnobPort.Value().empty())
    {
        DEBUG_CONNECTION_INFO info;
        if (!PIN_GetDebugConnectionInfo(&info))
        {
            std::cerr << "Error from PIN_GetDebugConnectionInfo()" << std::endl;
            return 1;
        }
        if (info._type != DEBUG_CONNECTION_TYPE_TCP_SERVER)
        {
            std::cerr << "Unexpected connection type from PIN_GetDebugConnectionInfo()" << std::endl;
            return 1;
        }

        std::ofstream out(KnobPort.Value().c_str());
        out << std::dec << info._tcpServer._tcpPort;
    }

    if (KnobWhere.Value() == "")
        INS_AddInstrumentFunction(InstrumentIns, 0);
    else
        RTN_AddInstrumentFunction(InstrumentRtn, 0);
    PIN_AddFiniFunction(OnExit, 0);

    PIN_StartProgram();
    return 0;
}

static void InstrumentRtn(RTN rtn, VOID *)
{
    if (RTN_Name(rtn) == KnobWhere.Value())
    {
        RTN_Open(rtn);
        INS ins = RTN_InsHeadOnly(rtn);
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoBreakpoint), 
                       (KnobUseIargConstContext)?IARG_CONST_CONTEXT:IARG_CONTEXT,
                       // IARG_CONST_CONTEXT has much lower overhead 
                       // than IARG_CONTEX for passing the CONTEXT* 
                       // to the analysis routine. Note that IARG_CONST_CONTEXT
                       // passes a read-only CONTEXT* to the analysis routine
                       IARG_THREAD_ID, IARG_END);
        FoundWhere = TRUE;
        RTN_Close(rtn);
    }
}

static void InstrumentIns(INS ins, VOID *)
{
    if (!FoundWhere)
    {
        FoundWhere = TRUE;
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(DoBreakpoint), 
                       (KnobUseIargConstContext)?IARG_CONST_CONTEXT:IARG_CONTEXT, 
                       // IARG_CONST_CONTEXT has much lower overhead 
                       // than IARG_CONTEX for passing the CONTEXT* 
                       // to the analysis routine. Note that IARG_CONST_CONTEXT
                       // passes a read-only CONTEXT* to the analysis routine
                       IARG_THREAD_ID, IARG_END);
    }
}

static void DoBreakpoint(CONTEXT *ctxt, THREADID tid)
{
    if (IsFirstBreakpoint)
    {
        std::cout << "Tool stopping at breakpoint" << std::endl;
        IsFirstBreakpoint = FALSE;
        PIN_ApplicationBreakpoint(ctxt, tid, KnobWaitForDebugger.Value(), "The tool wants to stop");
    }
}

static void OnExit(INT32, VOID *)
{
    if (!FoundWhere)
    {
        std::cout << "FAILURE: Couldn't add instrumentation routine" << std::endl;
        std::exit(1);
    }
}
