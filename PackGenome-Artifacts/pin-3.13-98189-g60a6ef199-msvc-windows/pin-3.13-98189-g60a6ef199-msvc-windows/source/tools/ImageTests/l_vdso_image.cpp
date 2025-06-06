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
 *  This tool check that vdso image can be instrumented (see code comments for more details).
 *  The tool should be used with the l_vdso_image_app application.
 *
 *  See below KnobCheckVsyscallAreaNotUsed documentation for another mode this tool is checking.
 */

#include <iostream>
#include <fstream>
#include <linux/unistd.h>
#include "pin.H"
using std::ofstream;
using std::cerr;
using std::string;
using std::endl;


// Global variables

// A knob for defining the file with list of loaded images
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "l_vdso_image.log", "log file for the tool");


/*!
 * Starting from Linux kernel XYZ, vsyscall area is execute only (XO). Therefore PIN cannot fetch and/or instrument it.
 * We currently don't know the exact kernel version, so for now we added support for this mode under KnobRunVsyscallAreaNativly
 * knob.
 * When we know the exact kernel version we can remove this knob and check the kernel version itself (~using OS_GetKernelRelease())
 * Note that VDSO may branch into vsyscall area on old kernels.
 */
KNOB<BOOL> KnobCheckVsyscallAreaNotUsed(KNOB_MODE_WRITEONCE, "pintool",
    "check_vsyscall_not_used", "0", "If True check the we don't instrument vsyscall area");

ofstream outFile; // The tool's output file for printing the loaded images.
BOOL beforeTimeOfDayCalled = false;
BOOL unload_vsdo = false;
BOOL vdsoUsed = false; // True if one of the functions below are fetched
ADDRINT vdsoGetTimeOfDayAddress = 0; // Address of __vdso_gettimeofday function
ADDRINT kernelVsyscallAddress = 0; // Address of __kernel_vsyscall function
BOOL vsyscallAreaUsed = false; // True if vsyscall area is being fetched and instrumented

/* ===================================================================== */
/* Analysis routines                                                     */
/* ===================================================================== */

VOID timeOfDayBefore()
{
    outFile << "Before __vdso_gettimeofday" << endl;
    beforeTimeOfDayCalled = true;
}

VOID kernelVSyscallRtnBefore(ADDRINT l_eax)
{
    if (l_eax == __NR_gettimeofday)
    {
        outFile << "Before __kernel_vsyscall with EAX equal to __NR_gettimeofday" << endl;
        beforeTimeOfDayCalled = true;
    }
}

VOID Trace(TRACE trace, VOID *v)
{
    ADDRINT traceAddress = TRACE_Address(trace);
    ADDRINT traceLastAddress = traceAddress + TRACE_Size(trace) - 1;

    if (((vdsoGetTimeOfDayAddress >= traceAddress) &&  (vdsoGetTimeOfDayAddress <= traceLastAddress))
        || ((kernelVsyscallAddress >= traceAddress) &&  (kernelVsyscallAddress <= traceLastAddress)))

    {
        outFile << "vdso used" << endl;
        vdsoUsed = true;
    }

#if defined(TARGET_IA32E)
    if ((traceAddress >= 0xffffffffff600000) && (traceAddress < 0xffffffffff601000))
    {
        outFile << "Reached ins of vsyscall area, adderss = 0x" << std::hex << traceAddress<< endl;
        vsyscallAreaUsed = true;
    }
#endif
}

/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */

static VOID ImageLoad(IMG img, VOID *v)
{
    if (!IMG_IsVDSO(img))
    {
        return;
    }
    outFile << IMG_Name(img) << endl;


    RTN getTimeOfDayRtn = RTN_FindByName(img, "__vdso_gettimeofday");
    RTN kernelVSyscallRtn = RTN_FindByName(img, "__kernel_vsyscall");
    if (!RTN_Valid(getTimeOfDayRtn) && !RTN_Valid(kernelVSyscallRtn))
    {
        cerr << "TOOL ERROR: Unable to find the __vdso_gettimeofday or __kernel_vsyscall functions in the application."
                << endl;
        PIN_ExitProcess(1);
    }

    // Different Linux OS's (as well as 32/64 bit) have different ways of calling VDSO gettimeofday service
    // (no easy switch). So just catching any of them will satisfy the test.
    if (RTN_Valid(getTimeOfDayRtn))
    {
        vdsoGetTimeOfDayAddress = RTN_Address(getTimeOfDayRtn);

        // Instrumenting __vdso_gettimeofday() will satisfy the test
        RTN_Open(getTimeOfDayRtn);
        RTN_InsertCall(getTimeOfDayRtn, IPOINT_BEFORE, (AFUNPTR)timeOfDayBefore, IARG_END);
        RTN_Close(getTimeOfDayRtn);
    }
    if (RTN_Valid(kernelVSyscallRtn))
    {
        kernelVsyscallAddress = RTN_Address(kernelVSyscallRtn);

        // Instrumenting __kernel_vsyscall() with EAX equal to __NR_gettimeofday will satisfy the test
        RTN_Open(kernelVSyscallRtn);
        RTN_InsertCall(kernelVSyscallRtn, IPOINT_BEFORE, (AFUNPTR)kernelVSyscallRtnBefore,
                IARG_REG_VALUE, REG_EAX,
                IARG_END);
        RTN_Close(kernelVSyscallRtn);
    }

}

static VOID ImageUnload(IMG img, VOID *v)
{
    if (IMG_IsVDSO(img))
    {
        unload_vsdo = true;
    }
}


static VOID Fini(INT32 code, VOID *v)
{
    ASSERT(unload_vsdo,
            "Error, VDSO wasn't unloaded");
    ASSERT(!vdsoUsed || beforeTimeOfDayCalled,
                "Error, VDSO gettimeofday service was not instrumented "
                "(__vdso_gettimeofday() or __kernel_vsyscall with __NR_gettimeofday)");
    // sanity check: A situation where VDSO was not used but the analysis was called shouldn't happen
    ASSERTX( !(!vdsoUsed && beforeTimeOfDayCalled) );

    if (KnobCheckVsyscallAreaNotUsed)
    {
        // Starting from Linux kernel XYZ, vsyscall area is execute only (XO). Therefore PIN cannot fetch and/or instrument it.
        // on Linux distributions greater than  kernel XYZ, if Pin doesn't handle correctly indirect branches to vsyscall area
        // it will crash before getting to this assert. So this assert should never occur on these distributions.
        // On distributions with older kernels this assert will fail, however since currently we run this test with
        // -run_vsyscall_natively, it's safe to use it.
        ASSERT(vsyscallAreaUsed==false, "Starting from Linux kernel XYZ, vsyscall area is execute only (XO). Therefore PIN cannot "
                "fetch and/or instrument it.\n");
    }
    outFile.close();
}


int main( INT32 argc, CHAR *argv[] )
{
    // Initialization.
    PIN_InitSymbols();
    PIN_Init(argc, argv);

    // Open the tool's output file for printing the loaded images.
    outFile.open(KnobOutputFile.Value().c_str());
    if(!outFile.is_open() || outFile.fail())
    {
        cerr << "TOOL ERROR: Unable to open the output file." << endl;
        PIN_ExitProcess(1);
    }

    IMG_AddInstrumentFunction(ImageLoad, 0);
    IMG_AddUnloadFunction(ImageUnload, 0);
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Start the program.
    PIN_StartProgram(); // never returns

    return 1; // return error value
}
