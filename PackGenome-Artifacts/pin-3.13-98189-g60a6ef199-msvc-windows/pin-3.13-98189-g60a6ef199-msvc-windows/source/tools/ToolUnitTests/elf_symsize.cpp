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
 *  This test checks bogus symbol size
 */

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>

#include "pin.H"
using std::cerr;
using std::ofstream;
using std::hex;
using std::string;
using std::endl;



KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,         "pintool",
                            "o", "elf_symsize.out", "specify output file name");

ofstream outfile;

VOID ImageLoad(IMG img, void *v)
{
    if (!IMG_IsMainExecutable(img))
    {
        outfile << "Ignoring image: " << IMG_Name(img) << endl;
        return;
    }

    outfile << "Parsing image: " << IMG_Name(img) << endl;
    for( SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) )
    {
        outfile << "Symbol " << SYM_Name(sym) << " address 0x" 
                << hex << SYM_Address(sym) << endl;

        RTN rtn = RTN_FindByName(img, SYM_Name(sym).c_str());
        if (!RTN_Valid(rtn))
        {
            outfile << "Routine not found, continue..." << endl;
            continue;
        }
        
        outfile << "Routine " << RTN_Name(rtn) << " address 0x" 
                << hex << RTN_Address(rtn) << " size 0x" 
                << hex << RTN_Size(rtn) << endl;
    }
}

VOID Fini(INT32 code, VOID *v)
{
    outfile << "Symbol test passed successfully" << endl;
    outfile.close();
}
/* ===================================================================== */
/* Print Help Message.                                                   */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This is the invocation pintool" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}


/* ===================================================================== */
/* Main.                                                                 */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();

    outfile.open(KnobOutputFile.Value().c_str());
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}



/* ================================================================== */
