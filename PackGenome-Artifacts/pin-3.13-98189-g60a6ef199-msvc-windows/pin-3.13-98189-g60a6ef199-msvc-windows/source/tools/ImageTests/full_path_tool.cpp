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

#include "pin.H"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <assert.h>
using std::ofstream;
using std::string;
using std::endl;

using std::cerr;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "full_path.out", "specify file name");

ofstream TraceFile;

static VOID ImageLoad(IMG img, VOID *data)
{
    TraceFile << "%s is loaded\n" << IMG_Name(img) << endl;
}

int main(int argc, char** argv)
{
    if (!PIN_Init(argc, argv))
    {
        TraceFile.open(KnobOutputFile.Value().c_str());

        PIN_InitSymbols();
        
        IMG_AddInstrumentFunction(ImageLoad,  0);

        PIN_StartProgramProbed();
    }

    return 1;
}
