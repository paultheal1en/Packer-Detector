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

/*!
 * This is a test for mantis 2575 and was updated for Mantis 3116.
 *
 * This tests verifies that RTN_CreateAt replaces that RTN when used on an address
 * which already has an RTN. See Mantis 3116 for more details.
 *
 */

#include <iostream>
#include "pin.H"
using std::string;

using std::cout;
using std::cerr;
using std::endl;

static VOID ImageLoad(IMG img, VOID * v) {
    // For simplicity, instrument only the main image. This can be extended to any other image of course.
    if (IMG_IsMainExecutable(img)) {

        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {

            // For each section, process all RTNs.
            RTN rtn = SEC_RtnHead(sec);

            if (!RTN_Valid(rtn)) continue;

            // There is already an RTN object associated with this address so RTN_CreateAt
            // should replace this RTN
            //
            string oldName = RTN_Name(rtn);
            rtn = RTN_CreateAt(RTN_Address(rtn), "NEWNAME");
            ASSERT(oldName != RTN_Name(rtn), "FAILED");
        }
    }
}

/* ===================================================================== */
// main
/* ===================================================================== */

int main(INT32 argc, CHAR **argv) {
    PIN_InitSymbols();

    PIN_Init(argc,argv);

    IMG_AddInstrumentFunction(ImageLoad, NULL);

    // Never returns
    PIN_StartProgram();

    return 0;
}
