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

/* ===================================================================== */
/*! @file
  This is a negative test.
*/

/* ===================================================================== */
#include "pin.H"
#include <iostream>
using std::endl;
using std::string;
using std::cout;


/* ===================================================================== */
VOID ImageLoad(IMG img, VOID *v)
{
    if ( IMG_IsMainExecutable( img ))
    {
        string s = "333";
        INT64 i = Uint64FromString( s );
        cout << s << "=" << i << endl;

        s = "0xa";
        UINT64 j = Uint64FromString( s );
        cout << s << "=" << j << endl;

        s = "0Xb";
        j = Uint64FromString( s );
        cout << s << "=" << j << endl;

        s = "12345678901234567890";
        j = Uint64FromString( s );
        cout << s << "=" << j << endl;

        // this should report an error
        s = "123456789012345678901";
        j = Uint64FromString( s );
        cout << s << "=" << j << endl;
    }
}

    

/* ===================================================================== */
int main(INT32 argc, CHAR *argv[])
{
    PIN_InitSymbols();

    PIN_Init(argc, argv);

    IMG_AddInstrumentFunction(ImageLoad, 0);
    
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
