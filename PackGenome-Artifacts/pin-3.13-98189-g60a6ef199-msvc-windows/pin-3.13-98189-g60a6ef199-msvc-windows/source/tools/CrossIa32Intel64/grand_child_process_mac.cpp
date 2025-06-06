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

//Child process application
#include <stdio.h>
#include <string>
#include <cstring>
#include <iostream>

using std::endl;
using std::cout;

int main(int argc, char * argv[])
{
    if (argc != 3)
    {
        cout << "Grand child report: expected 2 parameters, received " << argc-1 << endl;
        return -1;
    }
    if (strcmp(argv[1], "param1 param2") || strcmp(argv[2], "param3"))
    {
        cout << "Grand child report: wrong parameters: " << argv[1] << " " << argv[2] << endl;
        return -1;
    }
    cout << "Grand child report: The process works correctly!" << endl;
    return 0;
}
