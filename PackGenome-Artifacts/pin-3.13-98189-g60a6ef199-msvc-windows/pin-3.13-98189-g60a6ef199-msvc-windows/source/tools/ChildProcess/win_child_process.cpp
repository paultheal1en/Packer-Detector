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
#include <windows.h>
#include <stdio.h>
#include <iostream>
using std::endl;
using std::cout;
using std::string;

int main(int argc, char * argv[])
{
    const int baseArgc = 3;
    if (argc < baseArgc)
    {
        //Got unexpected parameter
        cout << "Some arguments missed" << endl;
        return (-2);
    }
    CHAR * expectedArgv[baseArgc] = {{"win_child_process.exe"}, {"param1 param2"}, {"param3"}};
    string currentArgv;
    
    //Take into account that a path might be added to the executable name
    currentArgv = argv[0];
    string::size_type index = currentArgv.find(expectedArgv[0]);
    if(index == string::npos)
    {
        //Got unexpected parameter
        cout << "Got unexpected parameter: " << argv[0] << endl;
        return (-1);
    }
    //All the rest should have exact match
    for(int i = 1; i < baseArgc; i++)
    {
        currentArgv = argv[i];
        if(currentArgv.compare(expectedArgv[i]) != 0)
        {
            //Got unexpected parameter
            cout << "Got unexpected parameter: " << argv[i] << endl;
            return (-1);
        }
    }
    if (argc > baseArgc)
    {
        // Next parameter is sleep interval in milliseconds
        int msecs = atoi(argv[baseArgc]);
        if (msecs > 0)
        {
            Sleep(msecs);
        }
    }
    return 0;
}
