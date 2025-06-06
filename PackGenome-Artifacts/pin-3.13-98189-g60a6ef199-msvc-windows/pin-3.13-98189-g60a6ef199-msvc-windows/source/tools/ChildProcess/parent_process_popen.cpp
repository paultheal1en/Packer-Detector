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

// Application that creates new process using popen

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <iostream>
#include <string>

using std::string;
using std::cout;
using std::endl;

extern char **environ;

//Wait for a process completion
//Verify it returned the expected exit code

int main(int argc, char * argv[])
{
    string cmd = argv[1];
    for (int i = 2; i < argc; i++) cmd += string(" \"") + argv[i] + "\"";
    FILE* pr = popen(cmd.c_str(), "r");
    if (NULL == pr)
    {
       cout << "popen failed with " << errno << endl;
       return 1;
    }
    char buf[128];
    while (NULL != fgets(buf, sizeof(buf), pr))
    {
        int i = strlen(buf) - 1;
        for (; i >= 0 && isspace(buf[i]); i--);
        for (; i >= 0; i--) cout << buf[i];
        cout << endl;
    }
    return pclose(pr);
}
