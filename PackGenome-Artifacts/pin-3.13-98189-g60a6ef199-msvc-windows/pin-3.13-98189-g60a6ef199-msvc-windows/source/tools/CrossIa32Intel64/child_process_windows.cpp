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

// Application that creates new process

#include <Windows.h>
#include <iostream>
#include <string>

using std::endl;
using std::cout;
using std::string;

//Wait for a process completion
//Verify it returned the expected exit code
bool WaitAndVerify(HANDLE process)
{
    if(WaitForSingleObject( process, INFINITE ) == WAIT_FAILED)
    {
        cout << "WaitForSingleObject failed" << endl;
        return FALSE;
    }
    DWORD processExitCode;
    if(GetExitCodeProcess (process, &processExitCode) == FALSE)
    {
        cout << "GetExitCodeProcess Failed" << endl;
        return FALSE;
    }
    if(processExitCode != 0)
    {
        cout << "Got unexpected exit code" << endl;
        return FALSE;
    }
    return TRUE;
}

string SplitString(string * input, const string & delimiter = " ")
{
    string::size_type pos = input->find(delimiter);
    string substr = input->substr(0, pos);
    if(pos != string::npos)
    {
        *input = input->substr(pos + 1);
    } else
    {
        *input = "";
    }
    return substr;
}

int main(int argc, char * argv[])
{
	string cmdLine = GetCommandLine();
	SplitString(&cmdLine);
    STARTUPINFO         si;
    PROCESS_INFORMATION  pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(STARTUPINFO);
    memset(&pi, 0, sizeof(pi));
	if (!CreateProcess(NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, TRUE, NULL, 
        NULL, NULL, &si, &pi))
    {
        cout <<  "Couldn't create grand child process " << endl;
        exit(0);
    }
    if(WaitAndVerify(pi.hProcess) == FALSE)
    {
        exit(0);
    }
    cout << " Grand Child Process was created successfully!" << endl;
        
    return 0;
}

