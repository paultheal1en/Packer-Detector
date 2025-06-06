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

/*! @file
 *  pin tool combined from multi-DLLs (main_dll, dynamic_secondary_dll, static_secondary_dll). 
 */

#include <link.h>
#include <dlfcn.h>

#include <iostream>
#include <fstream>

using std::ofstream;
using std::hex;
using std::showbase;
using std::endl;

ofstream outfile;

// This function gets info of an image loaded by Pin loader.
// Invoked by dl_iterate_phdr()
int dl_iterate_callback(struct dl_phdr_info * info, size_t size, VOID * data)
{
    // Increment module counter.
    ++(*reinterpret_cast<int *>(data));
    return 0;
}


extern "C" __declspec( dllexport ) int Init2(bool enumerate)
{
    int nModules = 0;
    if (enumerate)
    {
        // Enumerate DLLs currently loaded by Pin loader.
        dl_iterate_phdr(dl_iterate_callback, &nModules);
    }
    outfile.open("dynamic_secondary_dll.out");
    outfile << hex << showbase;

    return nModules;
}

extern "C" __declspec( dllexport ) void BeforeBBL2(void * ip)
{
    outfile << "Before BBL, ip " << ip << endl;
}

extern "C" __declspec( dllexport ) void Fini2()
{
    outfile.close();
}

// Define main - will never be called
// can be avoided by removing /EXPORT:main from link flags
int main(int argc, char * argv[])
{
    return 0;
}
