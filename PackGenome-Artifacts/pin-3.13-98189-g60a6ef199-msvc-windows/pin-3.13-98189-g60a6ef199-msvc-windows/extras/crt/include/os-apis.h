/*
 * Copyright 2002-2019 Intel Corporation.
 * 
 * This software and the related documents are Intel copyrighted materials, and your
 * use of them is governed by the express license under which they were provided to
 * you ("License"). Unless the License provides otherwise, you may not use, modify,
 * copy, publish, distribute, disclose or transmit this software or the related
 * documents without Intel's prior written permission.
 * 
 * This software and the related documents are provided as is, with no express or
 * implied warranties, other than those that are expressly stated in the License.
 */

// <COMPONENT>: os-apis
// <FILE-TYPE>: component public header

#ifndef OS_APIS_H
#define OS_APIS_H

#ifdef __cplusplus
extern "C" {
#endif

/*! @mainpage OS_APIS library
 *
 * The OS_APIS library provides a consistent api for calling system calls.
 */

/*! @brief The OS_APIS library. */

#if !defined(__cplusplus) && defined(__GNUC__) && !defined(_GNU_SOURCE)
// This tells GCC to define more structs it wouldn't define otherwise
#define _GNU_SOURCE 1
#endif

#include "types.h"
#include "types_marker.h"
#include "os-apis/os_return_codes.h"
#include "os-apis/memory.h"
#include "os-apis/file.h"
#include "os-apis/threads.h"
#include "os-apis/process.h"
#include "os-apis/time.h"
#include "os-apis/threads-management.h"
#include "os-apis/pin-tls.h"
#include "os-apis/host.h"
#include "os-apis/mutex.h"
#include "os-apis/rw-lock.h"
#include "os-apis/ipc-pipe.h"
#ifdef TARGET_WINDOWS
# include "windows/util-windows.h"
#else
# include "os-apis/signals.h"
# include "os-apis/ipc.h"
#endif

#ifdef __cplusplus
}
#endif

#endif // file guard
