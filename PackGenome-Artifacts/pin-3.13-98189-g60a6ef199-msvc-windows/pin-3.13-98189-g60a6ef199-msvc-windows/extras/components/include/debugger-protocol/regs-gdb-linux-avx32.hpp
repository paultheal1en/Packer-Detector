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

// <COMPONENT>: debugger-protocol
// <FILE-TYPE>: component public header

#ifndef DEBUGGER_PROTOCOL_REGS_GDB_LINUX_AVX32_HPP
#define DEBUGGER_PROTOCOL_REGS_GDB_LINUX_AVX32_HPP

#include "debugger-protocol.hpp"


namespace DEBUGGER_PROTOCOL {

#if defined(DEBUGGER_PROTOCOL_BUILD)    // Library clients should NOT define this.

/*!
 * This is the register set used by GDB for 32-bit AVX on Linux.
 */
DEBUGGER_PROTOCOL_API REG_DESCRIPTION RegsGdbLinuxAvx32[] =
{
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_EAX
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_ECX
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_EDX
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_EBX
    {32, REG_INVALID, true},    // REG_GDB_LINUX_AVX32_ESP
    {32, REG_INVALID, true},    // REG_GDB_LINUX_AVX32_EBP
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_ESI
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_EDI
    {32, REG_PC, true},         // REG_GDB_LINUX_AVX32_PC
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_EFLAGS
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_CS
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_SS
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_DS
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_ES
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_FS
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_GS
    {80, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_ST0
    {80, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_ST1
    {80, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_ST2
    {80, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_ST3
    {80, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_ST4
    {80, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_ST5
    {80, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_ST6
    {80, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_ST7
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_FCTRL
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_FSTAT
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_FTAG_FULL
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_FISEG
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_FIOFF
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_FOSEG
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_FOOFF
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_FOP
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_XMM0
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_XMM1
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_XMM2
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_XMM3
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_XMM4
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_XMM5
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_XMM6
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_XMM7
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_MXCSR
    {32, REG_INVALID, false},   // REG_GDB_LINUX_AVX32_ORIG_EAX
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_YMM0H
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_YMM1H
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_YMM2H
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_YMM3H
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_YMM4H
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_YMM5H
    {128, REG_INVALID, false},  // REG_GDB_LINUX_AVX32_YMM6H
    {128, REG_INVALID, false}   // REG_GDB_LINUX_AVX32_YMM7H
};

/*!
 * Number of entries in RegsGdbLinuxAvx32.
 */
DEBUGGER_PROTOCOL_API unsigned RegsGdbLinuxAvx32Count = sizeof(RegsGdbLinuxAvx32) / sizeof(RegsGdbLinuxAvx32[0]);

#else

DEBUGGER_PROTOCOL_API extern REG_DESCRIPTION RegsGdbLinuxAvx32[];     ///< GDB's 32-bit AVX register set on Linux.
DEBUGGER_PROTOCOL_API extern unsigned RegsGdbLinuxAvx32Count;         ///< Number of entries in RegsGdbLinuxAvx32.

#endif /*DEBUGGER_PROTOCOL_BUILD*/


/*!
 * Convenient identifiers for the registers in this set.
 */
enum REG_GDB_LINUX_AVX32
{
    REG_GDB_LINUX_AVX32_FIRST = REG_END,
    REG_GDB_LINUX_AVX32_EAX = REG_GDB_LINUX_AVX32_FIRST,
    REG_GDB_LINUX_AVX32_ECX,
    REG_GDB_LINUX_AVX32_EDX,
    REG_GDB_LINUX_AVX32_EBX,
    REG_GDB_LINUX_AVX32_ESP,
    REG_GDB_LINUX_AVX32_EBP,
    REG_GDB_LINUX_AVX32_ESI,
    REG_GDB_LINUX_AVX32_EDI,
    REG_GDB_LINUX_AVX32_PC,
    REG_GDB_LINUX_AVX32_EFLAGS,
    REG_GDB_LINUX_AVX32_CS,
    REG_GDB_LINUX_AVX32_SS,
    REG_GDB_LINUX_AVX32_DS,
    REG_GDB_LINUX_AVX32_ES,
    REG_GDB_LINUX_AVX32_FS,
    REG_GDB_LINUX_AVX32_GS,
    REG_GDB_LINUX_AVX32_ST0,
    REG_GDB_LINUX_AVX32_ST1,
    REG_GDB_LINUX_AVX32_ST2,
    REG_GDB_LINUX_AVX32_ST3,
    REG_GDB_LINUX_AVX32_ST4,
    REG_GDB_LINUX_AVX32_ST5,
    REG_GDB_LINUX_AVX32_ST6,
    REG_GDB_LINUX_AVX32_ST7,
    REG_GDB_LINUX_AVX32_FCTRL,
    REG_GDB_LINUX_AVX32_FSTAT,
    REG_GDB_LINUX_AVX32_FTAG_FULL,      // 16-bit "full" encoding
    REG_GDB_LINUX_AVX32_FISEG,
    REG_GDB_LINUX_AVX32_FIOFF,
    REG_GDB_LINUX_AVX32_FOSEG,
    REG_GDB_LINUX_AVX32_FOOFF,
    REG_GDB_LINUX_AVX32_FOP,
    REG_GDB_LINUX_AVX32_XMM0,
    REG_GDB_LINUX_AVX32_XMM1,
    REG_GDB_LINUX_AVX32_XMM2,
    REG_GDB_LINUX_AVX32_XMM3,
    REG_GDB_LINUX_AVX32_XMM4,
    REG_GDB_LINUX_AVX32_XMM5,
    REG_GDB_LINUX_AVX32_XMM6,
    REG_GDB_LINUX_AVX32_XMM7,
    REG_GDB_LINUX_AVX32_MXCSR,
    REG_GDB_LINUX_AVX32_ORIG_EAX,
    REG_GDB_LINUX_AVX32_YMM0H,
    REG_GDB_LINUX_AVX32_YMM1H,
    REG_GDB_LINUX_AVX32_YMM2H,
    REG_GDB_LINUX_AVX32_YMM3H,
    REG_GDB_LINUX_AVX32_YMM4H,
    REG_GDB_LINUX_AVX32_YMM5H,
    REG_GDB_LINUX_AVX32_YMM6H,
    REG_GDB_LINUX_AVX32_YMM7H,
    REG_GDB_LINUX_AVX32_LAST = REG_GDB_LINUX_AVX32_YMM7H
};

} // namespace
#endif // file guard
