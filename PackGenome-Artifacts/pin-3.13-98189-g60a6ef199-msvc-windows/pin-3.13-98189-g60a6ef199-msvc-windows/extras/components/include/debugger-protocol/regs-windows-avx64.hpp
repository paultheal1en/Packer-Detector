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

#ifndef DEBUGGER_PROTOCOL_REGS_WINDOWS_AVX64_HPP
#define DEBUGGER_PROTOCOL_REGS_WINDOWS_AVX64_HPP

#include "debugger-protocol.hpp"


namespace DEBUGGER_PROTOCOL {

#if defined(DEBUGGER_PROTOCOL_BUILD)    // Library clients should NOT define this.

/*!
 * This is the register set the Windows debuggers use for 64-bit AVX.
 */
DEBUGGER_PROTOCOL_API REG_DESCRIPTION RegsWindowsAvx64[] =
{
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_RAX
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_RBX
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_RCX
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_RDX
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_RSI
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_RDI
    {64, REG_INVALID, true},    // REG_WINDOWS_AVX64_RBP
    {64, REG_INVALID, true},    // REG_WINDOWS_AVX64_RSP
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_R8
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_R9
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_R10
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_R11
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_R12
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_R13
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_R14
    {64, REG_INVALID, false},   // REG_WINDOWS_AVX64_R15
    {64, REG_PC, true},         // REG_WINDOWS_AVX64_PC
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_EFLAGS
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_CS
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_SS
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_DS
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_ES
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_FS
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_GS
    {80, REG_INVALID, false},   // REG_WINDOWS_AVX64_ST0
    {80, REG_INVALID, false},   // REG_WINDOWS_AVX64_ST1
    {80, REG_INVALID, false},   // REG_WINDOWS_AVX64_ST2
    {80, REG_INVALID, false},   // REG_WINDOWS_AVX64_ST3
    {80, REG_INVALID, false},   // REG_WINDOWS_AVX64_ST4
    {80, REG_INVALID, false},   // REG_WINDOWS_AVX64_ST5
    {80, REG_INVALID, false},   // REG_WINDOWS_AVX64_ST6
    {80, REG_INVALID, false},   // REG_WINDOWS_AVX64_ST7
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_FCTRL
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_FSTAT
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_FTAG_FULL
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_FISEG
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_FIOFF
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_FOSEG
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_FOOFF
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_FOP
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM0
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM1
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM2
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM3
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM4
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM5
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM6
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM7
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM8
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM9
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM10
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM11
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM12
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM13
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM14
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_XMM15
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_MXCSR
    {32, REG_INVALID, false},   // REG_WINDOWS_AVX64_MXCSRMASK
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM0H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM1H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM2H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM3H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM4H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM5H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM6H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM7H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM8H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM9H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM10H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM11H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM12H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM13H
    {128, REG_INVALID, false},  // REG_WINDOWS_AVX64_YMM14H
    {128, REG_INVALID, false}   // REG_WINDOWS_AVX64_YMM15H
};

/*!
 * Number of entries in RegsWindowsAvx64.
 */
DEBUGGER_PROTOCOL_API unsigned RegsWindowsAvx64Count = sizeof(RegsWindowsAvx64) / sizeof(RegsWindowsAvx64[0]);

#else

DEBUGGER_PROTOCOL_API extern REG_DESCRIPTION RegsWindowsAvx64[];   ///< 64-bit AVX register set on Windows.
DEBUGGER_PROTOCOL_API extern unsigned RegsWindowsAvx64Count;       ///< Number of entries in RegsWindowsAvx64.

#endif /*DEBUGGER_PROTOCOL_BUILD*/


/*!
 * Convenient identifiers for the registers in this set.
 */
enum REG_WINDOWS_AVX64
{
    REG_WINDOWS_AVX64_FIRST = REG_END,
    REG_WINDOWS_AVX64_RAX = REG_WINDOWS_AVX64_FIRST,
    REG_WINDOWS_AVX64_RBX,
    REG_WINDOWS_AVX64_RCX,
    REG_WINDOWS_AVX64_RDX,
    REG_WINDOWS_AVX64_RSI,
    REG_WINDOWS_AVX64_RDI,
    REG_WINDOWS_AVX64_RBP,
    REG_WINDOWS_AVX64_RSP,
    REG_WINDOWS_AVX64_R8,
    REG_WINDOWS_AVX64_R9,
    REG_WINDOWS_AVX64_R10,
    REG_WINDOWS_AVX64_R11,
    REG_WINDOWS_AVX64_R12,
    REG_WINDOWS_AVX64_R13,
    REG_WINDOWS_AVX64_R14,
    REG_WINDOWS_AVX64_R15,
    REG_WINDOWS_AVX64_PC,
    REG_WINDOWS_AVX64_EFLAGS,
    REG_WINDOWS_AVX64_CS,
    REG_WINDOWS_AVX64_SS,
    REG_WINDOWS_AVX64_DS,
    REG_WINDOWS_AVX64_ES,
    REG_WINDOWS_AVX64_FS,
    REG_WINDOWS_AVX64_GS,
    REG_WINDOWS_AVX64_ST0,
    REG_WINDOWS_AVX64_ST1,
    REG_WINDOWS_AVX64_ST2,
    REG_WINDOWS_AVX64_ST3,
    REG_WINDOWS_AVX64_ST4,
    REG_WINDOWS_AVX64_ST5,
    REG_WINDOWS_AVX64_ST6,
    REG_WINDOWS_AVX64_ST7,
    REG_WINDOWS_AVX64_FCTRL,
    REG_WINDOWS_AVX64_FSTAT,
    REG_WINDOWS_AVX64_FTAG_FULL,      // 16-bit "full" encoding
    REG_WINDOWS_AVX64_FISEG,
    REG_WINDOWS_AVX64_FIOFF,
    REG_WINDOWS_AVX64_FOSEG,
    REG_WINDOWS_AVX64_FOOFF,
    REG_WINDOWS_AVX64_FOP,
    REG_WINDOWS_AVX64_XMM0,
    REG_WINDOWS_AVX64_XMM1,
    REG_WINDOWS_AVX64_XMM2,
    REG_WINDOWS_AVX64_XMM3,
    REG_WINDOWS_AVX64_XMM4,
    REG_WINDOWS_AVX64_XMM5,
    REG_WINDOWS_AVX64_XMM6,
    REG_WINDOWS_AVX64_XMM7,
    REG_WINDOWS_AVX64_XMM8,
    REG_WINDOWS_AVX64_XMM9,
    REG_WINDOWS_AVX64_XMM10,
    REG_WINDOWS_AVX64_XMM11,
    REG_WINDOWS_AVX64_XMM12,
    REG_WINDOWS_AVX64_XMM13,
    REG_WINDOWS_AVX64_XMM14,
    REG_WINDOWS_AVX64_XMM15,
    REG_WINDOWS_AVX64_MXCSR,
    REG_WINDOWS_AVX64_MXCSRMASK,
    REG_WINDOWS_AVX64_YMM0H,
    REG_WINDOWS_AVX64_YMM1H,
    REG_WINDOWS_AVX64_YMM2H,
    REG_WINDOWS_AVX64_YMM3H,
    REG_WINDOWS_AVX64_YMM4H,
    REG_WINDOWS_AVX64_YMM5H,
    REG_WINDOWS_AVX64_YMM6H,
    REG_WINDOWS_AVX64_YMM7H,
    REG_WINDOWS_AVX64_YMM8H,
    REG_WINDOWS_AVX64_YMM9H,
    REG_WINDOWS_AVX64_YMM10H,
    REG_WINDOWS_AVX64_YMM11H,
    REG_WINDOWS_AVX64_YMM12H,
    REG_WINDOWS_AVX64_YMM13H,
    REG_WINDOWS_AVX64_YMM14H,
    REG_WINDOWS_AVX64_YMM15H,
    REG_WINDOWS_AVX64_LAST = REG_WINDOWS_AVX64_YMM15H
};

} // namespace
#endif // file guard
