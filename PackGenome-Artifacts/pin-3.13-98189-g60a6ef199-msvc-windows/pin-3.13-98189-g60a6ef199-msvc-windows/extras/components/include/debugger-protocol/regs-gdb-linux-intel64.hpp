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

#ifndef DEBUGGER_PROTOCOL_REGS_GDB_LINUX_INTEL64_HPP
#define DEBUGGER_PROTOCOL_REGS_GDB_LINUX_INTEL64_HPP

#include "debugger-protocol.hpp"


namespace DEBUGGER_PROTOCOL {

#if defined(DEBUGGER_PROTOCOL_BUILD)    // Library clients should NOT define this.

/*!
 * This is the register set GDB uses on Intel64 Linux.
 */
DEBUGGER_PROTOCOL_API REG_DESCRIPTION RegsGdbLinuxIntel64[] =
{
    {64, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_RAX
    {64, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_RBX
    {64, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_RCX
    {64, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_RDX
    {64, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_RSI
    {64, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_RDI
    {64, REG_INVALID, true},    // REG_GDB_LINUX_INTEL64_RBP
    {64, REG_INVALID, true},    // REG_GDB_LINUX_INTEL64_RSP
    {64, REG_INVALID, false},    // REG_GDB_LINUX_INTEL64_R8
    {64, REG_INVALID, false},    // REG_GDB_LINUX_INTEL64_R9
    {64, REG_INVALID, false},    // REG_GDB_LINUX_INTEL64_R10
    {64, REG_INVALID, false},    // REG_GDB_LINUX_INTEL64_R11
    {64, REG_INVALID, false},    // REG_GDB_LINUX_INTEL64_R12
    {64, REG_INVALID, false},    // REG_GDB_LINUX_INTEL64_R13
    {64, REG_INVALID, false},    // REG_GDB_LINUX_INTEL64_R14
    {64, REG_INVALID, false},    // REG_GDB_LINUX_INTEL64_R15
    {64, REG_PC, true},         // REG_GDB_LINUX_INTEL64_PC
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_EFLAGS
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_CS
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_SS
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_DS
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_ES
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_FS
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_GS
    {80, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_ST0
    {80, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_ST1
    {80, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_ST2
    {80, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_ST3
    {80, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_ST4
    {80, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_ST5
    {80, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_ST6
    {80, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_ST7
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_FCTRL
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_FSTAT
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_FTAG_FULL
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_FISEG
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_FIOFF
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_FOSEG
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_FOOFF
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_FOP
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM0
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM1
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM2
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM3
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM4
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM5
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM6
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM7
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM8
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM9
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM10
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM11
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM12
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM13
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM14
    {128, REG_INVALID, false},  // REG_GDB_LINUX_INTEL64_XMM15
    {32, REG_INVALID, false},   // REG_GDB_LINUX_INTEL64_MXCSR
    {64, REG_INVALID, false}    // REG_GDB_LINUX_INTEL64_ORIG_RAX
};

/*!
 * Number of entries in RegsGdbLinuxIntel64.
 */
DEBUGGER_PROTOCOL_API unsigned RegsGdbLinuxIntel64Count = sizeof(RegsGdbLinuxIntel64) / sizeof(RegsGdbLinuxIntel64[0]);

#else

DEBUGGER_PROTOCOL_API extern REG_DESCRIPTION RegsGdbLinuxIntel64[];   ///< GDB's Intel64 register set on Linux.
DEBUGGER_PROTOCOL_API extern unsigned RegsGdbLinuxIntel64Count;       ///< Number of entries in RegsGdbLinuxIntel64.

#endif /*DEBUGGER_PROTOCOL_BUILD*/


/*!
 * Convenient identifiers for the registers in this set.
 */
enum REG_GDB_LINUX_INTEL64
{
    REG_GDB_LINUX_INTEL64_FIRST = REG_END,
    REG_GDB_LINUX_INTEL64_RAX = REG_GDB_LINUX_INTEL64_FIRST,
    REG_GDB_LINUX_INTEL64_RBX,
    REG_GDB_LINUX_INTEL64_RCX,
    REG_GDB_LINUX_INTEL64_RDX,
    REG_GDB_LINUX_INTEL64_RSI,
    REG_GDB_LINUX_INTEL64_RDI,
    REG_GDB_LINUX_INTEL64_RBP,
    REG_GDB_LINUX_INTEL64_RSP,
    REG_GDB_LINUX_INTEL64_R8,
    REG_GDB_LINUX_INTEL64_R9,
    REG_GDB_LINUX_INTEL64_R10,
    REG_GDB_LINUX_INTEL64_R11,
    REG_GDB_LINUX_INTEL64_R12,
    REG_GDB_LINUX_INTEL64_R13,
    REG_GDB_LINUX_INTEL64_R14,
    REG_GDB_LINUX_INTEL64_R15,
    REG_GDB_LINUX_INTEL64_PC,
    REG_GDB_LINUX_INTEL64_EFLAGS,
    REG_GDB_LINUX_INTEL64_CS,
    REG_GDB_LINUX_INTEL64_SS,
    REG_GDB_LINUX_INTEL64_DS,
    REG_GDB_LINUX_INTEL64_ES,
    REG_GDB_LINUX_INTEL64_FS,
    REG_GDB_LINUX_INTEL64_GS,
    REG_GDB_LINUX_INTEL64_ST0,
    REG_GDB_LINUX_INTEL64_ST1,
    REG_GDB_LINUX_INTEL64_ST2,
    REG_GDB_LINUX_INTEL64_ST3,
    REG_GDB_LINUX_INTEL64_ST4,
    REG_GDB_LINUX_INTEL64_ST5,
    REG_GDB_LINUX_INTEL64_ST6,
    REG_GDB_LINUX_INTEL64_ST7,
    REG_GDB_LINUX_INTEL64_FCTRL,
    REG_GDB_LINUX_INTEL64_FSTAT,
    REG_GDB_LINUX_INTEL64_FTAG_FULL,    // 16-bit "full" encoding
    REG_GDB_LINUX_INTEL64_FISEG,
    REG_GDB_LINUX_INTEL64_FIOFF,
    REG_GDB_LINUX_INTEL64_FOSEG,
    REG_GDB_LINUX_INTEL64_FOOFF,
    REG_GDB_LINUX_INTEL64_FOP,
    REG_GDB_LINUX_INTEL64_XMM0,
    REG_GDB_LINUX_INTEL64_XMM1,
    REG_GDB_LINUX_INTEL64_XMM2,
    REG_GDB_LINUX_INTEL64_XMM3,
    REG_GDB_LINUX_INTEL64_XMM4,
    REG_GDB_LINUX_INTEL64_XMM5,
    REG_GDB_LINUX_INTEL64_XMM6,
    REG_GDB_LINUX_INTEL64_XMM7,
    REG_GDB_LINUX_INTEL64_XMM8,
    REG_GDB_LINUX_INTEL64_XMM9,
    REG_GDB_LINUX_INTEL64_XMM10,
    REG_GDB_LINUX_INTEL64_XMM11,
    REG_GDB_LINUX_INTEL64_XMM12,
    REG_GDB_LINUX_INTEL64_XMM13,
    REG_GDB_LINUX_INTEL64_XMM14,
    REG_GDB_LINUX_INTEL64_XMM15,
    REG_GDB_LINUX_INTEL64_MXCSR,
    REG_GDB_LINUX_INTEL64_ORIG_RAX,
    REG_GDB_LINUX_INTEL64_LAST = REG_GDB_LINUX_INTEL64_ORIG_RAX
};

} // namespace
#endif // file guard
