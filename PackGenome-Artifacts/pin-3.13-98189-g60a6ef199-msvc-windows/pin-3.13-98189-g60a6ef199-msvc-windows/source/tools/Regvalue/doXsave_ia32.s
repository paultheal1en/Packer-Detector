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

#include "asm_macros.h"

.data
.extern xsaveArea
.extern flags

.text

# void DoXsave();
# This function calls xsave and stores the FP state in the given dst area.
# The caller is expected to allocate enough space for the xsave area.
# The function expects the given dst pointer to be properly aligned for the xsave instruction.
DECLARE_FUNCTION_AS(DoXsave)
DoXsave:
    mov     (flags), %eax
    lea     xsaveArea, %ecx
    xor     %edx, %edx

    # Do xsave
    xsave   (%ecx)

    ret

# void DoXsaveOpt();
# This function calls xsaveopt and stores the FP state in the given dst area.
# The caller is expected to allocate enough space for the xsaveopt area.
# The function expects the given dst pointer to be properly aligned for the xsaveopt instruction.
DECLARE_FUNCTION_AS(DoXsaveOpt)
DoXsaveOpt:
    mov     (flags), %eax
    lea     xsaveArea, %ecx
    xor     %edx, %edx

    # Do xsaveopt
    xsaveopt   (%ecx)

    ret

# void DoXrstor();
# This function calls xrstor and restores the specified thetures from the xsave dst area.
# The function expects the given dst pointer to be properly aligned
DECLARE_FUNCTION_AS(DoXrstor)
DoXrstor:
    mov     (flags), %eax
    lea     xsaveArea, %ecx
    xor     %edx, %edx

    # Do xrstor
    xrstor   (%ecx)

    ret

# void DoFxsave();
# This function calls fxsave and stores the legacy FP state in the given dst area.
# The caller is expected to allocate enough space for the fxsave area.
# The function expects the given dst pointer to be properly aligned for the xsave instruction.
DECLARE_FUNCTION_AS(DoFxsave)
DoFxsave:
    lea     xsaveArea, %ecx

    # Do fxsave
    fxsave   (%ecx)

    ret

# void DoFxrstor();
# This function calls fxrstor and restores the legacy FP state fxsave dst area.
# The function expects the given dst pointer to be properly aligned
DECLARE_FUNCTION_AS(DoFxrstor)
DoFxrstor:
    lea     xsaveArea, %ecx

    # Do fxrstor
    fxrstor   (%ecx)

    ret
