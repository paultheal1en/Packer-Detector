/*BEGIN_LEGAL 
Copyright 2002-2019 Intel Corporation.

This software and the related documents are Intel copyrighted materials, and your
use of them is governed by the express license under which they were provided to
you ("License"). Unless the License provides otherwise, you may not use, modify,
copy, publish, distribute, disclose or transmit this software or the related
documents without Intel's prior written permission.

This software and the related documents are provided as is, with no express or
implied warranties, other than those that are expressly stated in the License.
END_LEGAL */

#if !defined(XED_PRINT_INFO_H)
# define XED_PRINT_INFO_H

#include "xed-types.h"
#include "xed-decoded-inst.h"
#include "xed-disas.h" // callback function type
#include "xed-syntax-enum.h" 
#include "xed-format-options.h"

/// @ingroup PRINT
/// This contains the information used by the various disassembly printers.
/// Call xed_init_print_info to initialize the fields.  Then change the
/// required and optional fields when required.
typedef struct {

    /////////////////////////////////////////
    // REQUIRED FIELDS - users should set these
    /////////////////////////////////////////
    
    /// the decoded instruction to print
    const xed_decoded_inst_t* p;

    /// pointer to the output buffer
    char* buf;

    /// length of the output buffer. (bytes) Must be > 25 to start.
    int blen;

    /////////////////////////////////////////
    // OPTIONAL FIELDS - user can set these
    /////////////////////////////////////////
    
    /// program counter location. Must be zero if not used.  (Sometimes
    /// instructions are disassembled in a temporary buffer at a different
    /// location than where they may or will exist in memory).
    xed_uint64_t runtime_address;

    /// disassembly_callback MUST be set to zero if not used!  If zero, the
    /// default disassembly callback is used (if one has been registered).
    xed_disassembly_callback_fn_t disassembly_callback;

    /// passed to disassembly callback. Can be zero if not used.
    void* context; 

    /// default is Intel-syntax (dest on left)
    xed_syntax_enum_t syntax; 

    /// 1=indicated the format_options field is valid, 0=use default
    /// formatting options from xed_format_set_options().
    int format_options_valid;  
    xed_format_options_t format_options;

    
    /////////////////////////////////////////
    // NONPUBLIC FIELDS - Users should not use these!
    /////////////////////////////////////////

    /// internal, do not use
    xed_bool_t emitted;
    
    /// internal, do not use
    unsigned int operand_indx;
    
    /// internal, do not use
    unsigned int skip_operand;

    /// internal, do not use
    xed_reg_enum_t extra_index_operand; // for MPX

    /// internal, do not use
    xed_bool_t implicit;

} xed_print_info_t;

// This function initializes the #xed_print_info_t structure.
// You must still set the required fields of that structure.
/// @ingroup PRINT
XED_DLL_EXPORT void xed_init_print_info(xed_print_info_t* pi);

#endif
