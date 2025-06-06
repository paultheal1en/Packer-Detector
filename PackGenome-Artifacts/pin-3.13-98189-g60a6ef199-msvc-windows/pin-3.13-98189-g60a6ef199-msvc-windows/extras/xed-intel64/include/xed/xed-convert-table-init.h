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
/// @file xed-convert-table-init.h

// This file was automatically generated.
// Do not edit this file.

#if !defined(XED_CONVERT_TABLE_INIT_H)
# define XED_CONVERT_TABLE_INIT_H
#include "xed-internal-header.h"
typedef struct {

   const char** table_name;

   xed_operand_enum_t opnd;

   unsigned int limit;

} xed_convert_table_t;
extern xed_convert_table_t xed_convert_table[XED_OPERAND_CONVERT_LAST];
#endif
