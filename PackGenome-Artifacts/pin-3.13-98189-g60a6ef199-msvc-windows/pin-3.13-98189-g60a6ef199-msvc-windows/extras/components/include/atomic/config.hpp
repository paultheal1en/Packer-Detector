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

// <COMPONENT>: atomic
// <FILE-TYPE>: component public header

#ifndef ATOMIC_CONFIG_HPP
#define ATOMIC_CONFIG_HPP


/*! @defgroup CONFIG Configuration
 *
 * The ATOMIC library can be configured by redefining the following macros
 * prior to including "atomic.hpp".
 *
 * \par ATOMIC_ASSERT
 * The ATOMIC library contains some internal assertion checks in its header
 * files.  By default, these assertion checks use the <cassert> implementation.
 * In order to override this, define ATOMIC_ASSERT to the name of a macro or
 * function that takes a single argument.
 *
 * \par ATOMIC_NO_ASSERT   
 * Define this macro in order to disable all internal assertion checks in the
 * ATOMIC header files.
 *
 * \par ATOMIC_NO_ASSERTSLOW
 * Some of the ATOMIC assertion checks could be particularly slow.  Define this
 * macro in order to disable just the slow assertion checks.
 */

// Define the macro for normal asserts.
//
#if defined(ATOMIC_NO_ASSERT)
#   define ATOMIC_CHECK_ASSERT(x) (static_cast<void>(0))
#elif !defined(ATOMIC_ASSERT)
#   include <cassert>
#   define ATOMIC_CHECK_ASSERT(x) assert(x)
#else
#   define ATOMIC_CHECK_ASSERT(x) ATOMIC_ASSERT(x)
#endif

// Define the macro for slow asserts.
//
#if defined(ATOMIC_NO_ASSERTSLOW)
#   define ATOMIC_CHECK_ASSERTSLOW(x) ((void)0)
#else
#   define ATOMIC_CHECK_ASSERTSLOW(x) ATOMIC_CHECK_ASSERT(x)
#endif

#endif // file guard
