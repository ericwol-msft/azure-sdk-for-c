// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: MIT

#ifndef _az_CBOR_PRIVATE_H
#define _az_CBOR_PRIVATE_H

#include <azure/core/az_cbor.h>
#include <azure/core/internal/az_precondition_internal.h>

#include <azure/core/_az_cfg_prefix.h>

#define _az_CBOR_TOKEN_DEFAULT                     \
  (az_cbor_token)                                  \
  {                                                \
    .kind = AZ_cbor_TOKEN_NONE, ._internal = { 0 } \
  }

enum
{
  // We are using a uint64_t to represent our nested state, so we can only go 64 levels deep.
  // This is safe to do because sizeof will not dereference the pointer and is used to find the size
  // of the field used as the stack.
  _az_MAX_cbor_STACK_SIZE = sizeof(((_az_cbor_bit_stack*)0)->_internal.az_cbor_stack) * 8 // 64
};

enum
{
  // Max size for an already escaped string value (~ half of INT_MAX)
  _az_MAX_ESCAPED_STRING_SIZE = 1000000000,

  // In the worst case, an ASCII character represented as a single UTF-8 byte could expand 6x when
  // escaped.
  // For example: '+' becomes '\u0043'
  // Escaping surrogate pairs (represented by 3 or 4 UTF-8 bytes) would expand to 12 bytes (which is
  // still <= 6x).
  _az_MAX_EXPANSION_FACTOR_WHILE_ESCAPING = 6,

  _az_MAX_UNESCAPED_STRING_SIZE
  = _az_MAX_ESCAPED_STRING_SIZE / _az_MAX_EXPANSION_FACTOR_WHILE_ESCAPING, // 166_666_666 bytes

  // [-][0-9]{16}.[0-9]{15}, i.e. 1+16+1+15 since _az_MAX_SUPPORTED_FRACTIONAL_DIGITS is 15
  _az_MAX_SIZE_FOR_WRITING_DOUBLE = 33,

  // When writing large cbor strings in chunks, ask for at least 64 bytes, to avoid writing one
  // character at a time.
  // This value should be between 12 and 512 (inclusive).
  // In the worst case, a 4-byte UTF-8 character, that needs to be escaped using the \uXXXX UTF-16
  // format, will need 12 bytes, for the two UTF-16 escaped characters (high/low surrogate pairs).
  // Anything larger than 512 is not feasible since it is difficult for embedded devices to have
  // such large blocks of contiguous memory available.
  _az_MINIMUM_STRING_CHUNK_SIZE = 64,

  // We need 2 bytes for the quotes, potentially one more for the comma to separate items, and one
  // more for the colon if writing a property name. Therefore, only a maximum of 10 character
  // strings are guaranteed to fit into a single 64 byte chunk, if all 10 needed to be escaped (i.e.
  // multiply by 6). 10 * 6 + 4 = 64, and that fits within _az_MINIMUM_STRING_CHUNK_SIZE
  _az_MAX_UNESCAPED_STRING_SIZE_PER_CHUNK = 10,

  // The number of unique values in base 16 (hexadecimal).
  _az_NUMBER_OF_HEX_VALUES = 16,
};

typedef enum
{
  _az_CBOR_STACK_OBJECT = 1,
  _az_CBOR_STACK_ARRAY = 0,
} _az_cbor_stack_item;

AZ_INLINE _az_cbor_stack_item _az_cbor_stack_pop(_az_cbor_bit_stack* ref_cbor_stack)
{
  _az_PRECONDITION(
      ref_cbor_stack->_internal.current_depth > 0
      && ref_cbor_stack->_internal.current_depth <= _az_MAX_cbor_STACK_SIZE);

  // Don't do the right bit shift if we are at the last bit in the stack.
  if (ref_cbor_stack->_internal.current_depth != 0)
  {
    ref_cbor_stack->_internal.az_cbor_stack >>= 1U;

    // We don't want current_depth to become negative, in case preconditions are off, and if
    // append_container_end is called before append_X_start.
    ref_cbor_stack->_internal.current_depth--;
  }

  // true (i.e. 1) means _az_cbor_STACK_OBJECT, while false (i.e. 0) means _az_cbor_STACK_ARRAY
  return (ref_cbor_stack->_internal.az_cbor_stack & 1U) != 0 ? _az_CBOR_STACK_OBJECT
                                                             : _az_CBOR_STACK_ARRAY;
}

AZ_INLINE void _az_cbor_stack_push(_az_cbor_bit_stack* ref_cbor_stack, _az_cbor_stack_item item)
{
  _az_PRECONDITION(
      ref_cbor_stack->_internal.current_depth >= 0
      && ref_cbor_stack->_internal.current_depth < _az_MAX_cbor_STACK_SIZE);

  ref_cbor_stack->_internal.current_depth++;
  ref_cbor_stack->_internal.az_cbor_stack <<= 1U;
  ref_cbor_stack->_internal.az_cbor_stack |= (uint32_t)item;
}

AZ_NODISCARD AZ_INLINE _az_cbor_stack_item _az_cbor_stack_peek(_az_cbor_bit_stack const* cbor_stack)
{
  _az_PRECONDITION(
      cbor_stack->_internal.current_depth >= 0
      && cbor_stack->_internal.current_depth <= _az_MAX_cbor_STACK_SIZE);

  // true (i.e. 1) means _az_cbor_STACK_OBJECT, while false (i.e. 0) means _az_cbor_STACK_ARRAY
  return (cbor_stack->_internal.az_cbor_stack & 1U) != 0 ? _az_CBOR_STACK_OBJECT
                                                         : _az_CBOR_STACK_ARRAY;
}

#include <azure/core/_az_cfg_suffix.h>

#endif // _az_CBOR_PRIVATE_H
