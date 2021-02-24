// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: MIT

#include "az_cbor_private.h"
#include "az_span_private.h"
#include <azure/core/az_precondition.h>
#include <azure/core/internal/az_result_internal.h>
#include <azure/core/internal/az_span_internal.h>

#include <ctype.h>

#include <azure/core/_az_cfg.h>

AZ_NODISCARD az_result az_cbor_reader_init(
    az_cbor_reader* out_cbor_reader,
    az_span cbor_buffer,
    az_cbor_reader_options const* options)
{
  _az_PRECONDITION(az_span_size(cbor_buffer) >= 1);

  *out_cbor_reader = (az_cbor_reader){
    .token = (az_cbor_token){
      .kind = AZ_CBOR_TOKEN_NONE,
      .slice = AZ_SPAN_EMPTY,
      .size = 0,
      ._internal = {
        .is_multisegment = false,
        .string_has_escaped_chars = false,
        .pointer_to_first_buffer = &AZ_SPAN_EMPTY,
        .start_buffer_index = -1,
        .start_buffer_offset = -1,
        .end_buffer_index = -1,
        .end_buffer_offset = -1,
      },
    },
    ._internal = {
      .cbor_buffer = cbor_buffer,
      .cbor_buffers = &AZ_SPAN_EMPTY,
      .number_of_buffers = 1,
      .buffer_index = 0,
      .bytes_consumed = 0,
      .total_bytes_consumed = 0,
      .is_complex_cbor = false,
      .bit_stack = { 0 },
      .options = options == NULL ? az_cbor_reader_options_default() : *options,
    },
  };
  return AZ_OK;
}

AZ_NODISCARD az_result az_cbor_reader_chunked_init(
    az_cbor_reader* out_cbor_reader,
    az_span cbor_buffers[],
    int32_t number_of_buffers,
    az_cbor_reader_options const* options)
{
  _az_PRECONDITION(number_of_buffers >= 1);
  _az_PRECONDITION(az_span_size(cbor_buffers[0]) >= 1);

  *out_cbor_reader = (az_cbor_reader){
    .token = (az_cbor_token){
      .kind = AZ_CBOR_TOKEN_NONE,
      .slice = AZ_SPAN_EMPTY,
      .size = 0,
      ._internal = {
        .is_multisegment = false,
        .string_has_escaped_chars = false,
        .pointer_to_first_buffer = cbor_buffers,
        .start_buffer_index = -1,
        .start_buffer_offset = -1,
        .end_buffer_index = -1,
        .end_buffer_offset = -1,
      },
    },
    ._internal = {
      .cbor_buffer = cbor_buffers[0],
      .cbor_buffers = cbor_buffers,
      .number_of_buffers = number_of_buffers,
      .buffer_index = 0,
      .bytes_consumed = 0,
      .total_bytes_consumed = 0,
      .is_complex_cbor = false,
      .bit_stack = { 0 },
      .options = options == NULL ? az_cbor_reader_options_default() : *options,
    },
  };
  return AZ_OK;
}

AZ_NODISCARD static az_span _get_remaining_cbor(az_cbor_reader* cbor_reader)
{
  _az_PRECONDITION_NOT_NULL(cbor_reader);

  return az_span_slice_to_end(
      cbor_reader->_internal.cbor_buffer, cbor_reader->_internal.bytes_consumed);
}

static void _az_cbor_reader_update_state(
    az_cbor_reader* ref_cbor_reader,
    az_cbor_token_kind token_kind,
    az_span token_slice,
    int32_t current_segment_consumed,
    int32_t consumed)
{
  ref_cbor_reader->token.kind = token_kind;
  ref_cbor_reader->token.size = consumed;

  ref_cbor_reader->_internal.bytes_consumed += current_segment_consumed;
  ref_cbor_reader->_internal.total_bytes_consumed += current_segment_consumed;

  // We should have already set start_buffer_index and offset before moving to the next buffer.
  ref_cbor_reader->token._internal.end_buffer_index = ref_cbor_reader->_internal.buffer_index;
  ref_cbor_reader->token._internal.end_buffer_offset = ref_cbor_reader->_internal.bytes_consumed;

  ref_cbor_reader->token._internal.is_multisegment = false;

  // Token straddles more than one segment
  int32_t start_index = ref_cbor_reader->token._internal.start_buffer_index;
  if (start_index != -1 && start_index < ref_cbor_reader->token._internal.end_buffer_index)
  {
    ref_cbor_reader->token._internal.is_multisegment = true;
  }

  ref_cbor_reader->token.slice = token_slice;
}

AZ_NODISCARD static az_result _az_cbor_reader_get_next_buffer(
    az_cbor_reader* ref_cbor_reader,
    az_span* remaining,
    bool skip_whitespace)
{
  // If we only had one buffer, or we ran out of the set of discontiguous buffers, return error.
  if (ref_cbor_reader->_internal.buffer_index >= ref_cbor_reader->_internal.number_of_buffers - 1)
  {
    return AZ_ERROR_UNEXPECTED_END;
  }

  if (!skip_whitespace && ref_cbor_reader->token._internal.start_buffer_index == -1)
  {
    ref_cbor_reader->token._internal.start_buffer_index = ref_cbor_reader->_internal.buffer_index;

    ref_cbor_reader->token._internal.start_buffer_offset
        = ref_cbor_reader->_internal.bytes_consumed;
  }

  ref_cbor_reader->_internal.buffer_index++;

  ref_cbor_reader->_internal.cbor_buffer
      = ref_cbor_reader->_internal.cbor_buffers[ref_cbor_reader->_internal.buffer_index];

  ref_cbor_reader->_internal.bytes_consumed = 0;

  az_span place_holder = _get_remaining_cbor(ref_cbor_reader);

  // Found an empty segment in the cbor_buffers array, which isn't allowed.
  if (az_span_size(place_holder) < 1)
  {
    return AZ_ERROR_UNEXPECTED_END;
  }

  *remaining = place_holder;
  return AZ_OK;
}

AZ_NODISCARD static az_span _az_cbor_reader_skip_whitespace(az_cbor_reader* ref_cbor_reader)
{
  az_span cbor;
  az_span remaining = _get_remaining_cbor(ref_cbor_reader);

  while (true)
  {
    cbor = _az_span_trim_whitespace_from_start(remaining);

    // Find out how many whitespace characters were trimmed.
    int32_t consumed = _az_span_diff(cbor, remaining);

    ref_cbor_reader->_internal.bytes_consumed += consumed;
    ref_cbor_reader->_internal.total_bytes_consumed += consumed;

    if (az_span_size(cbor) >= 1
        || az_result_failed(_az_cbor_reader_get_next_buffer(ref_cbor_reader, &remaining, true)))
    {
      break;
    }
  }

  return cbor;
}

AZ_NODISCARD static az_result _az_cbor_reader_process_container_end(
    az_cbor_reader* ref_cbor_reader,
    az_cbor_token_kind token_kind)
{
  // The cbor payload is invalid if it has a mismatched container end without a matching open.
  if ((token_kind == AZ_CBOR_TOKEN_END_OBJECT
       && _az_cbor_stack_peek(&ref_cbor_reader->_internal.bit_stack) != _az_CBOR_STACK_OBJECT)
      || (token_kind == AZ_CBOR_TOKEN_END_ARRAY
          && _az_cbor_stack_peek(&ref_cbor_reader->_internal.bit_stack) != _az_CBOR_STACK_ARRAY))
  {
    return AZ_ERROR_UNEXPECTED_CHAR;
  }

  az_span token = _get_remaining_cbor(ref_cbor_reader);
  _az_cbor_stack_pop(&ref_cbor_reader->_internal.bit_stack);
  _az_cbor_reader_update_state(ref_cbor_reader, token_kind, az_span_size(token) ? az_span_slice(token, 0, 1) : AZ_SPAN_EMPTY, 0, 1);
  return AZ_OK;
}

AZ_NODISCARD static az_result _az_cbor_reader_process_container_start(
    az_cbor_reader* ref_cbor_reader,
    az_cbor_token_kind token_kind,
    _az_cbor_stack_item container_kind)
{
  // The current depth is equal to or larger than the maximum allowed depth of 64. Cannot read the
  // next cbor object or array.
  if (ref_cbor_reader->_internal.bit_stack._internal.current_depth >= _az_MAX_cbor_STACK_SIZE)
  {
    return AZ_ERROR_CBOR_NESTING_OVERFLOW;
  }

  az_span token = _get_remaining_cbor(ref_cbor_reader);

  _az_cbor_stack_push(&ref_cbor_reader->_internal.bit_stack, container_kind);
  _az_cbor_reader_update_state(ref_cbor_reader, token_kind, az_span_slice(token, 0, 1), 1, 1);
  return AZ_OK;
}

AZ_NODISCARD static az_result _az_cbor_get_length(
    uint8_t type_id,
    uint8_t* token_ptr,
    uint32_t* element_length,
    uint32_t* token_header_len)
{
  if (type_id >= 0x00 && type_id <= 0x17)
  {
    *element_length = type_id - 0x00;
    *token_header_len = 0;
  }
  else if (type_id >= 0x18)
  {
    *element_length = token_ptr[1]; // 1
    *token_header_len = 1;
  }
  else if (type_id >= 0x19)
  {
    *element_length = (uint64_t)token_ptr[1] << 8; // 2
    *element_length |= (uint64_t)token_ptr[2];
    *token_header_len = 2;
  }
  else if (type_id >= 0x1A)
  {
    *element_length = (uint64_t)token_ptr[1] << 24; // 4
    *element_length |= (uint64_t)token_ptr[2] << 16;
    *element_length |= (uint64_t)token_ptr[3] << 8;
    *element_length |= (uint64_t)token_ptr[4];
    *token_header_len = 4;
  }
  else if (type_id >= 0x0B)
  {
    // 64bit not supported
    return AZ_ERROR_UNEXPECTED_CHAR;
  }
  else
  {
    return AZ_ERROR_UNEXPECTED_CHAR;
  }
  return AZ_OK;
}

AZ_NODISCARD static az_result _az_cbor_reader_process_string(az_cbor_reader* ref_cbor_reader)
{
  az_span token = _get_remaining_cbor(ref_cbor_reader);
  int32_t remaining_size = az_span_size(token);

  if (remaining_size < 1)
  {
    _az_RETURN_IF_FAILED(_az_cbor_reader_get_next_buffer(ref_cbor_reader, &token, false));
    remaining_size = az_span_size(token);
  }

  int32_t current_index = 0;
  uint32_t string_length = 0;
  uint8_t* token_ptr = az_span_ptr(token);
  uint8_t next_byte = token_ptr[0];

  uint32_t token_header_len;
  _az_RETURN_IF_FAILED(_az_cbor_get_length(
      next_byte - 0x60, token_ptr, &string_length, &token_header_len));

  token_ptr += token_header_len;
  remaining_size -= token_header_len;

  current_index = token_header_len + string_length;

    if (current_index >= remaining_size)
    {
        _az_RETURN_IF_FAILED(_az_cbor_reader_get_next_buffer(ref_cbor_reader, &token, false));
        current_index = 0;
        token_ptr = az_span_ptr(token);
        remaining_size = az_span_size(token);
    }

  _az_cbor_reader_update_state(
      ref_cbor_reader,
      AZ_CBOR_TOKEN_STRING,
        az_span_slice(token, token_header_len + 1, current_index + 1),
        current_index + 1,
        string_length);

  return AZ_OK;
}

AZ_NODISCARD static az_result _az_cbor_reader_process_property_name(az_cbor_reader* ref_cbor_reader)
{
  _az_RETURN_IF_FAILED(_az_cbor_reader_process_string(ref_cbor_reader));

  // We don't need to set the cbor_reader->token.slice since that was already done
  // in _az_cbor_reader_process_string when processing the string portion of the property name.
  // Therefore, we don't call _az_cbor_reader_update_state here.
  ref_cbor_reader->token.kind = AZ_CBOR_TOKEN_PROPERTY_NAME;

  return AZ_OK;
}

// Used to search for possible valid end of a number character, when we have complex cbor payloads
// (i.e. not a single cbor value).
// Whitespace characters, comma, or a container end character indicate the end of a cbor number.
static const az_span cbor_delimiters = AZ_SPAN_LITERAL_FROM_STR(",}] \n\r\t");

AZ_NODISCARD static bool _az_finished_consuming_cbor_number(
    uint8_t next_byte,
    az_span expected_next_bytes,
    az_result* out_result)
{
  az_span next_byte_span = az_span_create(&next_byte, 1);

  // Checking if we are done processing a cbor number
  int32_t index = az_span_find(cbor_delimiters, next_byte_span);
  if (index != -1)
  {
    *out_result = AZ_OK;
    return true;
  }

  // The next character after a "0" or a set of digits must either be a decimal or 'e'/'E' to
  // indicate scientific notation. For example "01" or "123f" is invalid.
  // The next character after "[-][digits].[digits]" must be 'e'/'E' if we haven't reached the end
  // of the number yet. For example, "1.1f" or "1.1-" are invalid.
  index = az_span_find(expected_next_bytes, next_byte_span);
  if (index == -1)
  {
    *out_result = AZ_ERROR_UNEXPECTED_CHAR;
    return true;
  }

  return false;
}

static void _az_cbor_reader_consume_digits(
    az_cbor_reader* ref_cbor_reader,
    az_span* token,
    int32_t* current_consumed,
    int32_t* total_consumed)
{
  int32_t counter = 0;
  az_span current = az_span_slice_to_end(*token, *current_consumed);
  while (true)
  {
    int32_t const token_size = az_span_size(current);
    uint8_t* next_byte_ptr = az_span_ptr(current);

    while (counter < token_size)
    {
      if (isdigit(*next_byte_ptr))
      {
        counter++;
        next_byte_ptr++;
      }
      else
      {
        break;
      }
    }
    if (counter == token_size
        && az_result_succeeded(_az_cbor_reader_get_next_buffer(ref_cbor_reader, token, false)))
    {
      *total_consumed += counter;
      counter = 0;
      *current_consumed = 0;
      current = *token;
      continue;
    }
    break;
  }

  *total_consumed += counter;
  *current_consumed += counter;
}

AZ_NODISCARD static az_result _az_cbor_reader_update_number_state_if_single_value(
    az_cbor_reader* ref_cbor_reader,
    az_span token_slice,
    int32_t current_consumed,
    int32_t total_consumed)
{
  if (ref_cbor_reader->_internal.is_complex_cbor)
  {
    return AZ_ERROR_UNEXPECTED_END;
  }

  _az_cbor_reader_update_state(
      ref_cbor_reader, AZ_CBOR_TOKEN_NUMBER, token_slice, current_consumed, total_consumed);

  return AZ_OK;
}

AZ_NODISCARD static az_result _az_validate_next_byte_is_digit(
    az_cbor_reader* ref_cbor_reader,
    az_span* remaining_number,
    int32_t* current_consumed)
{
  az_span current = az_span_slice_to_end(*remaining_number, *current_consumed);
  if (az_span_size(current) < 1)
  {
    _az_RETURN_IF_FAILED(_az_cbor_reader_get_next_buffer(ref_cbor_reader, remaining_number, false));
    current = *remaining_number;
    *current_consumed = 0;
  }

  if (!isdigit(az_span_ptr(current)[0]))
  {
    return AZ_ERROR_UNEXPECTED_CHAR;
  }

  return AZ_OK;
}

AZ_NODISCARD static az_result _az_cbor_reader_process_number(az_cbor_reader* ref_cbor_reader)
{
  az_span token = _get_remaining_cbor(ref_cbor_reader);

  int32_t total_consumed = 0;
  int32_t current_consumed = 0;

  uint8_t next_byte = az_span_ptr(token)[0];
  if (next_byte == '-')
  {
    total_consumed++;
    current_consumed++;

    // A negative sign must be followed by at least one digit.
    _az_RETURN_IF_FAILED(
        _az_validate_next_byte_is_digit(ref_cbor_reader, &token, &current_consumed));

    next_byte = az_span_ptr(token)[current_consumed];
  }

  if (next_byte == '0')
  {
    total_consumed++;
    current_consumed++;

    if (current_consumed >= az_span_size(token))
    {
      if (az_result_failed(_az_cbor_reader_get_next_buffer(ref_cbor_reader, &token, false)))
      {
        // If there is no more cbor, this is a valid end state only when the cbor payload contains a
        // single value: "[-]0"
        // Otherwise, the payload is incomplete and ending too early.
        return _az_cbor_reader_update_number_state_if_single_value(
            ref_cbor_reader,
            az_span_slice(token, 0, current_consumed),
            current_consumed,
            total_consumed);
      }
      current_consumed = 0;
    }

    next_byte = az_span_ptr(token)[current_consumed];
    az_result result = AZ_OK;
    if (_az_finished_consuming_cbor_number(next_byte, AZ_SPAN_FROM_STR(".eE"), &result))
    {
      if (az_result_succeeded(result))
      {
        _az_cbor_reader_update_state(
            ref_cbor_reader,
            AZ_CBOR_TOKEN_NUMBER,
            az_span_slice(token, 0, current_consumed),
            current_consumed,
            total_consumed);
      }
      return result;
    }
  }
  else
  {
    _az_PRECONDITION(isdigit(next_byte));

    // Integer part before decimal
    _az_cbor_reader_consume_digits(ref_cbor_reader, &token, &current_consumed, &total_consumed);

    if (current_consumed >= az_span_size(token))
    {
      if (az_result_failed(_az_cbor_reader_get_next_buffer(ref_cbor_reader, &token, false)))
      {
        // If there is no more cbor, this is a valid end state only when the cbor payload contains a
        // single value: "[-][digits]"
        // Otherwise, the payload is incomplete and ending too early.
        return _az_cbor_reader_update_number_state_if_single_value(
            ref_cbor_reader,
            az_span_slice(token, 0, current_consumed),
            current_consumed,
            total_consumed);
      }
      current_consumed = 0;
    }

    next_byte = az_span_ptr(token)[current_consumed];
    az_result result = AZ_OK;
    if (_az_finished_consuming_cbor_number(next_byte, AZ_SPAN_FROM_STR(".eE"), &result))
    {
      if (az_result_succeeded(result))
      {
        _az_cbor_reader_update_state(
            ref_cbor_reader,
            AZ_CBOR_TOKEN_NUMBER,
            az_span_slice(token, 0, current_consumed),
            current_consumed,
            total_consumed);
      }
      return result;
    }
  }

  if (next_byte == '.')
  {
    total_consumed++;
    current_consumed++;

    // A decimal point must be followed by at least one digit.
    _az_RETURN_IF_FAILED(
        _az_validate_next_byte_is_digit(ref_cbor_reader, &token, &current_consumed));

    // Integer part after decimal
    _az_cbor_reader_consume_digits(ref_cbor_reader, &token, &current_consumed, &total_consumed);

    if (current_consumed >= az_span_size(token))
    {
      if (az_result_failed(_az_cbor_reader_get_next_buffer(ref_cbor_reader, &token, false)))
      {
        // If there is no more cbor, this is a valid end state only when the cbor payload contains a
        // single value: "[-][digits].[digits]"
        // Otherwise, the payload is incomplete and ending too early.
        return _az_cbor_reader_update_number_state_if_single_value(
            ref_cbor_reader,
            az_span_slice(token, 0, current_consumed),
            current_consumed,
            total_consumed);
      }
      current_consumed = 0;
    }

    next_byte = az_span_ptr(token)[current_consumed];
    az_result result = AZ_OK;
    if (_az_finished_consuming_cbor_number(next_byte, AZ_SPAN_FROM_STR("eE"), &result))
    {
      if (az_result_succeeded(result))
      {
        _az_cbor_reader_update_state(
            ref_cbor_reader,
            AZ_CBOR_TOKEN_NUMBER,
            az_span_slice(token, 0, current_consumed),
            current_consumed,
            total_consumed);
      }
      return result;
    }
  }

  // Move past 'e'/'E'
  total_consumed++;
  current_consumed++;

  // The 'e'/'E' character must be followed by a sign or at least one digit.
  if (current_consumed >= az_span_size(token))
  {
    _az_RETURN_IF_FAILED(_az_cbor_reader_get_next_buffer(ref_cbor_reader, &token, false));
    current_consumed = 0;
  }

  next_byte = az_span_ptr(token)[current_consumed];
  if (next_byte == '-' || next_byte == '+')
  {
    total_consumed++;
    current_consumed++;

    // A sign must be followed by at least one digit.
    _az_RETURN_IF_FAILED(
        _az_validate_next_byte_is_digit(ref_cbor_reader, &token, &current_consumed));
  }

  // Integer part after the 'e'/'E'
  _az_cbor_reader_consume_digits(ref_cbor_reader, &token, &current_consumed, &total_consumed);

  if (current_consumed >= az_span_size(token))
  {
    if (az_result_failed(_az_cbor_reader_get_next_buffer(ref_cbor_reader, &token, false)))
    {

      // If there is no more cbor, this is a valid end state only when the cbor payload contains a
      // single value: "[-][digits].[digits]e[+|-][digits]"
      // Otherwise, the payload is incomplete and ending too early.
      return _az_cbor_reader_update_number_state_if_single_value(
          ref_cbor_reader,
          az_span_slice(token, 0, current_consumed),
          current_consumed,
          total_consumed);
    }
    current_consumed = 0;
  }

  // Checking if we are done processing a cbor number
  next_byte = az_span_ptr(token)[current_consumed];
  int32_t index = az_span_find(cbor_delimiters, az_span_create(&next_byte, 1));
  if (index == -1)
  {
    return AZ_ERROR_UNEXPECTED_CHAR;
  }

  _az_cbor_reader_update_state(
      ref_cbor_reader,
      AZ_CBOR_TOKEN_NUMBER,
      az_span_slice(token, 0, current_consumed),
      current_consumed,
      total_consumed);

  return AZ_OK;
}

AZ_INLINE int32_t _az_min(int32_t a, int32_t b) { return a < b ? a : b; }

AZ_NODISCARD static az_result _az_cbor_reader_process_literal(
    az_cbor_reader* ref_cbor_reader,
    az_span literal,
    az_cbor_token_kind kind)
{
  az_span token = _get_remaining_cbor(ref_cbor_reader);

  int32_t const expected_literal_size = az_span_size(literal);

  int32_t already_matched = 0;

  int32_t max_comparable_size = 0;
  while (true)
  {
    int32_t token_size = az_span_size(token);
    max_comparable_size = _az_min(token_size, expected_literal_size - already_matched);

    token = az_span_slice(token, 0, max_comparable_size);

    // Return if the subslice that can be compared contains a mismatch.
    if (!az_span_is_content_equal(
            token, az_span_slice(literal, already_matched, already_matched + max_comparable_size)))
    {
      return AZ_ERROR_UNEXPECTED_CHAR;
    }
    already_matched += max_comparable_size;

    if (already_matched == expected_literal_size)
    {
      break;
    }

    // If there is no more data, return EOF because the token is smaller than the expected literal.
    _az_RETURN_IF_FAILED(_az_cbor_reader_get_next_buffer(ref_cbor_reader, &token, false));
  }

  _az_cbor_reader_update_state(
      ref_cbor_reader, kind, token, max_comparable_size, expected_literal_size);
  return AZ_OK;
}

AZ_NODISCARD static az_result _az_cbor_reader_process_value(
    az_cbor_reader* ref_cbor_reader,
    uint8_t const next_byte)
{
  //if (next_byte == '"')
  //{
  //  return _az_cbor_reader_process_string(ref_cbor_reader);
  //}
  if (next_byte >= 0x60 && next_byte <= 0x7F)
  {
    uint32_t token_header_len;
    uint32_t token_element_len;
    (void)_az_cbor_get_length(
        next_byte - 0x80,
        az_span_ptr(ref_cbor_reader->token.slice),
        &token_element_len,
        &token_header_len);

    return _az_cbor_reader_process_string(ref_cbor_reader);
  }

  /*
  if (next_byte == '{')
  {
    return _az_cbor_reader_process_container_start(
        ref_cbor_reader, AZ_CBOR_TOKEN_BEGIN_OBJECT, _az_CBOR_STACK_OBJECT);
  }
  */
  if (next_byte >= 0xA0 && next_byte <= 0xBF)
  {
    uint32_t token_header_len;
    uint32_t token_element_len;
    (void) _az_cbor_get_length(
        next_byte - 0xA0, az_span_ptr(ref_cbor_reader->token.slice), &token_element_len, &token_header_len);

    az_result result =  _az_cbor_reader_process_container_start(ref_cbor_reader, AZ_CBOR_TOKEN_BEGIN_OBJECT, _az_CBOR_STACK_OBJECT);

    ref_cbor_reader->_internal
        .element_type[ref_cbor_reader->_internal.bit_stack._internal.current_depth]
        = 0xA0;
    ref_cbor_reader->_internal
        .element_len[ref_cbor_reader->_internal.bit_stack._internal.current_depth]
        = ((token_element_len) ) ;

    return result;
  }

  /*
  if (next_byte == '[')
  {
    return _az_cbor_reader_process_container_start(
        ref_cbor_reader, AZ_CBOR_TOKEN_BEGIN_ARRAY, _az_CBOR_STACK_ARRAY);
  }
  */
  if (next_byte >= 0x80 && next_byte <= 0x9F)
  {
    uint32_t token_header_len;
    uint32_t token_element_len;
    (void)_az_cbor_get_length(
        next_byte - 0x80,
        az_span_ptr(ref_cbor_reader->token.slice),
        &token_element_len,
        &token_header_len);

    az_result result =  _az_cbor_reader_process_container_start(ref_cbor_reader, AZ_CBOR_TOKEN_BEGIN_ARRAY, _az_CBOR_STACK_ARRAY);

    ref_cbor_reader->_internal
        .element_type[ref_cbor_reader->_internal.bit_stack._internal.current_depth]
        = 0x80;
    ref_cbor_reader->_internal
        .element_len[ref_cbor_reader->_internal.bit_stack._internal.current_depth]
        = token_element_len;
    return result;
  }


  if (isdigit(next_byte) || next_byte == '-')
  {
    return _az_cbor_reader_process_number(ref_cbor_reader);
  }

  if (next_byte == 'f')
  {
    return _az_cbor_reader_process_literal(
        ref_cbor_reader, AZ_SPAN_FROM_STR("false"), AZ_CBOR_TOKEN_FALSE);
  }

  if (next_byte == 't')
  {
    return _az_cbor_reader_process_literal(
        ref_cbor_reader, AZ_SPAN_FROM_STR("true"), AZ_CBOR_TOKEN_TRUE);
  }

  if (next_byte == 'n')
  {
    return _az_cbor_reader_process_literal(
        ref_cbor_reader, AZ_SPAN_FROM_STR("null"), AZ_CBOR_TOKEN_NULL);
  }

  return AZ_ERROR_UNEXPECTED_CHAR;
}

AZ_NODISCARD static az_result _az_cbor_reader_read_first_token(
    az_cbor_reader* ref_cbor_reader,
    az_span cbor,
    uint8_t const first_byte)
{
  if (first_byte >= 0xA0 && first_byte < 0xBB)  // map
  {
    _az_cbor_stack_push(&ref_cbor_reader->_internal.bit_stack, _az_CBOR_STACK_OBJECT);

    int32_t len_bytes = 0;


    uint32_t token_header_len;
    uint32_t token_element_len;
    _az_RETURN_IF_FAILED(_az_cbor_get_length(
        first_byte - 0xA0, az_span_ptr(cbor), &token_element_len, &token_header_len));

    len_bytes = token_header_len;
    ref_cbor_reader->_internal
        .element_type[ref_cbor_reader->_internal.bit_stack._internal.current_depth]
        = 0xA0;
    ref_cbor_reader->_internal
        .element_len[ref_cbor_reader->_internal.bit_stack._internal.current_depth]
        = token_element_len;

    _az_cbor_reader_update_state(
        ref_cbor_reader,
        AZ_CBOR_TOKEN_BEGIN_OBJECT,
        az_span_slice(cbor, 0, 1 + len_bytes),
        len_bytes + 1,
        len_bytes + 1);

//    ref_cbor_reader->_internal.bytes_consumed += (1 + len_bytes);
    ref_cbor_reader->_internal.is_complex_cbor = true;

    return AZ_OK;
  }

  /*
  if (first_byte == '{')
  {
    _az_cbor_stack_push(&ref_cbor_reader->_internal.bit_stack, _az_CBOR_STACK_OBJECT);

    _az_cbor_reader_update_state(
        ref_cbor_reader, AZ_CBOR_TOKEN_BEGIN_OBJECT, az_span_slice(cbor, 0, 1), 1, 1);

    ref_cbor_reader->_internal.is_complex_cbor = true;
    return AZ_OK;
  }
  */


  if (first_byte >= 0x80 && first_byte < 0x9F) // array
  {
    _az_cbor_stack_push(&ref_cbor_reader->_internal.bit_stack, _az_CBOR_STACK_ARRAY);

    uint32_t token_header_len;
    uint32_t token_element_len;
    _az_RETURN_IF_FAILED(_az_cbor_get_length(
        first_byte - 0x80, az_span_ptr(cbor), &token_element_len, &token_header_len));

    int32_t len_bytes = token_header_len;
    ref_cbor_reader->_internal
        .element_type[ref_cbor_reader->_internal.bit_stack._internal.current_depth]
        = 0x80;
    ref_cbor_reader->_internal
        .element_len[ref_cbor_reader->_internal.bit_stack._internal.current_depth]
        = token_element_len;

    _az_cbor_reader_update_state(
        ref_cbor_reader,
        AZ_CBOR_TOKEN_BEGIN_ARRAY,
        az_span_slice(cbor, 0, 1 + len_bytes),
        len_bytes,
        len_bytes);

    ref_cbor_reader->_internal.is_complex_cbor = true;
    ref_cbor_reader->_internal.bytes_consumed += (1 + len_bytes);

    return AZ_OK;
  }

  /*
  if (first_byte == '[')
  {
    _az_cbor_stack_push(&ref_cbor_reader->_internal.bit_stack, _az_CBOR_STACK_ARRAY);

    _az_cbor_reader_update_state(
        ref_cbor_reader, AZ_CBOR_TOKEN_BEGIN_ARRAY, az_span_slice(cbor, 0, 1), 1, 1);

    ref_cbor_reader->_internal.is_complex_cbor = true;
    return AZ_OK;
  }
  */

  return _az_cbor_reader_process_value(ref_cbor_reader, first_byte);
}

AZ_NODISCARD static az_result _az_cbor_reader_process_next_byte(
    az_cbor_reader* ref_cbor_reader,
    uint8_t next_byte)
{
  // Extra data after a single cbor value (complete object or array or one primitive value) is
  // invalid. Expected end of data.
  if (ref_cbor_reader->_internal.bit_stack._internal.current_depth == 0)
  {
    return AZ_ERROR_JSON_READER_DONE;
  }

  //bool within_object
  //    = _az_cbor_stack_peek(&ref_cbor_reader->_internal.bit_stack) == _az_CBOR_STACK_OBJECT;
  /*
  if (next_byte == ',')
  {
    ref_cbor_reader->_internal.bytes_consumed++;

    az_span cbor = _az_cbor_reader_skip_whitespace(ref_cbor_reader);

    // Expected start of a property name or value, but instead reached end of data.
    if (az_span_size(cbor) < 1)
    {
      return AZ_ERROR_UNEXPECTED_END;
    }

    next_byte = az_span_ptr(cbor)[0];

    if (within_object)
    {
      // Expected start of a property name after the comma since we are within a cbor object.
      if (next_byte != '"')
      {
        return AZ_ERROR_UNEXPECTED_CHAR;
      }
      return _az_cbor_reader_process_property_name(ref_cbor_reader);
    }

    return _az_cbor_reader_process_value(ref_cbor_reader, next_byte);
  }
  */
  if (ref_cbor_reader->_internal
          .element_len[ref_cbor_reader->_internal.bit_stack._internal.current_depth])
  {
    ref_cbor_reader->_internal
        .element_len[ref_cbor_reader->_internal.bit_stack._internal.current_depth]--;

      if (ref_cbor_reader->_internal
            .element_type[ref_cbor_reader->_internal.bit_stack._internal.current_depth]
            == 0xA0)
    {
        return _az_cbor_reader_process_property_name(ref_cbor_reader);
    }

    return _az_cbor_reader_process_value(ref_cbor_reader, next_byte);
  }

  //ref_cbor_reader->_internal
  //    .element_len[ref_cbor_reader->_internal.bit_stack._internal.current_depth-1]--;

  if (ref_cbor_reader->_internal
          .element_type[ref_cbor_reader->_internal.bit_stack._internal.current_depth] == 0xA0)
  {
    return _az_cbor_reader_process_container_end(ref_cbor_reader, AZ_CBOR_TOKEN_END_OBJECT);
  }

  if (ref_cbor_reader->_internal
          .element_type[ref_cbor_reader->_internal.bit_stack._internal.current_depth]
      == 0x80)
  {
    return _az_cbor_reader_process_container_end(ref_cbor_reader, AZ_CBOR_TOKEN_END_ARRAY);
  }

  // No other character is a valid token delimiter within cbor.
  return AZ_ERROR_UNEXPECTED_CHAR;
}

AZ_NODISCARD az_result az_cbor_reader_next_token(az_cbor_reader* ref_cbor_reader)
{
  _az_PRECONDITION_NOT_NULL(ref_cbor_reader);

  az_span cbor = ref_cbor_reader->_internal.cbor_buffer;
  if (az_span_size(cbor) < 1)
  {
    if (ref_cbor_reader->token.kind == AZ_CBOR_TOKEN_NONE
        || ref_cbor_reader->_internal.bit_stack._internal.current_depth != 0)
    {
      // An empty cbor payload is invalid.
      return AZ_ERROR_UNEXPECTED_END;
    }

    // No more cbor text left to process, we are done.
    return AZ_ERROR_CBOR_READER_DONE;
  }

  // Clear the internal state of any previous token.
  ref_cbor_reader->token._internal.start_buffer_index = -1;
  ref_cbor_reader->token._internal.start_buffer_offset = -1;
  ref_cbor_reader->token._internal.end_buffer_index = -1;
  ref_cbor_reader->token._internal.end_buffer_offset = -1;

  uint8_t const first_byte = az_span_ptr(cbor)[ref_cbor_reader->_internal.bytes_consumed];

  switch (ref_cbor_reader->token.kind)
  {
    case AZ_CBOR_TOKEN_NONE:
    {
      return _az_cbor_reader_read_first_token(ref_cbor_reader, cbor, first_byte);
    }
    case AZ_CBOR_TOKEN_BEGIN_OBJECT:
    {
      if (ref_cbor_reader->_internal.element_len[ref_cbor_reader->_internal.bit_stack._internal.current_depth]
          == 0 /*first_byte == '}'*/)
      {
        return _az_cbor_reader_process_container_end(ref_cbor_reader, AZ_CBOR_TOKEN_END_OBJECT);
      }
      ref_cbor_reader->_internal
          .element_len[ref_cbor_reader->_internal.bit_stack._internal.current_depth]--;

      return _az_cbor_reader_process_property_name(ref_cbor_reader);
    }
    case AZ_CBOR_TOKEN_BEGIN_ARRAY:
    {
      if (ref_cbor_reader->_internal.element_len[ref_cbor_reader->_internal.bit_stack._internal.current_depth]
          == 0 /*first_byte == '}'*/)
      {
        return _az_cbor_reader_process_container_end(ref_cbor_reader, AZ_CBOR_TOKEN_END_ARRAY);
      }
      ref_cbor_reader->_internal
          .element_len[ref_cbor_reader->_internal.bit_stack._internal.current_depth]--;

      return _az_cbor_reader_process_value(ref_cbor_reader, first_byte);
    }
    case AZ_CBOR_TOKEN_PROPERTY_NAME:
      return _az_cbor_reader_process_value(ref_cbor_reader, first_byte);
    case AZ_CBOR_TOKEN_END_OBJECT:
    case AZ_CBOR_TOKEN_END_ARRAY:
    case AZ_CBOR_TOKEN_STRING:
    case AZ_CBOR_TOKEN_NUMBER:
    case AZ_CBOR_TOKEN_TRUE:
    case AZ_CBOR_TOKEN_FALSE:
    case AZ_CBOR_TOKEN_NULL:
      return _az_cbor_reader_process_next_byte(ref_cbor_reader, first_byte);
    default:
      return AZ_ERROR_CBOR_INVALID_STATE;
  }
}

AZ_NODISCARD az_result az_cbor_reader_skip_children(az_cbor_reader* ref_cbor_reader)
{
  _az_PRECONDITION_NOT_NULL(ref_cbor_reader);

  if (ref_cbor_reader->token.kind == AZ_CBOR_TOKEN_PROPERTY_NAME)
  {
    _az_RETURN_IF_FAILED(az_cbor_reader_next_token(ref_cbor_reader));
  }

  az_cbor_token_kind const token_kind = ref_cbor_reader->token.kind;
  if (token_kind == AZ_CBOR_TOKEN_BEGIN_OBJECT || token_kind == AZ_CBOR_TOKEN_BEGIN_ARRAY)
  {
    // Keep moving the reader until we come back to the same depth.
    int32_t const depth = ref_cbor_reader->_internal.bit_stack._internal.current_depth;
    do
    {
      _az_RETURN_IF_FAILED(az_cbor_reader_next_token(ref_cbor_reader));
    } while (depth <= ref_cbor_reader->_internal.bit_stack._internal.current_depth);
  }
  return AZ_OK;
}
