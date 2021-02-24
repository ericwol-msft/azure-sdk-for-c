// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: MIT

/**
 * @file
 *
 * @brief This header defines the types and functions your application uses to read or write cbor
 * objects.
 *
 * @note You MUST NOT use any symbols (macros, functions, structures, enums, etc.)
 * prefixed with an underscore ('_') directly in your application code. These symbols
 * are part of Azure SDK's internal implementation; we do not document these symbols
 * and they are subject to change in future versions of the SDK which would break your code.
 */

#ifndef _az_CBOR_H
#define _az_CBOR_H

#include <azure/core/az_result.h>
#include <azure/core/az_span.h>

#include <stdbool.h>
#include <stdint.h>

#include <azure/core/_az_cfg_prefix.h>

/**
 * @brief Defines symbols for the various kinds of cbor tokens that make up any cbor text.
 */
typedef enum
{
  AZ_CBOR_TOKEN_NONE, ///< There is no value (as distinct from #AZ_CBOR_TOKEN_NULL).
  AZ_CBOR_TOKEN_BEGIN_OBJECT, ///< The token kind is the start of a cbor object.
  AZ_CBOR_TOKEN_END_OBJECT, ///< The token kind is the end of a cbor object.
  AZ_CBOR_TOKEN_BEGIN_ARRAY, ///< The token kind is the start of a cbor array.
  AZ_CBOR_TOKEN_END_ARRAY, ///< The token kind is the end of a cbor array.
  AZ_CBOR_TOKEN_PROPERTY_NAME, ///< The token kind is a cbor property name.
  AZ_CBOR_TOKEN_STRING, ///< The token kind is a cbor string.
  AZ_CBOR_TOKEN_NUMBER, ///< The token kind is a cbor number.
  AZ_CBOR_TOKEN_TRUE, ///< The token kind is the cbor literal `true`.
  AZ_CBOR_TOKEN_FALSE, ///< The token kind is the cbor literal `false`.
  AZ_CBOR_TOKEN_NULL, ///< The token kind is the cbor literal `null`.
} az_cbor_token_kind;

/**
 * @brief A limited stack used by the #az_cbor_writer and #az_cbor_reader to track state information
 * for processing and validation.
 */
typedef struct
{
  struct
  {
    // This uint64_t container represents a tiny stack to track the state during nested transitions.
    // The first bit represents the state of the current depth (1 == object, 0 == array).
    // Each subsequent bit is the parent / containing type (object or array).
    uint64_t az_cbor_stack;
    int32_t current_depth;
  } _internal;
} _az_cbor_bit_stack;

/**
 * @brief Represents a cbor token. The kind field indicates the type of the cbor token and the slice
 * represents the portion of the cbor payload that points to the token value.
 *
 * @remarks An instance of #az_cbor_token must not outlive the lifetime of the #az_cbor_reader it
 * came from.
 */
typedef struct
{
  /// This read-only field gives access to the slice of the cbor text that represents the token
  /// value, and it shouldn't be modified by the caller.
  /// If the token straddles non-contiguous buffers, this is set to the partial token value
  /// available in the last segment.
  /// The user can call #az_cbor_token_copy_into_span() to get the token value into a contiguous
  /// buffer.
  /// In the case of cbor strings, the slice does not include the surrounding quotes.
  az_span slice;

  // Avoid using enum as the first field within structs, to allow for { 0 } initialization.
  // This is a workaround for IAR compiler warning [Pe188]: enumerated type mixed with another type.

  /// This read-only field gives access to the type of the token returned by the #az_cbor_reader,
  /// and it shouldn't be modified by the caller.
  az_cbor_token_kind kind;

  /// This read-only field gives access to the size of the cbor text slice that represents the token
  /// value, and it shouldn't be modified by the caller. This is useful if the token straddles
  /// non-contiguous buffers, to figure out what sized destination buffer to provide when calling
  /// #az_cbor_token_copy_into_span().
  int32_t size;

  struct
  {
    /// A flag to indicate whether the cbor token straddles more than one buffer segment and is
    /// split amongst non-contiguous buffers. For tokens created from input cbor payloads within a
    /// contiguous buffer, this field is always false.
    bool is_multisegment;

    /// A flag to indicate whether the cbor string contained any escaped characters, used as an
    /// optimization to avoid redundant checks. It is meaningless for any other token kind.
    bool string_has_escaped_chars;

    /// This is the first segment in the entire cbor payload, if it was non-contiguous. Otherwise,
    /// its set to #AZ_SPAN_EMPTY.
    az_span* pointer_to_first_buffer;

    /// The segment index within the non-contiguous cbor payload where this token starts.
    int32_t start_buffer_index;

    /// The offset within the particular segment within which this token starts.
    int32_t start_buffer_offset;

    /// The segment index within the non-contiguous cbor payload where this token ends.
    int32_t end_buffer_index;

    /// The offset within the particular segment within which this token ends.
    int32_t end_buffer_offset;
  } _internal;
} az_cbor_token;

// TODO: Should the parameters be reversed?
/**
 * @brief Copies the content of the \p token #az_cbor_token to the \p destination #az_span.
 *
 * @param[in] cbor_token A pointer to an #az_cbor_token instance containing the cbor text to copy to
 * the \p destination.
 * @param destination The #az_span whose bytes will be replaced by the cbor text from the \p
 * cbor_token.
 *
 * @return An #az_span that is a slice of the \p destination #az_span (i.e. the remainder) after the
 * token bytes have been copied.
 *
 * @remarks The function assumes that the \p destination has a large enough size to hold the
 * contents of \p cbor_token.
 *
 * @remarks If \p cbor_token doesn't contain any text, this function will just return \p
 * destination.
 */
az_span az_cbor_token_copy_into_span(az_cbor_token const* cbor_token, az_span destination);

/**
 * @brief Gets the cbor token's boolean.
 *
 * @param[in] cbor_token A pointer to an #az_cbor_token instance.
 * @param[out] out_value A pointer to a variable to receive the value.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The boolean value is returned.
 * @retval #AZ_ERROR_cbor_INVALID_STATE The kind is not #AZ_cbor_TOKEN_TRUE or #AZ_cbor_TOKEN_FALSE.
 */
AZ_NODISCARD az_result az_cbor_token_get_boolean(az_cbor_token const* cbor_token, bool* out_value);

/**
 * @brief Gets the cbor token's number as a 64-bit unsigned integer.
 *
 * @param[in] cbor_token A pointer to an #az_cbor_token instance.
 * @param[out] out_value A pointer to a variable to receive the value.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The number is returned.
 * @retval #AZ_ERROR_cbor_INVALID_STATE The kind is not #AZ_cbor_TOKEN_NUMBER.
 * @retval #AZ_ERROR_UNEXPECTED_CHAR A non-ASCII digit is found within the \p cbor_token or \p
 * cbor_token contains a number that would overflow or underflow `uint64_t`.
 */
AZ_NODISCARD az_result
az_cbor_token_get_uint64(az_cbor_token const* cbor_token, uint64_t* out_value);

/**
 * @brief Gets the cbor token's number as a 32-bit unsigned integer.
 *
 * @param[in] cbor_token A pointer to an #az_cbor_token instance.
 * @param[out] out_value A pointer to a variable to receive the value.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The number is returned.
 * @retval #AZ_ERROR_cbor_INVALID_STATE The kind is not #AZ_cbor_TOKEN_NUMBER.
 * @retval #AZ_ERROR_UNEXPECTED_CHAR A non-ASCII digit is found within the token or if it contains a
 * number that would overflow or underflow `uint32_t`.
 */
AZ_NODISCARD az_result
az_cbor_token_get_uint32(az_cbor_token const* cbor_token, uint32_t* out_value);

/**
 * @brief Gets the cbor token's number as a 64-bit signed integer.
 *
 * @param[in] cbor_token A pointer to an #az_cbor_token instance.
 * @param[out] out_value A pointer to a variable to receive the value.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The number is returned.
 * @retval #AZ_ERROR_cbor_INVALID_STATE The kind is not #AZ_cbor_TOKEN_NUMBER.
 * @retval #AZ_ERROR_UNEXPECTED_CHAR A non-ASCII digit is found within the token or if it contains
 * a number that would overflow or underflow `int64_t`.
 */
AZ_NODISCARD az_result az_cbor_token_get_int64(az_cbor_token const* cbor_token, int64_t* out_value);

/**
 * @brief Gets the cbor token's number as a 32-bit signed integer.
 *
 * @param[in] cbor_token A pointer to an #az_cbor_token instance.
 * @param[out] out_value A pointer to a variable to receive the value.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The number is returned.
 * @retval #AZ_ERROR_cbor_INVALID_STATE The kind is not #AZ_cbor_TOKEN_NUMBER.
 * @retval #AZ_ERROR_UNEXPECTED_CHAR A non-ASCII digit is found within the token or if it contains a
 * number that would overflow or underflow `int32_t`.
 */
AZ_NODISCARD az_result az_cbor_token_get_int32(az_cbor_token const* cbor_token, int32_t* out_value);

/**
 * @brief Gets the cbor token's number as a `double`.
 *
 * @param[in] cbor_token A pointer to an #az_cbor_token instance.
 * @param[out] out_value A pointer to a variable to receive the value.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The number is returned.
 * @retval #AZ_ERROR_cbor_INVALID_STATE The kind is not #AZ_cbor_TOKEN_NUMBER.
 * @retval #AZ_ERROR_UNEXPECTED_CHAR The resulting \p out_value wouldn't be a finite double number.
 */
AZ_NODISCARD az_result az_cbor_token_get_double(az_cbor_token const* cbor_token, double* out_value);

/**
 * @brief Gets the cbor token's string after unescaping it, if required.
 *
 * @param[in] cbor_token A pointer to an #az_cbor_token instance.
 * @param destination A pointer to a buffer where the string should be copied into.
 * @param[in] destination_max_size The maximum available space within the buffer referred to by
 * \p destination.
 * @param[out] out_string_length __[nullable]__ Contains the number of bytes written to the \p
 * destination which denote the length of the unescaped string. If `NULL` is passed, the parameter
 * is ignored.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The string is returned.
 * @retval #AZ_ERROR_cbor_INVALID_STATE The kind is not #AZ_cbor_TOKEN_STRING.
 * @retval #AZ_ERROR_NOT_ENOUGH_SPACE \p destination does not have enough size.
 */
AZ_NODISCARD az_result az_cbor_token_get_string(
    az_cbor_token const* cbor_token,
    char* destination,
    int32_t destination_max_size,
    int32_t* out_string_length);

/**
 * @brief Determines whether the unescaped cbor token value that the #az_cbor_token points to is
 * equal to the expected text within the provided byte span by doing a case-sensitive comparison.
 *
 * @param[in] cbor_token A pointer to an #az_cbor_token instance containing the cbor string token.
 * @param[in] expected_text The lookup text to compare the token against.
 *
 * @return `true` if the current cbor token value in the cbor source semantically matches the
 * expected lookup text, with the exact casing; otherwise, `false`.
 *
 * @remarks This operation is only valid for the string and property name token kinds. For all other
 * token kinds, it returns false.
 */
AZ_NODISCARD bool az_cbor_token_is_text_equal(
    az_cbor_token const* cbor_token,
    az_span expected_text);

/************************************ cbor WRITER ******************/

/**
 * @brief Allows the user to define custom behavior when writing cbor using the #az_cbor_writer.
 */
typedef struct
{
  struct
  {
    /// Currently, this is unused, but needed as a placeholder since we can't have an empty struct.
    bool unused;
  } _internal;
} az_cbor_writer_options;

/**
 * @brief Gets the default cbor writer options which builds minimized cbor (with no extra white
 * space) according to the cbor RFC.
 *
 * @details Call this to obtain an initialized #az_cbor_writer_options structure that can be
 * modified and passed to #az_cbor_writer_init().
 *
 * @return The default #az_cbor_writer_options.
 */
AZ_NODISCARD AZ_INLINE az_cbor_writer_options az_cbor_writer_options_default()
{
  az_cbor_writer_options options = (az_cbor_writer_options) {
    ._internal = {
      .unused = false,
    },
  };

  return options;
}

/**
 * @brief Provides forward-only, non-cached writing of UTF-8 encoded cbor text into the provided
 * buffer.
 *
 * @remarks #az_cbor_writer builds the text sequentially with no caching and by default adheres to
 * the cbor RFC: https://tools.ietf.org/html/rfc8259.
 */
typedef struct
{
  struct
  {
    az_span destination_buffer;
    int32_t bytes_written;
    // For single contiguous buffer, bytes_written == total_bytes_written
    int32_t total_bytes_written; // Currently, this is primarily used for testing.
    az_span_allocator_fn allocator_callback;
    void* user_context;
    bool need_comma;
    az_cbor_token_kind token_kind; // needed for validation, potentially #if/def with preconditions.
    _az_cbor_bit_stack bit_stack; // needed for validation, potentially #if/def with preconditions.
    az_cbor_writer_options options;
  } _internal;
} az_cbor_writer;

/**
 * @brief Initializes an #az_cbor_writer which writes cbor text into a buffer.
 *
 * @param[out] out_cbor_writer A pointer to an #az_cbor_writer instance to initialize.
 * @param destination_buffer An #az_span over the byte buffer where the cbor text is to be written.
 * @param[in] options __[nullable]__ A reference to an #az_cbor_writer_options
 * structure which defines custom behavior of the #az_cbor_writer. If `NULL` is passed, the writer
 * will use the default options (i.e. #az_cbor_writer_options_default()).
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK #az_cbor_writer is initialized successfully.
 * @retval other Initialization failed.
 */
AZ_NODISCARD az_result az_cbor_writer_init(
    az_cbor_writer* out_cbor_writer,
    az_span destination_buffer,
    az_cbor_writer_options const* options);

/**
 * @brief Initializes an #az_cbor_writer which writes cbor text into a destination that can contain
 * non-contiguous buffers.
 *
 * @param[out] out_cbor_writer A pointer to an #az_cbor_writer the instance to initialize.
 * @param[in] first_destination_buffer An #az_span over the byte buffer where the cbor text is to be
 * written at the start.
 * @param[in] allocator_callback An #az_span_allocator_fn callback function that provides the
 * destination span to write the cbor text to once the previous buffer is full or too small to
 * contain the next token.
 * @param user_context A context specific user-defined struct or set of fields that is passed
 * through to calls to the #az_span_allocator_fn.
 * @param[in] options __[nullable]__ A reference to an #az_cbor_writer_options
 * structure which defines custom behavior of the #az_cbor_writer. If `NULL` is passed, the writer
 * will use the default options (i.e. #az_cbor_writer_options_default()).
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The #az_cbor_writer is initialized successfully.
 * @retval other Failure.
 */
AZ_NODISCARD az_result az_cbor_writer_chunked_init(
    az_cbor_writer* out_cbor_writer,
    az_span first_destination_buffer,
    az_span_allocator_fn allocator_callback,
    void* user_context,
    az_cbor_writer_options const* options);

/**
 * @brief Returns the #az_span containing the cbor text written to the underlying buffer so far, in
 * the last provided destination buffer.
 *
 * @param[in] cbor_writer A pointer to an #az_cbor_writer instance wrapping the destination buffer.
 *
 * @note Do NOT modify or override the contents of the returned #az_span unless you are no longer
 * writing cbor text into it.
 *
 * @return An #az_span containing the cbor text built so far.
 *
 * @remarks This function returns the entire cbor text when it fits in the first provided buffer,
 * where the destination is a single, contiguous buffer. When the destination can be a set of
 * non-contiguous buffers (using #az_cbor_writer_chunked_init()), and the cbor is larger than the
 * first provided destination span, this function only returns the text written into the last
 * provided destination buffer from the allocator callback.
 */
AZ_NODISCARD AZ_INLINE az_span
az_cbor_writer_get_bytes_used_in_destination(az_cbor_writer const* cbor_writer)
{
  return az_span_slice(
      cbor_writer->_internal.destination_buffer, 0, cbor_writer->_internal.bytes_written);
}

/**
 * @brief Appends the UTF-8 text value (as a cbor string) into the buffer.
 *
 * @param[in,out] ref_cbor_writer A pointer to an #az_cbor_writer instance containing the buffer to
 * append the string value to.
 * @param[in] value The UTF-8 encoded value to be written as a cbor string. The value is escaped
 * before writing.
 *
 * @remarks If \p value is #AZ_SPAN_EMPTY, the empty cbor string value is written (i.e. "").
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The string value was appended successfully.
 * @retval #AZ_ERROR_NOT_ENOUGH_SPACE The buffer is too small.
 */
AZ_NODISCARD az_result az_cbor_writer_append_string(az_cbor_writer* ref_cbor_writer, az_span value);

/**
 * @brief Appends an existing UTF-8 encoded cbor text into the buffer, useful for appending nested
 * cbor.
 *
 * @param[in,out] ref_cbor_writer A pointer to an #az_cbor_writer instance containing the buffer to
 * append the cbor text to.
 * @param[in] cbor_text A single, possibly nested, valid, UTF-8 encoded, cbor value to be written as
 * is, without any formatting or spacing changes. No modifications are made to this text, including
 * escaping.
 *
 * @remarks A single, possibly nested, cbor value is one that starts and ends with {} or [] or is a
 * single primitive token. The cbor cannot start with an end object or array, or a property name, or
 * be incomplete.
 *
 * @remarks The function validates that the provided cbor to be appended is valid and properly
 * escaped, and fails otherwise.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The provided \p cbor_text was appended successfully.
 * @retval #AZ_ERROR_NOT_ENOUGH_SPACE The destination is too small for the provided \p cbor_text.
 * @retval #AZ_ERROR_cbor_INVALID_STATE The \p ref_cbor_writer is in a state where the \p cbor_text
 * cannot be appended because it would result in invalid cbor.
 * @retval #AZ_ERROR_UNEXPECTED_END The provided \p cbor_text is invalid because it is incomplete
 * and ends too early.
 * @retval #AZ_ERROR_UNEXPECTED_CHAR The provided \p cbor_text is invalid because of an unexpected
 * character.
 */
AZ_NODISCARD az_result
az_cbor_writer_append_cbor_text(az_cbor_writer* ref_cbor_writer, az_span cbor_text);

/**
 * @brief Appends the UTF-8 property name (as a cbor string) which is the first part of a name/value
 * pair of a cbor object.
 *
 * @param[in,out] ref_cbor_writer A pointer to an #az_cbor_writer instance containing the buffer to
 * append the property name to.
 * @param[in] name The UTF-8 encoded property name of the cbor value to be written. The name is
 * escaped before writing.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The property name was appended successfully.
 * @retval #AZ_ERROR_NOT_ENOUGH_SPACE The buffer is too small.
 */
AZ_NODISCARD az_result
az_cbor_writer_append_property_name(az_cbor_writer* ref_cbor_writer, az_span name);

/**
 * @brief Appends a boolean value (as a cbor literal `true` or `false`).
 *
 * @param[in,out] ref_cbor_writer A pointer to an #az_cbor_writer instance containing the buffer to
 * append the boolean to.
 * @param[in] value The value to be written as a cbor literal `true` or `false`.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The boolean was appended successfully.
 * @retval #AZ_ERROR_NOT_ENOUGH_SPACE The buffer is too small.
 */
AZ_NODISCARD az_result az_cbor_writer_append_bool(az_cbor_writer* ref_cbor_writer, bool value);

/**
 * @brief Appends an `int32_t` number value.
 *
 * @param[in,out] ref_cbor_writer A pointer to an #az_cbor_writer instance containing the buffer to
 * append the number to.
 * @param[in] value The value to be written as a cbor number.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The number was appended successfully.
 * @retval #AZ_ERROR_NOT_ENOUGH_SPACE The buffer is too small.
 */
AZ_NODISCARD az_result az_cbor_writer_append_int32(az_cbor_writer* ref_cbor_writer, int32_t value);

/**
 * @brief Appends a `double` number value.
 *
 * @param[in,out] ref_cbor_writer A pointer to an #az_cbor_writer instance containing the buffer to
 * append the number to.
 * @param[in] value The value to be written as a cbor number.
 * @param[in] fractional_digits The number of digits of the \p value to write after the decimal
 * point and truncate the rest.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The number was appended successfully.
 * @retval #AZ_ERROR_NOT_ENOUGH_SPACE The buffer is too small.
 * @retval #AZ_ERROR_NOT_SUPPORTED The \p value contains an integer component that is too large and
 * would overflow beyond `2^53 - 1`.
 *
 * @remark Only finite double values are supported. Values such as `NAN` and `INFINITY` are not
 * allowed and would lead to invalid cbor being written.
 *
 * @remark Non-significant trailing zeros (after the decimal point) are not written, even if \p
 * fractional_digits is large enough to allow the zero padding.
 *
 * @remark The \p fractional_digits must be between 0 and 15 (inclusive). Any value passed in that
 * is larger will be clamped down to 15.
 */
AZ_NODISCARD az_result az_cbor_writer_append_double(
    az_cbor_writer* ref_cbor_writer,
    double value,
    int32_t fractional_digits);

/**
 * @brief Appends the cbor literal `null`.
 *
 * @param[in,out] ref_cbor_writer A pointer to an #az_cbor_writer instance containing the buffer to
 * append the `null` literal to.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK `null` was appended successfully.
 * @retval #AZ_ERROR_NOT_ENOUGH_SPACE The buffer is too small.
 */
AZ_NODISCARD az_result az_cbor_writer_append_null(az_cbor_writer* ref_cbor_writer);

/**
 * @brief Appends the beginning of a cbor object (i.e. `{`).
 *
 * @param[in,out] ref_cbor_writer A pointer to an #az_cbor_writer instance containing the buffer to
 * append the start of object to.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK Object start was appended successfully.
 * @retval #AZ_ERROR_NOT_ENOUGH_SPACE The buffer is too small.
 * @retval #AZ_ERROR_CBOR_NESTING_OVERFLOW The depth of the cbor exceeds the maximum allowed
 * depth of 64.
 */
AZ_NODISCARD az_result az_cbor_writer_append_begin_object(az_cbor_writer* ref_cbor_writer);

/**
 * @brief Appends the beginning of a cbor array (i.e. `[`).
 *
 * @param[in,out] ref_cbor_writer A pointer to an #az_cbor_writer instance containing the buffer to
 * append the start of array to.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK Array start was appended successfully.
 * @retval #AZ_ERROR_NOT_ENOUGH_SPACE The buffer is too small.
 * @retval #AZ_ERROR_cbor_NESTING_OVERFLOW The depth of the cbor exceeds the maximum allowed depth
 * of 64.
 */
AZ_NODISCARD az_result az_cbor_writer_append_begin_array(az_cbor_writer* ref_cbor_writer);

/**
 * @brief Appends the end of the current cbor object (i.e. `}`).
 *
 * @param[in,out] ref_cbor_writer A pointer to an #az_cbor_writer instance containing the buffer to
 * append the closing character to.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK Object end was appended successfully.
 * @retval #AZ_ERROR_NOT_ENOUGH_SPACE The buffer is too small.
 */
AZ_NODISCARD az_result az_cbor_writer_append_end_object(az_cbor_writer* ref_cbor_writer);

/**
 * @brief Appends the end of the current cbor array (i.e. `]`).
 *
 * @param[in,out] ref_cbor_writer A pointer to an #az_cbor_writer instance containing the buffer to
 * append the closing character to.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK Array end was appended successfully.
 * @retval #AZ_ERROR_NOT_ENOUGH_SPACE The buffer is too small.
 */
AZ_NODISCARD az_result az_cbor_writer_append_end_array(az_cbor_writer* ref_cbor_writer);

/************************************ cbor READER ******************/

/**
 * @brief Allows the user to define custom behavior when reading cbor using the #az_cbor_reader.
 */
typedef struct
{
  struct
  {
    /// Currently, this is unused, but needed as a placeholder since we can't have an empty struct.
    bool unused;
  } _internal;
} az_cbor_reader_options;

/**
 * @brief Gets the default cbor reader options which reads the cbor strictly according to the cbor
 * RFC.
 *
 * @details Call this to obtain an initialized #az_cbor_reader_options structure that can be
 * modified and passed to #az_cbor_reader_init().
 *
 * @return The default #az_cbor_reader_options.
 */
AZ_NODISCARD AZ_INLINE az_cbor_reader_options az_cbor_reader_options_default()
{
  az_cbor_reader_options options = (az_cbor_reader_options) {
    ._internal = {
      .unused = false,
    },
  };

  return options;
}

/**
 * @brief Returns the cbor tokens contained within a cbor buffer, one at a time.
 *
 * @remarks The token field is meant to be used as read-only to return the #az_cbor_token while
 * reading the cbor. Do NOT modify it.
 */
typedef struct
{
  /// This read-only field gives access to the current token that the #az_cbor_reader has processed,
  /// and it shouldn't be modified by the caller.
  az_cbor_token token;

  struct
  {
    /// The first buffer containing the cbor payload.
    az_span cbor_buffer;

    /// The array of non-contiguous buffers containing the cbor payload, which will be null for the
    /// single buffer case.
    az_span* cbor_buffers;

    /// The number of non-contiguous buffer segments in the array. It is set to one for the single
    /// buffer case.
    int32_t number_of_buffers;

    /// The current buffer segment being processed while reading the cbor in non-contiguous buffer
    /// segments.
    int32_t buffer_index;

    /// The number of bytes consumed so far in the current buffer segment.
    int32_t bytes_consumed;

    /// The total bytes consumed from the input cbor payload. In the case of a single buffer, this
    /// is identical to bytes_consumed.
    int32_t total_bytes_consumed;

    /// Flag which indicates that we have a cbor object or array in the payload, rather than a
    /// single primitive token (string, number, true, false, null).
    bool is_complex_cbor;

    uint32_t element_type[256];
    uint32_t element_len[256];

    /// A limited stack to track the depth and nested cbor objects or arrays read so far.
    _az_cbor_bit_stack bit_stack;

    /// A copy of the options provided by the user.
    az_cbor_reader_options options;
  } _internal;
} az_cbor_reader;

/**
 * @brief Initializes an #az_cbor_reader to read the cbor payload contained within the provided
 * buffer.
 *
 * @param[out] out_cbor_reader A pointer to an #az_cbor_reader instance to initialize.
 * @param[in] cbor_buffer An #az_span over the byte buffer containing the cbor text to read.
 * @param[in] options __[nullable]__ A reference to an #az_cbor_reader_options structure which
 * defines custom behavior of the #az_cbor_reader. If `NULL` is passed, the reader will use the
 * default options (i.e. #az_cbor_reader_options_default()).
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The #az_cbor_reader is initialized successfully.
 * @retval other Initialization failed.
 *
 * @remarks The provided cbor buffer must not be empty, as that is invalid cbor.
 *
 * @remarks An instance of #az_cbor_reader must not outlive the lifetime of the cbor payload within
 * the \p cbor_buffer.
 */
AZ_NODISCARD az_result az_cbor_reader_init(
    az_cbor_reader* out_cbor_reader,
    az_span cbor_buffer,
    az_cbor_reader_options const* options);

/**
 * @brief Initializes an #az_cbor_reader to read the cbor payload contained within the provided
 * set of discontiguous buffers.
 *
 * @param[out] out_cbor_reader A pointer to an #az_cbor_reader instance to initialize.
 * @param[in] cbor_buffers An array of non-contiguous byte buffers, as spans, containing the cbor
 * text to read.
 * @param[in] number_of_buffers The number of buffer segments provided, i.e. the length of the \p
 * cbor_buffers array.
 * @param[in] options __[nullable]__ A reference to an #az_cbor_reader_options
 * structure which defines custom behavior of the #az_cbor_reader. If `NULL` is passed, the reader
 * will use the default options (i.e. #az_cbor_reader_options_default()).
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The #az_cbor_reader is initialized successfully.
 * @retval other Initialization failed.
 *
 * @remarks The provided array of cbor buffers must not be empty, as that is invalid cbor, and
 * therefore \p number_of_buffers must also be greater than 0. The array must also not contain any
 * empty span segments.
 *
 * @remarks An instance of #az_cbor_reader must not outlive the lifetime of the cbor payload within
 * the \p cbor_buffers.
 */
AZ_NODISCARD az_result az_cbor_reader_chunked_init(
    az_cbor_reader* out_cbor_reader,
    az_span cbor_buffers[],
    int32_t number_of_buffers,
    az_cbor_reader_options const* options);

/**
 * @brief Reads the next token in the cbor text and updates the reader state.
 *
 * @param[in,out] ref_cbor_reader A pointer to an #az_cbor_reader instance containing the cbor to
 * read.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The token was read successfully.
 * @retval #AZ_ERROR_UNEXPECTED_END The end of the cbor document is reached.
 * @retval #AZ_ERROR_UNEXPECTED_CHAR An invalid character is detected.
 * @retval #AZ_ERROR_cbor_READER_DONE No more cbor text left to process.
 */
AZ_NODISCARD az_result az_cbor_reader_next_token(az_cbor_reader* ref_cbor_reader);

/**
 * @brief Reads and skips over any nested cbor elements.
 *
 * @param[in,out] ref_cbor_reader A pointer to an #az_cbor_reader instance containing the cbor to
 * read.
 *
 * @return An #az_result value indicating the result of the operation.
 * @retval #AZ_OK The children of the current cbor token are skipped successfully.
 * @retval #AZ_ERROR_UNEXPECTED_END The end of the cbor document is reached.
 * @retval #AZ_ERROR_UNEXPECTED_CHAR An invalid character is detected.
 *
 * @remarks If the current token kind is a property name, the reader first moves to the property
 * value. Then, if the token kind is start of an object or array, the reader moves to the matching
 * end object or array. For all other token kinds, the reader doesn't move and returns #AZ_OK.
 */
AZ_NODISCARD az_result az_cbor_reader_skip_children(az_cbor_reader* ref_cbor_reader);

#include <azure/core/_az_cfg_suffix.h>

#endif // _az_CBOR_H
