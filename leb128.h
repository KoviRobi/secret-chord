#pragma once

#include <stdint.h>
#include <stdlib.h>

typedef struct {
	uintptr_t value;
	uint8_t size;
} uvalue_size;

typedef struct {
	intptr_t value;
	uint8_t size;
} value_size;

/// Return the number of bytes to encode the given unsigned value as uleb128
uint8_t uleb128_bytes(uintptr_t value);

/// Encode the given unsigned value as uleb128 into data, return size of encode
uint8_t uleb128_encode(uintptr_t value, uint8_t *data);

/// Decode the uleb128 data given, return value and size
uvalue_size uleb128_decode(uint8_t *data);

/// Return the number of bytes to encode the given signed value as leb128
uint8_t leb128_bytes(intptr_t value);

/// Encode the given signed value as leb128 into data, return size of encode
uint8_t leb128_encode(intptr_t value, uint8_t *data);

/// Decode the leb128 data given, return value and size
value_size leb128_decode(uint8_t *data);
