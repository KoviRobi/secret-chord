#pragma once

#include <stdint.h>
#include <stdlib.h>


typedef struct {
  uint64_t value;
  uint8_t size;
} value_size;


uint8_t uleb128_bytes(uint64_t value);

uint8_t uleb128_encode(uint64_t value, uint8_t *data);

value_size uleb128_decode(uint8_t *data);

uint8_t leb128_bytes(int64_t value);

uint8_t leb128_encode(int64_t value, uint8_t *data);

value_size leb128_decode(uint8_t *data);
