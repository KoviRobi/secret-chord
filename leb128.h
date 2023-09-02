#pragma once

#include <stdint.h>
#include <stdlib.h>


typedef struct {
  uint32_t value;
  uint8_t size;
} value_size;


uint8_t uleb128_bytes(uint32_t value);

uint8_t uleb128_encode(uint32_t value, uint8_t *data);

value_size uleb128_decode(uint8_t *data);

uint8_t leb128_bytes(int32_t value);

uint8_t leb128_encode(int32_t value, uint8_t *data);

value_size leb128_decode(uint8_t *data);
