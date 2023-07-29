#include <stdio.h>

#include "leb128.h"

uint8_t uleb128_bytes(uint64_t value) {
  int i = 0;
  for (i = 0; i < 10; i++) {
    if (value < 128) {
      i++;
      break;
    } else {
      value = value >> 7;
    }
  }
  return i;
}

uint8_t uleb128_encode(uint64_t value, uint8_t *data) {
  int i = 0;
  for (i = 0; i < 10; i++) {
    if (value < 128) {
      data[i] = value;
      i++;
      break;
    } else {
      data[i] = (value & 127) | 128;
      value = value >> 7;
    }
  }
  return i;
}

value_size uleb128_decode(uint8_t *data) {
  value_size ret = {.value = 0};
  for (ret.size = 0; ret.size < 10; ret.size++) {
    uint64_t shift = 7 * ret.size;
    uint64_t continue_bit = 128llu << shift;
    ret.value |= (uint64_t)data[ret.size] << shift;
    if ((ret.value & continue_bit) == 0) {
      ret.size++;
      break;
    } else {
      ret.value &= ~continue_bit;
    }
  }
  return ret;
}

uint8_t leb128_bytes(int64_t value) {
  _Static_assert((-1 >> 1) == -1, "Shift is not arithmetic");
  int i = 0;
  for (i = 0; i < 10; i++) {
    if (-64 <= value && value < 64) {
      i++;
      break;
    } else {
      value = value >> 7;
    }
  }
  return i;
}

uint8_t leb128_encode(int64_t value, uint8_t *data) {
  _Static_assert((-1 >> 1) == -1, "Shift is not arithmetic");
  int i = 0;
  for (i = 0; i < 10; i++) {
    if (-64 <= value && value < 64) {
      data[i] = value & 127;
      i++;
      break;
    } else {
      data[i] = (value & 127) | 128;
      value = value >> 7;
    }
  }
  return i;
}

value_size leb128_decode(uint8_t *data) {
  value_size ret = {.value = 0};
  for (ret.size = 0; ret.size < 10; ret.size++) {
    uint64_t shift = 7 * ret.size;
    uint64_t continue_bit = 128llu << shift;
    ret.value |= (uint64_t)data[ret.size] << shift;
    if ((ret.value & continue_bit) == 0) {
      // Sign extend
      ret.value |= ((ret.value << 1) & continue_bit) * ~0llu;
      ret.size++;
      break;
    } else {
      ret.value &= ~continue_bit;
    }
  }
  return ret;
}
