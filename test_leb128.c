// vim: set errorformat=%t%*[^\:]\:%f\:%l\:\ %m :
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "leb128.h"

static bool fail = false;
static uint8_t buffer[12];
static value_size decoded;

void hexdump(const uint8_t *buffer, size_t len) {
  if (len > 0) {
    printf("0x%02X", buffer[0]);
    for (size_t i = 1; i < len; i++) {
      printf(" 0x%02X", buffer[i]);
    }
  }
}

inline int min(int a, int b) { return a < b ? a : b; }

void expect_bytes(uint8_t *expected, size_t size, char *file, unsigned line) {
  if (memcmp(buffer, expected, min(sizeof(buffer), size)) != 0) {
    printf("ERROR:%s:%u: Expected ", file, line);
    hexdump(expected, size);
    printf(" != ");
    hexdump(buffer, sizeof(buffer));
    printf("\n");
    fail = true;
  }
}
#define EXPECT_BYTES(...)                                                      \
  expect_bytes(((uint8_t[]){__VA_ARGS__}), sizeof((uint8_t[]){__VA_ARGS__}),   \
               __FILE__, __LINE__)

void expect_long(uint64_t expected, uint64_t value, char *file, unsigned line) {
  if (expected != value) {
    printf("ERROR:%s:%u: Expected 0x%lX != 0x%lX\n", file, line, expected,
           value);
    fail = true;
  }
}

void expect_decoded(uint64_t expected, uint8_t size, char *file,
                    unsigned line) {
  expect_long(expected, decoded.value, file, line);
  expect_long(size, decoded.size, file, line);
}

#ifndef __STDC_LIB_EXT1__
// Missing memcpy_s/memset_s, so ignore the warning
// NOLINTBEGIN(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
#endif

int main(void) {

  memset(buffer, 0, sizeof(buffer));
  uleb128_encode(0, buffer);
  EXPECT_BYTES(0);

  memset(buffer, 0, sizeof(buffer));
  uleb128_encode(1, buffer);
  EXPECT_BYTES(1);

  memset(buffer, 0, sizeof(buffer));
  uleb128_encode(3, buffer);
  EXPECT_BYTES(3);

  memset(buffer, 0, sizeof(buffer));
  uleb128_encode(128, buffer);
  EXPECT_BYTES(0x80, 0x01);

  memset(buffer, 0, sizeof(buffer));
  uleb128_encode(128 * 2, buffer);
  EXPECT_BYTES(0x80, 0x02);

  memset(buffer, 0, sizeof(buffer));
  uleb128_encode(128 * 2 + 1, buffer);
  EXPECT_BYTES(0x81, 0x02);

  memset(buffer, 0, sizeof(buffer));
  uleb128_encode(128 * 128, buffer);
  EXPECT_BYTES(0x80, 0x80, 0x01);

  memset(buffer, 0, sizeof(buffer));
  uleb128_encode(127 + 127 * 128, buffer);
  EXPECT_BYTES(0xFF, 0x7F);

  memset(buffer, 0, sizeof(buffer));
  uleb128_encode(624485, buffer);
  EXPECT_BYTES(0xE5, 0x8E, 0x26);

  memset(buffer, 0, sizeof(buffer));
  uleb128_encode(UINT64_MAX, buffer);
  // 9 * 7 = 63 bits, so we need the 10th byte for the last bit
  EXPECT_BYTES(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){0}, sizeof(buffer));
  decoded = uleb128_decode(buffer);
  expect_decoded(0, 1, __FILE__, __LINE__);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){1}, sizeof(buffer));
  decoded = uleb128_decode(buffer);
  expect_decoded(1, 1, __FILE__, __LINE__);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){0x80, 1}, sizeof(buffer));
  decoded = uleb128_decode(buffer);
  expect_decoded(128, 2, __FILE__, __LINE__);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){0x80, 2}, sizeof(buffer));
  decoded = uleb128_decode(buffer);
  expect_decoded(128 * 2, 2, __FILE__, __LINE__);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){0x81, 2}, sizeof(buffer));
  decoded = uleb128_decode(buffer);
  expect_decoded(128 * 2 + 1, 2, __FILE__, __LINE__);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){0x80, 0x80, 1}, sizeof(buffer));
  decoded = uleb128_decode(buffer);
  expect_decoded(128 * 128, 3, __FILE__, __LINE__);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){0xE5, 0x8E, 0x26}, sizeof(buffer));
  decoded = uleb128_decode(buffer);
  expect_decoded(624485, 3, __FILE__, __LINE__);

  // 9 * 7 = 63 bits, so we need the 10th byte for the last bit
  memcpy(buffer,
         (uint8_t[sizeof(buffer)]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                   0xFF, 0xFF, 0x01},
         sizeof(buffer));
  decoded = uleb128_decode(buffer);
  expect_decoded(UINT64_MAX, 10, __FILE__, __LINE__);

  for (int i = 0; i < 100; i++) {
    uint8_t buffer2[sizeof(buffer)];
    uint64_t value = (uint64_t)rand() << 32 | rand();
    uint8_t size = uleb128_bytes(value);
    uint8_t bytes;

    memset(buffer, 0, sizeof(buffer));
    uint8_t size2 = uleb128_encode(value, buffer);
    memcpy(buffer2, buffer, sizeof(buffer));
    decoded = uleb128_decode(buffer);

    for (bytes = 0; buffer[bytes] & 0x80; bytes++)
      ;
    bytes++;
    expect_long(size, bytes, __FILE__, __LINE__);
    expect_long(size2, bytes, __FILE__, __LINE__);
    expect_decoded(value, size, __FILE__, __LINE__);
    uleb128_encode(value, buffer);
    expect_bytes(buffer2, size, __FILE__, __LINE__);
  }

  memset(buffer, 0, sizeof(buffer));
  leb128_encode(-1, buffer);
  EXPECT_BYTES(-1 & 127);

  memset(buffer, 0, sizeof(buffer));
  leb128_encode(-64, buffer);
  EXPECT_BYTES(-64 & 127);

  memset(buffer, 0, sizeof(buffer));
  leb128_encode(-3, buffer);
  EXPECT_BYTES(-3 & 127);

  memset(buffer, 0, sizeof(buffer));
  leb128_encode(63, buffer);
  EXPECT_BYTES(63);

  memset(buffer, 0, sizeof(buffer));
  leb128_encode(-128, buffer);
  EXPECT_BYTES(0x80, 0x7F);

  memset(buffer, 0, sizeof(buffer));
  leb128_encode(INT64_MAX, buffer);
  EXPECT_BYTES(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00);

  memset(buffer, 0, sizeof(buffer));
  leb128_encode(INT64_MIN, buffer);
  EXPECT_BYTES(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){0}, sizeof(buffer));
  decoded = leb128_decode(buffer);
  expect_decoded(0, 1, __FILE__, __LINE__);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){1}, sizeof(buffer));
  decoded = leb128_decode(buffer);
  expect_decoded(1, 1, __FILE__, __LINE__);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){0x80, 1}, sizeof(buffer));
  decoded = leb128_decode(buffer);
  expect_decoded(128, 2, __FILE__, __LINE__);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){0x80, 2}, sizeof(buffer));
  decoded = leb128_decode(buffer);
  expect_decoded(128 * 2, 2, __FILE__, __LINE__);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){0x81, 2}, sizeof(buffer));
  decoded = leb128_decode(buffer);
  expect_decoded(128 * 2 + 1, 2, __FILE__, __LINE__);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){0x80, 0x80, 1}, sizeof(buffer));
  decoded = leb128_decode(buffer);
  expect_decoded(128 * 128, 3, __FILE__, __LINE__);

  memcpy(buffer, (uint8_t[sizeof(buffer)]){0xE5, 0x8E, 0x26}, sizeof(buffer));
  decoded = leb128_decode(buffer);
  expect_decoded(624485, 3, __FILE__, __LINE__);

  // 9 * 7 = 63 bits, so we need the 10th byte for the last bit
  memcpy(buffer,
         (uint8_t[sizeof(buffer)]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                   0xFF, 0xFF, 0x01},
         sizeof(buffer));
  decoded = leb128_decode(buffer);
  expect_decoded(UINT64_MAX, 10, __FILE__, __LINE__);

  for (int i = 0; i < 100; i++) {
    uint8_t buffer2[sizeof(buffer)];
    uint64_t uvalue = (uint64_t)rand() << 32 | rand();
    int64_t value = (int64_t)uvalue;
    // Note for signed size we need an extra bit for the sign, even if it is 0
    uint8_t size = leb128_bytes(value);
    uint8_t bytes;

    memset(buffer, 0, sizeof(buffer));
    uint8_t size2 = leb128_encode(value, buffer);
    memcpy(buffer2, buffer, sizeof(buffer));
    decoded = leb128_decode(buffer);

    for (bytes = 0; buffer[bytes] & 0x80; bytes++)
      ;
    bytes++;
    expect_long(size, bytes, __FILE__, __LINE__);
    expect_long(size2, bytes, __FILE__, __LINE__);
    expect_decoded(value, size, __FILE__, __LINE__);
    leb128_encode(value, buffer);
    expect_bytes(buffer2, size, __FILE__, __LINE__);
  }

  uint64_t value = 1234506789;
  uint64_t iters = 1e5;
  clock_t start, end;

  start = clock();
  for (uint64_t i = 0; i < iters; i++) {
    leb128_encode(value, buffer);
    leb128_encode(value, buffer);
    leb128_encode(value, buffer);
    leb128_encode(value, buffer);
    leb128_encode(value, buffer);
    leb128_encode(value, buffer);
    leb128_encode(value, buffer);
    leb128_encode(value, buffer);
    leb128_encode(value, buffer);
    leb128_encode(value, buffer);
  }
  end = clock();
  printf("Time for %ld encodes: %fs (%e/s, avg %es)\n", iters,
         (float)(end - start) / CLOCKS_PER_SEC,
         10 * iters * CLOCKS_PER_SEC / (float)(end - start),
         (float)(end - start) / CLOCKS_PER_SEC / 10 / iters);

  start = clock();
  for (uint64_t i = 0; i < iters; i++) {
    decoded = leb128_decode(buffer);
    decoded = leb128_decode(buffer);
    decoded = leb128_decode(buffer);
    decoded = leb128_decode(buffer);
    decoded = leb128_decode(buffer);
    decoded = leb128_decode(buffer);
    decoded = leb128_decode(buffer);
    decoded = leb128_decode(buffer);
    decoded = leb128_decode(buffer);
    decoded = leb128_decode(buffer);
  }
  end = clock();
  printf("Time for %ld decodes: %fs (%e/s, avg %es)\n", iters,
         (float)(end - start) / CLOCKS_PER_SEC,
         10 * iters * CLOCKS_PER_SEC / (float)(end - start),
         (float)(end - start) / CLOCKS_PER_SEC / 10 / iters);

  start = clock();
  for (uint64_t i = 0; i < iters; i++) {
    uleb128_encode(value, buffer);
    uleb128_encode(value, buffer);
    uleb128_encode(value, buffer);
    uleb128_encode(value, buffer);
    uleb128_encode(value, buffer);
    uleb128_encode(value, buffer);
    uleb128_encode(value, buffer);
    uleb128_encode(value, buffer);
    uleb128_encode(value, buffer);
    uleb128_encode(value, buffer);
  }
  end = clock();
  printf("Time for %ld unsigned encodes: %fs (%e/s, avg %es)\n", iters,
         (float)(end - start) / CLOCKS_PER_SEC,
         10 * iters * CLOCKS_PER_SEC / (float)(end - start),
         (float)(end - start) / CLOCKS_PER_SEC / 10 / iters);

  start = clock();
  for (uint64_t i = 0; i < iters; i++) {
    decoded = uleb128_decode(buffer);
    decoded = uleb128_decode(buffer);
    decoded = uleb128_decode(buffer);
    decoded = uleb128_decode(buffer);
    decoded = uleb128_decode(buffer);
    decoded = uleb128_decode(buffer);
    decoded = uleb128_decode(buffer);
    decoded = uleb128_decode(buffer);
    decoded = uleb128_decode(buffer);
    decoded = uleb128_decode(buffer);
  }
  end = clock();
  printf("Time for %ld unsigned decodes: %fs (%e/s, avg %es)\n", iters,
         (float)(end - start) / CLOCKS_PER_SEC,
         10 * iters * CLOCKS_PER_SEC / (float)(end - start),
         (float)(end - start) / CLOCKS_PER_SEC / 10 / iters);

  return fail;
}

#ifndef __STDC_LIB_EXT1__
// Missing memcpy_s/memset_s, so ignore the warning
// NOLINTEND(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
#endif
