#include "input.h"
#include "leb128.h"

#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

typedef uint32_t cell;
typedef int32_t scell;
typedef void instruction(uint8_t *next_instr, uint8_t *instr_code);

typedef union {
  uint8_t as_byte;
  struct {
    bool immediate : 1;
    bool hidden : 1;
    bool : 0;
  };
} dict_flags;
_Static_assert(sizeof(dict_flags) == 1, "Size of flags != one byte");

cell stack[512 + 256];
cell rstack[256];
cell stack_p;
cell latest;
cell data_p = 4;
alignas(max_align_t) uint8_t data[4096] = {0xEF, 0xCD, 0xAB, 0x89};

#define align(var, alignment)                                                  \
  ((var) + (alignof(alignment) - 1)) & ~(alignof(alignment) - 1)

#define POP(STACK, STACK_P) (STACK)[--(STACK_P)]
#define PUSH(STACK, STACK_P, VALUE) (STACK)[(STACK_P)++] = (VALUE)

#define MIN(a, b)                                                              \
  ({                                                                           \
    __typeof__(a) _a = (a);                                                    \
    __typeof__(b) _b = (b);                                                    \
    _a < _b ? _a : _b;                                                         \
  })
#define MAX(a, b)                                                              \
  ({                                                                           \
    __typeof__(a) _a = (a);                                                    \
    __typeof__(b) _b = (b);                                                    \
    _a < _b ? _b : _a;                                                         \
  })

static cell pop(void) { return POP(stack, stack_p); }
static void push(cell value) { PUSH(stack, stack_p, value); }

static void next(uint8_t *next_instr) {
  value_size decoded = uleb128_decode(next_instr);
  instruction **interpreter = (instruction **)(data + decoded.value);
  uint8_t *instr_code = (uint8_t *)(interpreter + 1);
  (*interpreter)(next_instr + decoded.size, instr_code);
}

static void add(uint8_t *instr_p, uint8_t *_instr_code) {
  cell a = pop(), b = pop();
  push(a + b);
  next(instr_p);
}

static void ulit(uint8_t *instr_p, uint8_t *_instr_code) {
  value_size literal = uleb128_decode(instr_p);
  instr_p += literal.size;
  push(literal.value);
  next(instr_p);
}

static void lit(uint8_t *instr_p, uint8_t *_instr_code) {
  value_size literal = leb128_decode(instr_p);
  instr_p += literal.size;
  push(literal.value);
  next(instr_p);
}

static void create(const char *name, cell len, dict_flags flags) {
  cell this = data_p;
  data[data_p] = flags.as_byte;
  data_p += sizeof(flags);
  data_p += leb128_encode((scell)(latest - this), &data[data_p]);
  data_p += uleb128_encode(len, &data[data_p]);
  // GCC doesn't implement strncpy_s
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  strncpy((char *)&data[data_p], name, len);
  data_p += len;
  latest = this;
  // Align DATA_P
  data_p = align(data_p, instruction *);
}

#define CREATE(name, flags) create((name), strlen(name), (dict_flags){flags})

static void add_native(const char *name, instruction *code) {
  create(name, strlen(name), (dict_flags){.immediate = false, .hidden = false});
  instruction **aligned = (instruction **)&data[data_p];
  *aligned = code;
  data_p += sizeof(instruction *);
}

static cell find_in_dict(uint64_t name_len, const char *name) {
  cell entry = latest;
  while (entry != 0) {
    cell start = entry;
    dict_flags flags = {.as_byte = data[entry]};
    entry += sizeof(flags);
    value_size next_offset = leb128_decode(&data[entry]);
    entry += next_offset.size;
    value_size strlen = uleb128_decode(&data[entry]);
    entry += strlen.size;
    if (!flags.hidden && strlen.value == name_len &&
        strncasecmp(name, (const char *)&data[entry], strlen.value) == 0)
      return start;
    entry = start + next_offset.value;
  }
  return 0;
}

static void exit_and_print(uint8_t *instr_p, uint8_t *_instr_code) {
  printf("<%u>", stack_p);
  for (cell i = 0; i < stack_p; i++)
    printf(" %d", stack[i]);
  printf("\n");
}

static cell to_interpreter(cell entry) {
  entry += sizeof(dict_flags);
  value_size next_offset = leb128_decode(&data[entry]);
  entry += next_offset.size;
  value_size strlen = uleb128_decode(&data[entry]);
  entry += strlen.size;
  entry += strlen.value;
  // Align ENTRY
  entry = align(entry, instruction *);
  return entry;
}

static void find_and_compile(const char *name) {
  cell entry = find_in_dict(strlen(name), name);
  if (entry) {
    cell interpreter = to_interpreter(entry);
    data_p += uleb128_encode(interpreter, &data[data_p]);
  } else {
    fprintf(stderr, "ERROR: unknown word %s\n", name);
    exit(1);
  }
}

static void compile_number(cell value) {
  if ((scell)value < 0) {
    find_and_compile("LIT");
    data_p += leb128_encode((scell)value, &data[data_p]);
  } else {
    find_and_compile("ULIT");
    data_p += uleb128_encode(value, &data[data_p]);
  }
}

static void chardump(const uint8_t *buffer, size_t len) {
  for (size_t i = 0; i < len; i++)
    if (' ' <= buffer[i] && buffer[i] <= '~')
      printf("%c", buffer[i]);
    else if (buffer[i] < ' ')
      // UTF-8 encoded NUL (2400) + buffer[i]
      printf("\xe2\x90%c", 0x80 + buffer[i]);
    else if (buffer[i] == 0x7F)
      // UTF-8 encoded DEL (2421)
      printf("\xe2\x90\xa1");
    else
      // UTF-8 encoded WHITE SQUARE (25A1)
      printf("\xe2\x96\xa1");
}

static void hexdump(const uint8_t *buffer, size_t len) {
  if (len > 0) {
    for (size_t i = 0; i < len || i % 8 != 0;) {
      if (i % 8 == 0)
        printf("%04lX: ", i);
      else if (i % 4 == 0)
        printf("    ");
      else if (i % 2 == 0)
        printf("  ");
      else
        printf(" ");

      if (i < len)
        printf("0x%02X", buffer[i]);
      else
        printf("    ");

      i++;

      if (i % 8 == 0) {
        printf("    |");
        size_t start = MAX(i - 8, 0);
        size_t chars = MIN(i, len);
        chars = chars % 8;
        if (len > 0 && chars == 0)
          chars = 8;
        chardump(&buffer[start], chars);
        printf("|\n");
      }
    }
  }
}

static cell init_dict(void) {
  add_native("LIT", &lit);
  add_native("ULIT", &ulit);

  add_native("+", &add);

  add_native("BYE", &exit_and_print);

  cell start = data_p;
  compile_number(1);
  compile_number(2);
  find_and_compile("+");
  find_and_compile("BYE");

  return start;
};

int main(int argc, char *argv[]) {
  input_init();
  cell start = init_dict();

  hexdump(data, data_p);

  next(&data[start]);
  return 0;
}
