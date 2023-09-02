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
cell ret_p;
cell latest;
cell compiling;
cell base = 10;
cell input_index;
cell input_buffer;
FILE *input_source;
cell input_size;
cell data_p = 4;
bool print_backtrace = true;
alignas(max_align_t) uint8_t data[4096] = {0xEF, 0xCD, 0xAB, 0x89};

#define FORTH_TRUE (-1)
#define FORTH_FALSE (0)
#define BOOL(x) (x) ? (FORTH_TRUE) : (FORTH_FALSE)

#define align(var, alignment)                                                  \
  ((var) + (alignof(alignment) - 1)) & ~(alignof(alignment) - 1)

#define POP(STACK, STACK_P)                                                    \
  {                                                                            \
    if ((STACK_P) == 0) {                                                      \
      printf("%s underflow!\n", #STACK);                                       \
      exit(1);                                                                 \
    }                                                                          \
    return (STACK)[--(STACK_P)];                                               \
  }
#define PUSH(STACK, STACK_P, VALUE)                                            \
  {                                                                            \
    if ((STACK_P) >= (sizeof((STACK)) / sizeof((STACK)[0])) - 1) {             \
      printf("%s overflow!\n", #STACK);                                        \
      exit(2);                                                                 \
    }                                                                          \
    (STACK)[(STACK_P)++] = (VALUE);                                            \
  }

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

static cell pop(void) { POP(stack, stack_p); }
static void push(cell value) { PUSH(stack, stack_p, value); }

static cell r_pop(void) { POP(rstack, ret_p); }
static void r_push(cell value) { PUSH(rstack, ret_p, value); }

#ifdef TRACE
static uint8_t *find_by_addr(uint8_t *interpreter_addr);
static cell frames = 0;
#endif

static void next(uint8_t *next_instr) {
  value_size decoded = uleb128_decode(next_instr);
  instruction **interpreter = &((instruction **)data)[decoded.value];

#ifdef TRACE
  uint8_t *counted_str = find_by_addr((uint8_t *)interpreter);
  if (counted_str) {
    value_size strlen = uleb128_decode(counted_str);
    const char *str = (const char *)(counted_str + strlen.size);
    printf("%.*s %.*s\n", MIN(ret_p, 5), "----+", (int)strlen.value, str);
  } else {
    printf("0x%04lX\n", decoded.value);
  }
#endif

  uint8_t *instr_code = (uint8_t *)(interpreter + 1);
  (*interpreter)(next_instr + decoded.size, instr_code);
}

static void forth_enter(uint8_t *instr_p, uint8_t *instr_code) {
  r_push((cell)(instr_p - data));
  next(instr_code);
}

static void forth_exit(uint8_t *instr_p, uint8_t *_instr_code) {
  next(&data[r_pop()]);
};

#define BINOP(name, cell_t, op)                                                \
  static void name(uint8_t *instr_p, uint8_t *_instr_code) {                   \
    cell_t b = pop(), a = pop();                                               \
    push(a op b);                                                              \
    next(instr_p);                                                             \
  }

BINOP(add, cell, +);
BINOP(sub, cell, -);
BINOP(mul, cell, *);
BINOP(forth_div, cell, /);
BINOP(rem, cell, %);
BINOP(and, cell, &);
BINOP(or, cell, |);
BINOP(xor, cell, ^);
BINOP(eq, cell, ==);
BINOP(ne, cell, !=);
BINOP(ult, cell, <);
BINOP(ule, cell, <=);
BINOP(ugt, cell, >);
BINOP(uge, cell, >=);
BINOP(lt, scell, <);
BINOP(le, scell, <=);
BINOP(gt, scell, >);
BINOP(ge, scell, >=);

static void invert(uint8_t *instr_p, uint8_t *_instr_code) {
  push(~pop());
  next(instr_p);
}

static void is_zero(uint8_t *instr_p, uint8_t *_instr_code) {
  cell a = pop();
  push(BOOL(a == 0));
  next(instr_p);
}

static void to_r(uint8_t *instr_p, uint8_t *_instr_code) {
  cell a = pop();
  r_push(a);
  next(instr_p);
}

static void r_from(uint8_t *instr_p, uint8_t *_instr_code) {
  cell a = r_pop();
  push(a);
  next(instr_p);
}

static void drop(uint8_t *instr_p, uint8_t *_instr_code) {
  pop();
  next(instr_p);
}

static void dup(uint8_t *instr_p, uint8_t *_instr_code) {
  cell a = pop();
  push(a);
  push(a);
  next(instr_p);
}

static void swap(uint8_t *instr_p, uint8_t *_instr_code) {
  cell a = pop(), b = pop();
  push(a), push(b);
  next(instr_p);
}

static void pick(uint8_t *instr_p, uint8_t *_instr_code) {
  cell n = pop();
  push(stack[stack_p - n - 1]);
  next(instr_p);
}

static void over(uint8_t *instr_p, uint8_t *_instr_code) {
  push(stack[stack_p - 2]);
  next(instr_p);
}

static void nip(uint8_t *instr_p, uint8_t *_instr_code) {
  cell a = pop();
  pop();
  push(a);
  next(instr_p);
}

static void rot(uint8_t *instr_p, uint8_t *_instr_code) {
  cell a = pop(), b = pop(), c = pop();
  push(b), push(a), push(c);
  next(instr_p);
}

static void fetch(uint8_t *instr_p, uint8_t *_instr_code) {
  push(*(cell *)&data[(scell)pop()]);
  next(instr_p);
}

static void store(uint8_t *instr_p, uint8_t *_instr_code) {
  cell *addr = (cell *)&data[(scell)pop()];
  cell value = pop();
  *addr = value;
  next(instr_p);
}

static void append(uint8_t *instr_p, uint8_t *_instr_code) {
  cell value = pop();
  *(cell *)&data[data_p] = value;
  data_p += sizeof(cell);
  next(instr_p);
}

static void char_fetch(uint8_t *instr_p, uint8_t *_instr_code) {
  push(*(char *)&data[(scell)pop()]);
  next(instr_p);
}

static void char_store(uint8_t *instr_p, uint8_t *_instr_code) {
  char *addr = (char *)&data[(scell)pop()];
  cell value = pop();
  *addr = value;
  next(instr_p);
}

static void char_append(uint8_t *instr_p, uint8_t *_instr_code) {
  char value = pop();
  *(char *)&data[data_p] = value;
  data_p += sizeof(char);
  next(instr_p);
}

static void leb128_fetch(uint8_t *instr_p, uint8_t *_instr_code) {
  cell addr = pop();
  value_size decoded = leb128_decode(&data[addr]);
  push((cell)decoded.value);
  push(decoded.size);
  next(instr_p);
}

static void leb128_store(uint8_t *instr_p, uint8_t *_instr_code) {
  cell addr = pop();
  cell value = pop();
  cell size = leb128_encode(value, &data[addr]);
  push(size);
  next(instr_p);
}

static void leb128_append(uint8_t *instr_p, uint8_t *_instr_code) {
  cell value = pop();
  cell size = leb128_encode(value, &data[data_p]);
  data_p += size;
  push(size);
  next(instr_p);
}

static void leb128_size(uint8_t *instr_p, uint8_t *_instr_code) {
  cell value = pop();
  cell size = leb128_bytes(value);
  push(size);
  next(instr_p);
}

static void uleb128_fetch(uint8_t *instr_p, uint8_t *_instr_code) {
  cell addr = pop();
  value_size decoded = uleb128_decode(&data[addr]);
  push((cell)decoded.value);
  push(decoded.size);
  next(instr_p);
}

static void uleb128_store(uint8_t *instr_p, uint8_t *_instr_code) {
  cell addr = pop();
  cell value = pop();
  cell size = uleb128_encode(value, &data[addr]);
  push(size);
  next(instr_p);
}

static void uleb128_append(uint8_t *instr_p, uint8_t *_instr_code) {
  cell value = pop();
  cell size = uleb128_encode(value, &data[data_p]);
  data_p += size;
  push(size);
  next(instr_p);
}

static void uleb128_size(uint8_t *instr_p, uint8_t *_instr_code) {
  cell value = pop();
  cell size = uleb128_bytes(value);
  push(size);
  next(instr_p);
}

static void ternary(uint8_t *instr_p, uint8_t *_instr_code) {
  cell c = pop(), b = pop(), a = pop();
  push(a ? b : c);
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

#define ENTER                                                                  \
  {                                                                            \
    /* CREATE aligns DATA_P */                                                 \
    instruction **aligned = (instruction **)&data[data_p];                     \
    *aligned = forth_enter;                                                    \
    data_p += sizeof(instruction *);                                           \
  }

static void new_entry(uint8_t *instr_p, uint8_t *instr_code) {
  cell len = pop();
  cell name_p = pop();
  create((const char *)&data[name_p], len, (dict_flags){.hidden = true});
  next(instr_p);
}

static void compile_interpreter(uint8_t *instr_p, uint8_t *instr_code) {
  value_size interpreter = uleb128_decode(instr_p);
  instr_p += interpreter.size;
  instruction **aligned = (instruction **)&data[data_p];
  *aligned = (instruction *)interpreter.value;
  data_p += sizeof(instruction *);
  next(instr_p);
}

static void interpreter_to_code(uint8_t *instr_p, uint8_t *instr_code) {
  cell interpreter = pop();
  push(interpreter * sizeof(instruction *) + sizeof(instruction *));
  next(instr_p);
}

static void immediate_fetch(uint8_t *instr_p, uint8_t *instr_code) {
  cell execution_token = pop();
  dict_flags flags = {.as_byte = data[execution_token]};
  push(BOOL(flags.immediate != 0));
  next(instr_p);
}

static void immediate_store(uint8_t *instr_p, uint8_t *instr_code) {
  cell execution_token = pop();
  dict_flags flags = {.as_byte = data[execution_token]};
  flags.immediate = pop() != 0;
  data[execution_token] = flags.as_byte;
  next(instr_p);
}

static void hidden_fetch(uint8_t *instr_p, uint8_t *instr_code) {
  cell execution_token = pop();
  dict_flags flags = {.as_byte = data[execution_token]};
  push(BOOL(flags.hidden != 0));
  next(instr_p);
}

static void hidden_store(uint8_t *instr_p, uint8_t *instr_code) {
  cell execution_token = pop();
  dict_flags flags = {.as_byte = data[execution_token]};
  flags.hidden = pop() != 0;
  data[execution_token] = flags.as_byte;
  next(instr_p);
}

static void add_native(const char *name, instruction *code) {
  create(name, strlen(name), (dict_flags){.immediate = false, .hidden = false});
  instruction **aligned = (instruction **)&data[data_p];
  *aligned = code;
  data_p += sizeof(instruction *);
}

static void constant(uint8_t *instr_p, uint8_t *instr_code) {
  value_size decoded = leb128_decode(instr_code);
  push(decoded.value);
  next(instr_p);
}

static void add_variable(const char *name, cell *addr) {
  create(name, strlen(name), (dict_flags){.immediate = false, .hidden = false});
  instruction **aligned_code = (instruction **)&data[data_p];
  // The constant is the location of the variable
  *aligned_code = &constant;
  data_p += sizeof(instruction *);
  data_p += leb128_encode((scell)((uint8_t *)addr - data), &data[data_p]);
}

static void variable(uint8_t *instr_p, uint8_t *instr_code) {
  push(instr_code - data);
  next(instr_p);
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

uint8_t *find_by_addr(uint8_t *interpreter_addr) {
  cell entry = latest;
  while (entry != 0) {
    cell start = entry;
    entry += sizeof(dict_flags);
    value_size next_offset = leb128_decode(&data[entry]);
    entry += next_offset.size;
    if (&data[start] <= interpreter_addr) {
      return &data[entry];
    }
    entry = start + next_offset.value;
  }
  return 0;
}

static void exit_and_print(uint8_t *instr_p, uint8_t *_instr_code) {
  printf("sp<%u>", stack_p);
  for (cell i = 0; i < stack_p; i++)
    printf(" %d", stack[i]);
  r_push((cell)(instr_p - data));
  if (print_backtrace) {
    printf("\nrp<%u>", ret_p);
    for (cell i = 0; i < ret_p; i++) {
      uint8_t *entry = find_by_addr(&data[rstack[i]]);
      value_size strlen = uleb128_decode(entry);
      printf(" 0x%X <%.*s+%ld>", rstack[i], strlen.value, entry + strlen.size,
             &data[rstack[i]] - entry - strlen.value);
    }
  }
  printf("\n");
  r_pop();
}

static void inspect_stack(uint8_t *instr_p, uint8_t *instr_code) {
  exit_and_print(instr_p, instr_code);
  next(instr_p);
}

static bool is_separator(char n) {
  return n == ' ' || n == '\t' || n == '\r' || n == '\n';
}

static bool refill_if_needed() {
  if (input_index >= input_size) {
    char *input = read_line(input_source, "> ");
    if (input != NULL)
      input_size = strlen(input);
    else
      input_size = 0;
    input_buffer = (cell)(input - (char *)data);
    input_index = 0;
    return input != NULL;
  }
  return true;
}

static void forth_refill_if_needed(uint8_t *instr_p, uint8_t *instr_code) {
  push(BOOL(refill_if_needed()));
  next(instr_p);
}

static void word(uint8_t *instr_p, uint8_t *instr_code) {
  while (refill_if_needed()) {
    while (input_index < input_size &&
           is_separator(data[input_buffer + input_index]))
      input_index++;

    if (input_index >= input_size)
      continue;

    cell start = input_index;
    while (input_index < input_size &&
           !is_separator(data[input_buffer + input_index])) {
      input_index++;
    }

    push((cell)(input_buffer + start));
    push(input_index - start);
    next(instr_p);
    return;
  }
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
  return entry / sizeof(instruction *);
}

static void see(uint8_t *instr_p, uint8_t *_instr_code) {
  cell size = pop();
  cell start = pop();
  start = to_interpreter(start);
  start *= sizeof(instruction *);
  start += sizeof(instruction *);
  cell end = start + size;
  while (start < end) {
    value_size decoded = uleb128_decode(&data[start]);
    printf("0x%04X 0x%04X", start, decoded.value);
    uint8_t *entry =
        find_by_addr((uint8_t *)&((instruction **)data)[decoded.value]);
    if (entry) {
      value_size strlen = uleb128_decode(entry);
      printf(" %.*s", strlen.value, entry + strlen.size);
    }
    printf("\n");
    start += decoded.size;
  }
  next(instr_p);
}

static void execute(uint8_t *instr_p, uint8_t *old_instr_code) {
  cell execution_token = pop();
  instruction **interpreter =
      &((instruction **)data)[to_interpreter(execution_token)];
  uint8_t *instr_code = (uint8_t *)(interpreter + 1);
  (*interpreter)(instr_p, instr_code);
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

static void find(uint8_t *instr_p, uint8_t *instr_code) {
  cell len = pop();
  cell index = pop();
  cell entry = find_in_dict(len, (char *)&data[index]);
  if (entry) {
    dict_flags flags = {.as_byte = data[entry]};
    push(entry);
    push(flags.immediate ? 1 : -1);
  } else {
    push(index);
    push(len);
    push(0);
  }
  next(instr_p);
}

static void compile_comma(uint8_t *instr_p, uint8_t *instr_code) {
  cell execution_token = pop();
  if (data_p >= sizeof(data) / sizeof(data[0]) - 1) {
    printf("heap overflow!\n");
  }
  data_p += uleb128_encode(to_interpreter(execution_token), &data[data_p]);
  next(instr_p);
}

static void parse_number(uint8_t *instr_p, uint8_t *instr_code) {
  cell len = pop();

  if (len == 0) {
    push(len);
    push(0);
    return next(instr_p);
  }

  cell start = pop();
  cell data_p = start;
  cell end = data_p + len;

  bool negative = false;
  if (len > 1 && data[data_p] == '-') {
    negative = true;
    data_p++;
  }

  cell saved_base = base;
  if (len > 2 && data[data_p] == '0') {
    if (data[data_p] == 'x' || data[data_p] == 'X') {
      base = 16;
      data_p += 2;
    } else if (data[data_p] == 'o') {
      base = 8;
      data_p += 2;
    } else if (data[data_p] == 'b' || data[data_p] == 'B') {
      base = 2;
      data_p += 2;
    }
  }

  union {
    cell u;
    scell s;
  } value = {0};
  while (data_p < end) {
    char c = data[data_p];
    value.u *= base;
    if ('0' <= c && c <= '9' && (c - '0') < base)
      value.u += c - '0';
    else if ('a' <= c && c <= 'z' && (c + 10 - 'a') < base)
      value.u += c + 10 - 'a';
    else if ('A' <= c && c <= 'Z' && (c + 10 - 'A') < base)
      value.u += c + 10 - 'A';
    else {
      push(start);
      push(len);
      push(0);
      return next(instr_p);
    }
    data_p++;
  }

  base = saved_base;

  if (negative)
    value.s = -value.s;

  push(value.u);
  push(FORTH_TRUE);
  return next(instr_p);
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

static void forth_compile_number(uint8_t *instr_p, uint8_t *_instr_code) {
  compile_number(pop());
  next(instr_p);
}

static void str_lit(uint8_t *instr_p, uint8_t *_instr_code) {
  value_size len = uleb128_decode(instr_p);
  instr_p += len.size;
  push((cell)(instr_p - data));
  push(len.value);
  instr_p += len.value;
  next(instr_p);
}

static void compile_string_literal(const char *str) {
  find_and_compile("STRLIT");
  cell len = strlen(str);
  data_p += uleb128_encode(len, &data[data_p]);
  for (int i = 0; i < len; i++) {
    data[data_p + i] = str[i];
  }
  data_p += len;
}

static void emit(uint8_t *instr_p, uint8_t *instr_code) {
  char c = pop();
  putc(c, stdout);
  next(instr_p);
}

static void print(uint8_t *instr_p, uint8_t *instr_code) {
  cell len = pop();
  cell data_p = pop();
  printf("%.*s", len, &data[data_p]);
  next(instr_p);
}

static void print_number(cell value) {
  const int max_digits = 8 * sizeof(cell);
  char buffer[max_digits];
  buffer[max_digits - 1] = '0';
  int i;
  for (i = 0; value != 0; i++) {
    char digit = value % base;
    if (digit < 10)
      buffer[max_digits - i - 1] = '0' + digit;
    else
      buffer[max_digits - i - 1] = 'A' + digit - 10;
    value /= base;
  }
  i = MAX(1, i);
  printf("%.*s", i, &buffer[max_digits - i]);
}

static void dot(uint8_t *instr_p, uint8_t *instr_code) {
  scell value = pop();
  bool negative = value < 0;
  if (negative) {
    printf("-");
    value = -value;
  }
  print_number(value);
  next(instr_p);
}

static void udot(uint8_t *instr_p, uint8_t *instr_code) {
  cell value = pop();
  print_number(value);
  next(instr_p);
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

static void assert(cell value, cell expected, const char *file,
                   const int line) {
  if (value != expected) {
    fprintf(stderr, "%s:%d Value %d != expected %d\n", file, line, value,
            expected);
    exit(1);
  }
}
#define ASSERT(value, expected) assert(value, expected, __FILE__, __LINE__);

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
  add_variable("SP", &stack_p);
  add_variable("RP", &ret_p);
  add_variable("DP", &data_p);
  add_variable("LATEST", &latest);
  add_variable("COMPILING", &compiling);
  add_variable("BASE", &base);
  add_variable(">IN", &input_index);
  add_variable("INPUT-BUFFER", &input_buffer);
  add_variable("INPUT-SIZE", &input_size);

  add_native("+", &add);
  add_native("-", &sub);
  add_native("*", &mul);
  add_native("/", &forth_div);
  add_native("%", &rem);
  add_native("=", &eq);
  add_native("<>", &ne);
  add_native("<", &lt);
  add_native("<=", &le);
  add_native(">", &gt);
  add_native(">=", &ge);
  add_native("U<", &ult);
  add_native("U<=", &ule);
  add_native("U>", &ugt);
  add_native("U>=", &uge);

  add_native("DROP", &drop);
  add_native("DUP", &dup);
  add_native("ROT", &rot);
  add_native("SWAP", &swap);
  add_native("PICK", &pick);
  add_native("OVER", &over);
  add_native("NIP", &nip);

  add_native("AND", &and);
  add_native("OR", & or);
  add_native("XOR", &xor);
  add_native("INVERT", &invert);

  add_native("0=", &is_zero);

  add_native("@", &fetch);
  add_native("!", &store);
  add_native(",", &append);

  add_native("C@", &char_fetch);
  add_native("C!", &char_store);
  add_native("C,", &char_append);

  add_native("?:", &ternary);

  add_native("LEB128@", &leb128_fetch);
  add_native("LEB128!", &leb128_store);
  add_native("LEB128,", &leb128_append);
  add_native("LEB128-SIZE", &leb128_size);
  add_native("ULEB128@", &uleb128_fetch);
  add_native("ULEB128!", &uleb128_store);
  add_native("ULEB128,", &uleb128_append);
  add_native("ULEB128-SIZE", &uleb128_size);

  add_native("(:)", &forth_enter);
  add_native("(;)", &forth_exit);

  add_native(">R", &to_r);
  add_native("R>", &r_from);

  CREATE("LIT", 0);
  ENTER;
  find_and_compile("R>");      // R
  find_and_compile("DUP");     // R R
  find_and_compile("LEB128@"); // R VAL SIZE
  find_and_compile("ROT");     // VAL SIZE R
  find_and_compile("+");       // VAL SIZE+R
  find_and_compile(">R");      // VAL
  find_and_compile("(;)");

  CREATE("ULIT", 0);
  ENTER;
  find_and_compile("R>");       // R
  find_and_compile("DUP");      // R R
  find_and_compile("ULEB128@"); // R VAL SIZE
  find_and_compile("ROT");      // VAL SIZE R
  find_and_compile("+");        // VAL SIZE+R
  find_and_compile(">R");       // VAL
  find_and_compile("(;)");

  CREATE("(AGAIN)", 0);
  ENTER;
  find_and_compile("R>");       // R
  find_and_compile("DUP");      // R R
  find_and_compile("ULEB128@"); // R VAL SIZE
  find_and_compile("DROP");     // R VAL
  find_and_compile("-");        // R-VAL
  find_and_compile(">R");
  find_and_compile("(;)");

  CREATE("(IF)", 0);
  ENTER;
  find_and_compile("0=");
  find_and_compile("R>"); // 0= RET
  find_and_compile("SWAP");
  find_and_compile("OVER");
  find_and_compile("ULEB128@"); // RET 0= OFF OFF_SIZE
  find_and_compile("?:");       // RET OFF/OFF_SIZE
  find_and_compile("+");
  find_and_compile(">R");
  find_and_compile("(;)");

  CREATE("(ELSE)", 0);
  ENTER;
  find_and_compile("R>");
  find_and_compile("DUP");
  find_and_compile("ULEB128@");
  find_and_compile("DROP");
  find_and_compile("+");
  find_and_compile(">R");
  find_and_compile("(;)");

  CREATE("1+", 0);
  ENTER;
  compile_number(1);
  find_and_compile("+");
  find_and_compile("(;)");

  CREATE("1-", 0);
  ENTER;
  compile_number(1);
  find_and_compile("-");
  find_and_compile("(;)");

  add_native("BYE", &exit_and_print);
  add_native(".S", &inspect_stack);

  add_native("?REFILL", &forth_refill_if_needed);
  add_native("WORD", &word);
  add_native("FIND", &find);
  add_native("EXECUTE", &execute);
  add_native("COMPILE,", &compile_comma);
  add_native("PARSE-NUMBER", &parse_number);
  add_native("LITERAL", &forth_compile_number);
  add_native("STRLIT", &str_lit);
  add_native("EMIT", &emit);
  add_native("TYPE", &print);
  add_native(".", &dot);
  add_native("U.", &udot);

#define IF(name, size)                                                         \
  find_and_compile("(IF)");                                                    \
  cell if_##name = data_p;                                                     \
  cell if_##name##_size = size;                                                \
  data_p += size; /* Reserve space for jump offset literal */
#define ELSE(name, size)                                                       \
  find_and_compile("(ELSE)");                                                  \
  ASSERT(uleb128_bytes(data_p + size - if_##name), if_##name##_size);          \
  uleb128_encode((scell)(data_p + size - if_##name), &data[if_##name]);        \
  if_##name = data_p;                                                          \
  if_##name##_size = size;                                                     \
  data_p += size; /* Reserve space for jump offset literal */
#define THEN(name)                                                             \
  ASSERT(uleb128_bytes(data_p - if_##name), if_##name##_size);                 \
  uleb128_encode((scell)(data_p - if_##name), &data[if_##name]);

  CREATE("INTERPRET", 0);
  ENTER;
  find_and_compile("WORD");
  find_and_compile("FIND");
  find_and_compile("DUP");

  IF(found, 1);
  {
    find_and_compile("1+");
    find_and_compile("COMPILING");
    find_and_compile("@");
    find_and_compile("0=");
    find_and_compile("OR");
    IF(immediate_or_interpreting, 1);
    find_and_compile("EXECUTE");
    ELSE(immediate_or_interpreting, 1);
    find_and_compile("COMPILE,");
    THEN(immediate_or_interpreting);
    find_and_compile("(;)");
  }
  ELSE(found, 1);
  {
    find_and_compile("DROP");
    find_and_compile("PARSE-NUMBER");
    IF(number, 1);
    {
      find_and_compile("COMPILING");
      find_and_compile("@");
      IF(compiling, 1);
      find_and_compile("LITERAL");
      THEN(compiling);
      find_and_compile("(;)");
    }
    THEN(number);
  }
  THEN(found);
  find_and_compile("DUP");
  IF(nonempty, 1);
  {
    compile_string_literal("\"");
    find_and_compile("TYPE");
    find_and_compile("TYPE");
    compile_string_literal("\" is not a number or word\n");
    find_and_compile("TYPE");
    find_and_compile("BYE");
  }
  ELSE(nonempty, 1);
  {
    find_and_compile("DROP");
    find_and_compile("DROP");
  }
  THEN(nonempty);
  find_and_compile("(;)");

  add_native("NEW-ENTRY", &new_entry);
  add_native("INTERPRETER,", &compile_interpreter);
  add_native("INTERPRETER>CODE", &interpreter_to_code);
  add_native("IMMEDIATE@", &immediate_fetch);
  add_native("IMMEDIATE!", &immediate_store);
  add_native("HIDDEN@", &hidden_fetch);
  add_native("HIDDEN!", &hidden_store);

  CREATE("+!", 0);
  ENTER;
  find_and_compile("SWAP"); // addr data
  find_and_compile("OVER"); // addr data addr
  find_and_compile("@");
  find_and_compile("+"); // addr data+*addr
  find_and_compile("SWAP");
  find_and_compile("!");
  find_and_compile("(;)");

  CREATE("[", .immediate = true);
  ENTER;
  find_and_compile("COMPILING");
  find_and_compile("@");
  find_and_compile("DUP");
  IF(nonzero, 1);
  find_and_compile("1-");
  THEN(nonzero);
  find_and_compile("COMPILING");
  find_and_compile("!");
  find_and_compile("(;)");

  CREATE("]", .immediate = true);
  ENTER;
  compile_number(1);
  find_and_compile("COMPILING");
  find_and_compile("+!");
  find_and_compile("(;)");

  CREATE("REVEAL", 0);
  ENTER;
  compile_number(FORTH_FALSE);
  find_and_compile("LATEST");
  find_and_compile("@");
  find_and_compile("HIDDEN!");
  find_and_compile("(;)");

  CREATE("CONSTANT", 0);
  ENTER;
  find_and_compile("WORD");
  find_and_compile("NEW-ENTRY");
  find_and_compile("INTERPRETER,");
  data_p += uleb128_encode((uintptr_t)&constant, &data[data_p]);
  find_and_compile(",");
  find_and_compile("REVEAL");
  find_and_compile("(;)");

  CREATE("VARIABLE", 0);
  ENTER;
  find_and_compile("WORD");
  find_and_compile("NEW-ENTRY");
  find_and_compile("INTERPRETER,");
  data_p += uleb128_encode((uintptr_t)&variable, &data[data_p]);
  compile_number(0);
  find_and_compile(",");
  find_and_compile("REVEAL");
  find_and_compile("(;)");

  CREATE(":", 0);
  ENTER;
  find_and_compile("WORD");
  find_and_compile("NEW-ENTRY");
  find_and_compile("INTERPRETER,");
  data_p += uleb128_encode((uintptr_t)&forth_enter, &data[data_p]);
  find_and_compile("]");
  find_and_compile("(;)");

  CREATE(";", .immediate = true);
  ENTER;
  find_and_compile("ULIT");
  data_p += uleb128_encode(find_in_dict(3, "(;)"), &data[data_p]);
  find_and_compile("COMPILE,");
  find_and_compile("[");
  find_and_compile("REVEAL");
  find_and_compile("(;)");

  CREATE("QUIT", 0);
  ENTER;
  cell start = data_p;
  compile_number(0);
  find_and_compile("RP");
  find_and_compile("!");
  cell loop = data_p;
  find_and_compile("INTERPRET");
  find_and_compile("(AGAIN)");
  data_p += uleb128_encode(data_p - loop, &data[data_p]);

  add_native("SEE", &see);

  return start;
};

int main(int argc, char *argv[]) {
  input_init();
  cell start = init_dict();

  for (int i = 1; i < argc; i++) {
    if (argv[i][0] == '-') {
      switch (argv[i][1]) {
      case 'b':
        print_backtrace = false;
        break;
      default:
        printf("Ignoring flag %s", argv[i]);
        break;
      }
    } else {
      input_source = fopen(argv[i], "r");
      if (!input_source) {
        printf("Failed to open file \"%s\"\n", argv[i]);
        exit(1);
      }
      next(&data[start]);
      fclose(input_source);
    }
  }

  input_source = stdin;
  next(&data[start]);

  return 0;
}
