#include "input.h"

#include <stdio.h>
#include <stdlib.h>

#include <readline/history.h>
#include <readline/readline.h>

static char *input_buffer = NULL;

void input_init(void) {
  using_history();
  read_history(HISTORY_FILE);
}

char *read_line(char *prompt) {
  if (input_buffer)
    free(input_buffer);
  input_buffer = readline(prompt);
  // EOF on its own returns NULL
  if (input_buffer) {
    add_history(input_buffer);
    write_history(HISTORY_FILE);
  }
  return input_buffer;
}
