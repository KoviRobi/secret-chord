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

char *read_line(FILE *input_source, char *prompt) {
  if (input_buffer)
    free(input_buffer);

  if (input_source == stdin) {
    input_buffer = readline(prompt);
    // EOF on its own returns NULL
    if (input_buffer) {
      add_history(input_buffer);
      write_history(HISTORY_FILE);

      // Re-add newline
      size_t len = strlen(input_buffer);
      char *eol_buffer = malloc(len + 2);
      strncpy(eol_buffer, input_buffer, len);
      eol_buffer[len] = '\n';
      eol_buffer[len + 1] = '\0';
      free(input_buffer);
      input_buffer = eol_buffer;
    }
    return input_buffer;
  } else {
    input_buffer = malloc(1024);
    int read = fread(input_buffer, 1, 1023, input_source);
    input_buffer[read] = '\0';
    for (int i = 0; i < read; i++) {
      if (input_buffer[read - i - 1] == '\r' ||
          input_buffer[read - i - 1] == '\n' ||
          input_buffer[read - i - 1] == '\t' ||
          input_buffer[read - i - 1] == ' ') {
        input_buffer[read - i - 1] = '\0';
        fseek(input_source, -i, SEEK_CUR);
        return input_buffer;
      }
    }
    if (read > 0) {
      return input_buffer;
    }
    return NULL;
  }
}
