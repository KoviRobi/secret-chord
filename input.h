#pragma once

#include <stdio.h>

#define HISTORY_FILE (".fth.hist")

void input_init(void);

char *read_line(FILE *input_source, char *prompt);
