#include <stdio.h>

#define ASIZE(x) (sizeof((x)) / sizeof((x)[0]))

typedef void instruction(void);

int stack[100];
unsigned stack_p;

void push(int value) { stack[stack_p++] = value; }
int pop(void) { return stack[--stack_p]; }

instruction put_0;
instruction increment;

instruction *prog[] = {
	&put_0,
	&increment,
};
int pc = 0;

void put_0(void) { push(0); }

void increment(void) { push(pop() + 1); }

int main(int argc, char *argv[]) {
	for (pc = 0; pc < ASIZE(prog); pc++) {
		prog[pc]();
	}

	// Print stack after exit
	printf("<%u>", stack_p);
	for (int i = 0; i < stack_p; i++)
		printf(" %d", stack[i]);
}
