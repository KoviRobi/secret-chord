#include <stdint.h>
#include <stdio.h>

#define ASIZE(x) (sizeof((x)) / sizeof((x)[0]))

typedef void instruction(void **pc);

int stack[100];
unsigned stack_p;

void push(int value) { stack[stack_p++] = value; }
int pop(void) { return stack[--stack_p]; }

instruction lit;
instruction stop;

instruction *prog[] = {
	&lit,
	(instruction *)3,
	&stop,
};

void next(void **pc) {
	instruction *next_instr = *pc;
	next_instr(pc + 1);
}

void lit(void **pc) {
	push(*(int *)pc++);
	next(pc);
}

void stop(void **pc) {}

int main(int argc, char *argv[]) {
	int start = 0;
	prog[start]((void **)&prog[start + 1]);

	// Print stack after exit
	printf("<%u>", stack_p);
	for (int i = 0; i < stack_p; i++)
		printf(" %d", stack[i]);
}
