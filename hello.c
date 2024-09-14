#include <stdio.h>

int main(int argc, char **argv) {
	for (int index = 0; index < argc; index++) {
		printf("Argument %d is %s\n", index, argv[index]);
	}
}
