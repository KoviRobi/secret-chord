#include "hexdump.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

void hexdump(const void *data, size_t len) {
	const uint8_t *bytes = data;
	for (size_t i = 0; i < len; i++) {
		if ((i & 15) == 0) {
			printf("%08lX:", i);
		}
		if ((i & 1) == 0) {
			printf(" ");
		}
		printf("%02x", bytes[i]);
		if ((i & 15) == 15 || i == len - 1) {
			printf("\n");
		}
	}
}

int main(int argc, char **argv) {
	printf("x\n");
	const uint32_t x = 1;
	hexdump(&x, sizeof(x));

	printf("y\n");
	const uint32_t y = 0x1234;
	hexdump(&y, sizeof(y));

	printf("z\n");
	const uint32_t z = -1;
	hexdump(&z, sizeof(z));

	printf("s\n");
	const char s[] = "Hello, world";
	hexdump(&s, sizeof(s));

	printf("t\n");
	const char *t = "Hello, world";
	hexdump(&t, sizeof(t));
}
