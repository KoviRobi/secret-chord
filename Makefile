.PHONY: test

CFLAGS?=-std=c11
CFLAGS+= -m32
CFLAGS+= -g -O2
CFLAGS+= $(shell pkg-config --libs --cflags readline)

test: fth
	echo "1 2 over - 1+ dup rot and or invert 1-" | ./fth | tail -n1 | grep '<1> -4'

fth: fth.c leb128.c leb128.h input.o
	$(CC) $(CFLAGS) fth.c leb128.c input.o -o $@

test_leb128: test_leb128.c leb128.c leb128.h
	$(CC) $(CFLAGS) leb128.c test_leb128.c -o test_leb128

input.o: input.c input.h
	$(CC) $(CFLAGS) input.c $(shell pkg-config --libs --cflags readline) -c -o input.o
