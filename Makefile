.PHONY: test

CFLAGS?=-std=c11
CFLAGS+= -m32
CFLAGS+= -g -O2
CFLAGS+= $(shell pkg-config --libs --cflags readline)

test: test_leb128
	./test_leb128

test_leb128: test_leb128.c leb128.c leb128.h
	$(CC) $(CFLAGS) leb128.c test_leb128.c -o test_leb128
