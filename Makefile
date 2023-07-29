.PHONY: all test

CFLAGS?=-std=c11
CFLAGS+= -g -O2
CFLAGS+= $(shell pkg-config --libs --cflags readline)

all: interactive-bootstraps.pdf

%.tex: %.nw
	noweave -delay $< > $@

%.pdf %.aux %.log: %.tex
	xelatex $<
