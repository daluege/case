CC=gcc
CFLAGS=-ldl

all: case

case:
	$(CC) src/case.c -o case $(CFLAGS)

