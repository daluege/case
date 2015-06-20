#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "memory.h"
#include "process.h"

#define error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

int main() {
  char *data = process_create();

  return 0;
}
