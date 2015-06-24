//#define DEBUG

#include <elf.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include "memory.h"
#include "process.h"
#include "sys.h"

#define error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

static volatile int untrusted() {
  return 18;
}

int main() {
  process_exe(untrusted);

  puts("Works like a charm");
  
  return 0;
}

