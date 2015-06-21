#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "memory.h"
#include "process.h"
#include "sys.h"

#define error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

static volatile int exec_begin() {
  return 18;
}
static volatile int exec_end() {
  return 19;
}

int main() {
  void *p;
  int r;
  char *data = process_create();
  if (!data) return;


  r = sys_brk((void *) process.base+10000);
  printf("%p %i \n", process.base, r);
  memcpy((void *) process.base, exec_begin, exec_end-exec_begin);
  
  int (*exe)() = (void *) process.base;
  int x = exe();
  printf("%i \n", x);
  puts("jsjs");
  exit(0);
  return 0;
}

