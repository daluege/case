#ifndef codebase_memory_h
#define codebase_memory_h

#include <unistd.h>
#include <sys/mman.h>

int mreserve(void *addr, size_t length) {
  static int fd = -2;
  if (fd < -1) fd = -1; // open("/dev/zero", 0); // If -1 is returned, mmap reserves space in memory

  long pagesize = sysconf(_SC_PAGESIZE);
  if (pagesize < 0) return 0;

  length = (((size_t) addr+length-1)/pagesize+1)*pagesize-(size_t) addr;
  addr -= (size_t) addr%pagesize;

  void *map = mmap(addr, length, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, fd, 0);
  if (map == MAP_FAILED) return -1;
  if (map != addr) {
    munmap(map, length);
    return -1;
  }
  return 0;
}

#endif
