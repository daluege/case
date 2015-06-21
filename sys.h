#ifndef case_sys_h
#define case_sys_h

int sys_brk(void *addr) {
  static size_t brk = NULL;
  size_t page;

  if (!brk) brk = process.base;
  if ((size_t) addr < process.base) return -1;

  if ((size_t) addr < brk) {
    page = process.pagesize*(((size_t) addr-1)/process.pagesize+1);
    if (munmap((void *) page, brk-page) < 0) {
      errno = ENOMEM;
      return -1;
    }
  } else {
    page = process.pagesize*((brk-1)/process.pagesize+1);
    if (mmap((void *) page, (size_t) addr-page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) {
      errno = ENOMEM;
      return -1;
    }
  }
  brk = (size_t) addr;
  return 0;
}

#endif
