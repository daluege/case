static volatile int begin() { }
extern char etext, end;

//TODO: minor add MAP_NORESERVE
#define __USE_GNU

#ifndef codebase_process_h
#define codebase_process_h

#include <fcntl.h>
#include <ucontext.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include "memory.h"
#include "op.h"

#define PROCESS_X64 64

// Scale corresponds to factor 2^scale
#define PROCESS_SCALE 2
#define PROCESS_SPACE 3
#define PROCESS_PAGE  (INT16_MIN<<1>>PROCESS_SPACE)
// Cleft due to the high byte of a spring jump having to be shared with the opcode of the next jump
#define PROCESS_CLEFT 0xE8000000

struct page {
  uint8_t jump;
  uint8_t trap;
  uint16_t size;
  uint8_t text[];
};

struct process {
  size_t pagesize;
  size_t base;
  size_t text;
  size_t data;
  size_t heap;
  void *ip;
  struct page *page;
  ucontext_t *ctx;
  int trap;
  char open;
};

static struct process process = { 0 };

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

int branch_link(void *dest, void *addr, int limit) {
  uint8_t *text = addr;
  int32_t rel = (size_t) dest-(size_t) addr;
  if (addr+rel != dest || limit < 5) error("Not implemented");
  text[0] = 0xE9;
  memcpy(text+1, &rel, 4);
  return 5;
}

int branch_call(void *addr, void *dest, int limit) {
  uint8_t *text = addr;
  int32_t rel = (size_t) dest-(size_t) addr;
  if (addr+rel != dest || limit < 5) error("Not implemented");
  text[0] = 0xE8;
  memcpy(text+1, &rel, 4);
  return 5;
}

void *branch_resolve(void *addr) {
  uint8_t *text = addr;
  switch (*text++) {
    case 0xEB: return addr+(int8_t) *text;
    case 0xE9: case 0xE8: return addr+*(int32_t *) text;
    default: return NULL;
  }
}

int branch_size(void *addr) {
  uint8_t *text = addr, reg, mod, rm;
  switch (*text++) {
    case 0xEB: return 2; // Short JMP
    case 0xE9: case 0xE8: return 5; // Near JMP and CALL
    case 0xFF:
      reg = *text++>>3&7;
      mod = *text>>6;
      rm = *text&7;
      switch (reg) {
        case 4: case 2: // Opcode extensions for indirect JMP and CALL
          if (rm == 4) text++; // SIB byte
          if (mod == 1) text++; // 8-byte displacement
          if (mod == 2) text += 4; // 32-byte displacement
          return (size_t) text-(size_t) addr;
        case 6: error("Not implemented");
      }
      return -1;
    case 0xEA: error("32 bit not implemented");
  }
}

static inline void *getspring(void *data) {
  void *spring = (void *) ((size_t) data<<PROCESS_SCALE<<PROCESS_SPACE);
  *(uint16_t *) &spring >>= PROCESS_SPACE;
  return spring;
}
static inline void *gettext(void *data) {
  return branch_resolve(getspring(data));
}
static inline void *getpage(void *data) {
  return (void *) (PROCESS_PAGE+((((size_t) data<<PROCESS_SCALE<<PROCESS_SPACE)+(int32_t) PROCESS_CLEFT)>>16<<16));
}

static inline void set_tf() {
  asm("pushfq; orl $0x100, (%rsp); popfq");
}
static inline void unset_tf() {
  asm("pushfq; xorl $0x100, (%rsp); popfq");
}

static inline size_t get_register(char reg, ucontext_t *ctx) {
  switch (reg) {
    case 0: return ctx->uc_mcontext.gregs[REG_RAX];
    case 1: return ctx->uc_mcontext.gregs[REG_RCX];
    case 2: return ctx->uc_mcontext.gregs[REG_RDX];
    case 3: return ctx->uc_mcontext.gregs[REG_RBX];
    case 4: return ctx->uc_mcontext.gregs[REG_RSP];
    case 5: return ctx->uc_mcontext.gregs[REG_RBP];
    case 6: return ctx->uc_mcontext.gregs[REG_RSI];
    case 7: return ctx->uc_mcontext.gregs[REG_RDI];
  }
}

void *resolve(void *addr, ucontext_t *ctx) {
  size_t result = 0;
  uint8_t *data = addr, s, d, reg, mod, rm, scale, index, base;
  int flags;

  flags = opflags(data);
  if (flags&OP_REGULAR == 0) return NULL;
  if (*data++&2 > 0) return NULL; // First operand is not a memory location

  reg = *data>>3&7;
  mod = *data>>6;
  rm = *data++&7;
  if (mod == 3) return NULL; // Destination is not indirect but a register

  if (rm == 5 && mod == 0) { // 32-bit displacement-only mode
    result = *(size_t *) data;
    data += 4;
  } else {
    if (rm == 4) {
      scale = *data>>6;
      index = *data>>3&7;
      base = *data++&7;

      if (base != 5) result = get_register(base, ctx);
      if (mod == 2) result &= 255; // 8-bit base register

      result += get_register(index, ctx)<<scale;
    } else {
      result = get_register(rm, ctx);
    }
    if (mod == 1) {
      result += *data++;
    } else if (mod == 2) {
      result += *(size_t *) data;
      data += 4;
    }
  }

  return (void *) result;
}

void step(void *addr) {
  uint8_t *spring, *text;
  struct page *page;
  int flags, size;
  size_t dest;

  process_open();

  if (process.ip != NULL) {
    spring = getspring(process.ip);
    page = process.page;
    flags = opflags(process.ip);

    if (flags&OP_KNOWN) {
      if (flags&OP_BRANCH) size = branch_size(process.ip);
      else size = (size_t) addr-(size_t) process.ip;

      if (size > 0 && size <= OP_MAX_LENGTH) {
        // Mark instruction secure
        branch_link(spring, page->text+page->size, 5);
        page->size += size;
        page->text[page->size] = OP_INT3;
      }
    }
  }

  spring = getspring(addr);
  page = getpage(addr);
  flags = opflags(addr);

  translate(page->text[page->size], addr);

  if (page != process.page) {
    // Page transition
    process_close();
  } else {
    int secure;
    // The next operation is secure if the destination is known and does not point to an unprotected core segment
    dest = (size_t) resolve(addr, process.ctx);
    secure = dest && dest >= process.heap && dest^(size_t) page > INT16_MAX && dest^(size_t) spring > INT16_MAX;
    // Write-protect core segments if not secure (3 syscalls required)
    if (!secure) process_close();
  }

  process.ip = addr;
  process.page = page;
}


void protexec(void *addr) {
  process_seal(addr);
  process.ip = NULL;
  set_tf();
  step(addr);
}
void protwrite(void *addr) {
  process_release(addr);
}

void trap(int signum, siginfo_t *info, ucontext_t *ctx) {
  uint8_t *rip = (uint8_t *) ctx->uc_mcontext.gregs[REG_RIP];
  int trapno = ctx->uc_mcontext.gregs[REG_TRAPNO];

  step(rip);
}


void segv(int signum, siginfo_t *info, ucontext_t *ctx) {
  //puts("SEGV");
  void *dest = info->si_addr;
  void *rip = (void *) ctx->uc_mcontext.gregs[REG_RIP];
  unsigned long err = ctx->uc_mcontext.gregs[REG_ERR];

  switch (err) {
    case 4: // Read EINTR
      break;
    case 6: // Write ENXIO
      protwrite(dest);
      break;
    case 20: // Exec ENOTDIR
      protexec(dest);
      break;
  }

  /*
  if (dest == rip) { // Exec
    uint8_t *i, *end;
    dest -= (size_t) dest%process.pagesize;
    mprotect(dest, process.pagesize, PROT_WRITE|PROT_READ);
    for (i = dest, end = i+process.pagesize; i < end; i++) *i = OP_INT3;
    mprotect(dest, process.pagesize, PROT_EXEC|PROT_READ);
  }
  */
}

int translate(void *dest, void *src) {
  int flags = opflags(src);
  uint8_t *data = src, *text = dest;

  if (flags&OP_INSECURE) switch (*data) {
    case 0xFF: return translate_branch(dest, src);
    case 0xCD: case 0xCE:
      *(uint32_t *) text = 0xCD06;
      return 2;
  }
  if (flags&OP_KNOWN == 0) {
    *(uint32_t *) text = 0xCD06;
    return 2;
  }
  memcpy(dest, data, OP_MAX_LENGTH);
  return OP_MAX_LENGTH;
}

static const struct {
  uint8_t call[5];
  uint8_t shift[11];
  uint8_t ret[1];
} dict = {
  { 0xE8, 0x0C, 0, 0, 0 }, // Push RIP+12 to the stack
  { 0x48, 0xC1, 0x24, 0x24, PROCESS_SCALE+PROCESS_SPACE, 0x66, 0xC1, 0x6C, 0x24, 0xFE, PROCESS_SPACE }, // Shift right by PROCESS_SCALE+PROCESS_SPACE, shift left by PROCESS_SCALE
  { 0xC3 } // Jump by return
};

int translate_branch(void *dest, void *src) {
  uint8_t *data = src, *text = dest, *c = data, reg, mod, rm;

  switch (*data) {
    case 0xFF:
      reg = *data++>>3&7;
      mod = *data>>6;
      rm = *data&7;

      switch (reg) {
        case 2: // Opcode extension for indirect CALL
          memcpy(text, dict.call, sizeof(dict.call));

        case 4: // Opcode extension for indirect JMP and CALL
          *text++ = *data++;
          *text++ = *data++^reg<<3|6<<3; // Clear opcode extension and change it to 6 for PUSH

          if (rm == 4) *text++ = *data++; // SIB byte
          if (mod == 1) *text++ = *data++; // 8-byte displacement
          if (mod == 2) {
            *(int32_t *) text = *(int32_t *) data; // 32-byte displacement
            text += 4;
            data += 4;
          }

          memcpy(text, dict.shift, sizeof(dict.shift));
          text += sizeof(dict.shift);

          memcpy(text, dict.ret, sizeof(dict.ret));
          text += sizeof(dict.ret);

          return (size_t) text-(size_t) dest;
      }
      break;

    case 0xC3: case 0xCB: // RET instruction
      memcpy(text, dict.shift, sizeof(dict.shift));
      text += sizeof(dict.shift);

      memcpy(text, dict.ret, sizeof(dict.ret));
      text += sizeof(dict.ret);
  }

  dest = branch_resolve(data);
  if (dest) {
    uint8_t *spring = getspring(dest), *dest = branch_resolve(spring);
    if (dest) return branch_link(dest, text, -1);
    else return branch_link(spring, text, -1);
  }

  return -1;
}

void *copy(const void *dest, const void *src, size_t n, unsigned int prot) {
  void *protected = (void *) dest;
  long pagesize = process.pagesize;
  if (pagesize <= 0) pagesize = sysconf(_SC_PAGESIZE);
  if (pagesize < 0) return NULL;

  // Unprotect .rodata section page containing dest
  if (mprotect(protected, pagesize, PROT_WRITE|PROT_READ|PROT_EXEC) < 0) return NULL;
  memcpy(protected, src, n);
  if (mprotect(protected-(size_t) protected%pagesize, pagesize, prot) < 0) {
    memset(protected, 0, n); // If sealing failed, erase written data
    return NULL;
  }
  return protected;
}

void process_seal(void *data) {
  int i;
  uint8_t *spring;
  struct page *page;
  data -= (size_t) data%process.pagesize;
  spring =  getspring(data);

  // Make all fields call the page trap
  page = getpage(data);
  page->trap = OP_INT3;
  for (i = 0; i < process.pagesize; i++) branch_call(&page->trap, spring+(1<<PROCESS_SCALE), 5);

  mprotect(spring, process.pagesize<<PROCESS_SCALE, PROT_READ|PROT_EXEC);
  mprotect(data, process.pagesize, PROT_READ);
}
void process_release(void *data) {
  uint8_t *text;
  data -= (size_t) data%process.pagesize;
  text = (uint8_t *) ((size_t) data<<PROCESS_SCALE);
  mprotect(text, process.pagesize<<PROCESS_SCALE, PROT_READ|PROT_WRITE);
  mprotect(data, process.pagesize, PROT_READ|PROT_WRITE);
}

void process_open(void *data) {
  // TODO: throw error if unsuccessful
  if (process.open) return;
  data -= (size_t) data%process.pagesize;
  mprotect(process.data, process.heap-process.data, PROT_READ|PROT_WRITE);
  mprotect(getpage(data), (uint16_t) -PROCESS_PAGE, PROT_READ|PROT_WRITE|PROT_EXEC);
  mprotect(getspring(data), PROCESS_PAGE, PROT_READ|PROT_WRITE|PROT_EXEC);
}
void process_close(void *data) {
  // TODO: throw error if unsuccessful
  if (!process.open) return;
  data -= (size_t) data%process.pagesize;
  mprotect(process.data, process.heap-process.data, PROT_READ);
  mprotect(getpage(data), (uint16_t) -PROCESS_PAGE, PROT_READ|PROT_EXEC);
  mprotect(getspring(data), PROCESS_PAGE, PROT_READ|PROT_EXEC);
}

extern void *process_create() {
  if (process.base) return (void *) process.base;
  // TODO: test signal handlers
  // TODO: protect global const struct process process by PROT_READ

  register size_t rsp asm("rsp");
  int r;
  size_t stack, text, data, heap;
  struct sigaction tact, sact;
  struct process p;
  size_t length;

  memset(&p, 0, sizeof(process));
  
  // Get the system page size
  p.pagesize = sysconf(_SC_PAGESIZE);
  if (p.pagesize <= 0) return NULL;

  // Get the minimum base address for any text reflection
  for (p.base = 1; p.base < rsp; p.base <<= 1);
  p.base >>= PROCESS_SCALE+PROCESS_SPACE;

  p.text = (size_t) &begin-(size_t) &begin%p.pagesize;
  p.heap = (size_t) &end;
  p.data = p.heap-p.heap%p.pagesize;

  // Unmap any pages before the beginning of the text segment
  if (munmap(NULL, p.text) < 0) return NULL;

  // Find beginning of the data segment
  while (p.data-p.pagesize > (size_t) &etext && mprotect((void *) p.data-p.pagesize, p.pagesize, PROT_READ|PROT_WRITE|PROT_EXEC) >= 0) p.data -= p.pagesize;

  // Map first page
  //if (process_map((void *) p.base, p.pagesize, PROT_NONE) < 0) return NULL;

  // Register trap
  memset(&tact, 0, sizeof(struct sigaction));
  tact.sa_sigaction = (void (*)(int, siginfo_t *, void *)) trap;
  sigaction(SIGTRAP, &tact, NULL);

  // Register sigsegv handler
  memset(&sact, 0, sizeof(struct sigaction));
  sact.sa_sigaction = (void (*)(int, siginfo_t *, void *)) segv;
  sact.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sact, NULL);

  //set_trap();

  // Make process parameters public on success
  process = p;
  return (void *) process.base;
}

extern void *process_malloc(size_t size) {
  register size_t rsp asm("rsp");
  void *addr, *reserve;

  // malloc allocates memory without PROT_EXEC rights

  // Assumes address space above data segment is at sole disposal of
  // process_malloc, otherwise allocation may fail returning NULL
  addr = malloc(size);
  if (!addr) return NULL;

  // Address too low
  if ((size_t) addr+size > (size_t) addr<<PROCESS_SCALE) {
    // Reallocate memory if the end of the section might overlap the beginning
    // of the scaled section, second allocation never overlaps due to arithmetics
    reserve = addr;
    addr = malloc(size);
    free(reserve);
    if (!addr) return NULL;
  }

  // Address too high
  if ((size_t) (addr+size)<<PROCESS_SCALE >= rsp-process.pagesize) {
    // If scaled pages do not fit in before the stack, memory is exhausted
    free(addr);
    return NULL;
  }

  // Reserve address map
  if (mreserve((void *) ((size_t) addr<<PROCESS_SCALE), size<<PROCESS_SCALE) < 0) {
    free(addr);
    return NULL;
  }
  return addr;
}

#endif
