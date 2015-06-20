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
#include "code.h"
#include "op.h"

// Constants
#define PROCESS_X64   64

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
  uint8_t *ip;
  size_t displacement;
  struct page *page;
  ucontext_t *ctx;
  int trap;
  char open;
};

typedef spring_t uint32_t;

static struct process process = { 0 };

static inline void *getdata(void *spring) {
  *(uint16_t *) &spring <<= PROCESS_SPACE;
  return spring>>PROCESS_SPACE>>PROCESS_SCALE;
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

void process_seal(uint8_t *data) {
  int i;
  spring_t *spring;
  uint8_t *target;
  struct page *page;

  data -= (size_t) data%process.pagesize;
  spring =  getspring(data);
  page = getpage(data);

  // Initialize spring field: link all target points to a trap
  for (i = 0, target = spring; i < process.pagesize; i++) {
    target += footprint(data[i]); // Reserve space possibly claimed by instruction
    *target = OP_INT3; // Signal a trap when calling untranslated positions
    branch_call(spring[i], target, 5); // Places spring address on the stack and jumps to trap
  }
  // Write-protect the spring page
  mprotect(spring, process.pagesize<<PROCESS_SCALE, PROT_READ|PROT_EXEC);
  // Watch the data page for changes
  mprotect(data, process.pagesize, PROT_READ);
}
void process_release(uint8_t *data) {
  uint8_t *text;
  data -= (size_t) data%process.pagesize;
  text = (uint8_t *) ((size_t) data<<PROCESS_SCALE);

  // Signal execution attempts on the spring page
  mprotect(spring, process.pagesize<<PROCESS_SCALE, PROT_READ);
  // Release the data page from monitoring
  mprotect(data, process.pagesize, PROT_READ|PROT_WRITE);
}
void process_open() {
  // TODO: throw error if unsuccessful
  if (process.open) return;
  process.open = 1;
  void *page = process.ip-(size_t) process.ip%process.pagesize;
  mprotect((void *) process.data, process.heap-process.data, PROT_READ|PROT_WRITE);
  mprotect(getpage(page), (uint16_t) -PROCESS_PAGE, PROT_READ|PROT_WRITE|PROT_EXEC);
  mprotect(getspring(page), PROCESS_PAGE, PROT_READ|PROT_WRITE|PROT_EXEC);
}
void process_close() {
  // TODO: throw error if unsuccessful
  if (!process.open) return;
  void *page = process.ip-(size_t) process.ip%process.pagesize;
  mprotect((void *) process.data, process.heap-process.data, PROT_READ);
  mprotect(getpage(page), (uint16_t) -PROCESS_PAGE, PROT_READ|PROT_EXEC);
  mprotect(getspring(page), PROCESS_PAGE, PROT_READ|PROT_EXEC);
  process.open = 0;
}

static inline void set_tf() {
  asm("pushfq; orl $0x100, (%rsp); popfq");
}
static inline void unset_tf() {
  asm("pushfq; xorl $0x100, (%rsp); popfq");
}

void step(void *text) {
  spring_t *spring;
  uint8_t *data;
  struct page *page;
  int flags, size;
  size_t dest;

  data = text-process.displacement;

  process_open();

  if (process.ip != NULL) {
    flags = opflags(process.ip);

    // For the set of jump instructions, we know their size
    if (opflags(process.ip)&OP_BRANCH) size = branch_size(process.ip);
    // Other sizes will be determined based on the RIP
    else size = (size_t) text-(size_t) process.ip;

    if (size > 0 && size <= OP_MAX_LENGTH) {
      instruct(data, size);
    } else {
      unset_tf(); // A jump has occured, runtime translation ends for this pipeline
      return;
    }
  }

  spring = getspring(data);
  page = getpage(data);

  // TODO: loop over next following regular instructions, disable TF and come back by INT3

  size = translate(text, data);

  // Write-protect page and sensitive segments
  if (page != process.page) { // Page crossing
    process_close(); // Always close as page looses focus
  } else {
    int secure;
    // The next operation is secure if the destination is known and does not point to an unprotected core segment
    dest = (size_t) resolve(text, process.ctx);
    secure = dest && dest >= process.heap && dest^(size_t) page > INT16_MAX && dest^(size_t) spring > INT16_MAX;
    // Only write-protect if next operation behavior unknown, otherwise save 3 syscalls
    if (!secure) process_close();
  }

  process.displacement += size;
  process.ip = text;
  process.page = page;
}

void instruct(uint8_t *data, char size) {
  spring_t *spring = getspring(data);
  uint8_t *page = process.page;

  // Link instruction
  branch_link(spring, page->text+page->size, 5);
  // Causes retranslation upon instruction boundary shift
  for (int i = 1; i < size; i++) spring[i] = OP_INT3; // TODO: check for page boundary
  // TODO: process_seal on boundary shift so page gets completely flushed

  page->size += size;
  page->text[page->size] = OP_INT3;
}

static inline char footprint(uint8_t *data) {
  static uint8_t footprints[256] = { 0 };
  // TODO: move to init process_create
  if (!footprints[0]) {
    memset(footprints, 1, sizeof(footprints));
    footprints[0xEB] = 4; // Short to near jump may cost 3 bytes
    memset(footprints+0x70, 4, 0x7F-0x70); // Conditional short to near jump
    // TODO: complete
  }
  if (*data == 0xFF) switch (data[1]>>3&7) {
    case 2: return 1+sizeof(dict.call)+sizeof(dict.shift)+sizeof(dict.ret);
    case 4: return 1+sizeof(dict.shift)+sizeof(dict.ret);
  }
  return footprints[*data];
}

int translate(uint8_t *text, uint8_t *data) {
  int flags = opflags(src);

  if (flags&OP_INSECURE) switch (*data) {
    case 0xFF: return branch_translate(dest, src);
    case 0xCD: case 0xCE:
      *(uint32_t *) text = 0xCD06;
      return 2;
    default: error("Not implemented");
  }
  if (flags&OP_KNOWN == 0) {
    *(uint32_t *) text = 0xCD06;
    return 2;
  }
  memcpy(dest, data, OP_MAX_LENGTH);
  return 0;
}

void enter(void *data) {
  uint8_t *spring, *page, *text;
  spring = getspring(data);
  page = getpage(data);
  text = branch_resolve(spring);

  // Page-relative overhead of translated text with respect to data
  process.displacement = text-data;
  process.ip = NULL;

  step(text);
}

void process_exec(void *data) {
  process_seal(data);
  enter(data);
}
void process_write(void *addr) {
  process_release(addr);
}
void process_breakpoint(uint8_t *text) {
  uint8_t *spring, *data;
  struct page *page;

  // Breakpoints are always induced by a CALL
  asm("pop %0" : "=r" (spring)); // Get return address from the stack pointer
  // Get instruction before (on 4-byte spring boundary)
  spring -= 2;
  spring &= -1<<PROCESS_SCALE;
  enter(getdata(spring));
}

void process_trap(int signum, siginfo_t *info, ucontext_t *ctx) {
  uint8_t *rip = (uint8_t *) ctx->uc_mcontext.gregs[REG_RIP];
  int trapno = ctx->uc_mcontext.gregs[REG_TRAPNO];

  if (trapno != 1) process_breakpoint(rip);
  else step(rip);
}
void process_segv(int signum, siginfo_t *info, ucontext_t *ctx) {
  void *dest = info->si_addr;
  void *rip = (void *) ctx->uc_mcontext.gregs[REG_RIP];
  unsigned long err = ctx->uc_mcontext.gregs[REG_ERR];

  switch (err) {
    case 4: break; // EINTR
    case 6: process_write(dest); break; // ENXIO
    case 20: process_exec(dest); break; // ENOTDIR
  }
}

extern void *process_create() {
  if (process.base) return (void *) process.base;
  // TODO: test signal handlers

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

  // End of the data segment is provided by POSIX
  p.heap = (size_t) &end;
  p.data = p.heap-(p.heap-1)%p.pagesize+1+p.pagesize;
  p.text = (size_t) &etext;
  p.text -= (p.text-1)%p.pagesize+1+p.pagesize;

  if (p.data < p.text) return NULL;

  // Find beginning of the data segment
  while (p.data-p.pagesize >= (size_t) &etext && mprotect((void *) p.data-p.pagesize, p.pagesize, PROT_READ|PROT_WRITE) >= 0) p.data -= p.pagesize;

  // Unmap any pages between text and data segment
  //if (munmap((void *) p.text, p.data-p.text) < 0) return NULL;

  // Find beginning of the text segment and protect text
  while (p.text-p.pagesize >= 0 && mprotect((void *) p.text-p.pagesize, p.pagesize, PROT_READ|PROT_EXEC) >= 0) p.text -= p.pagesize;

  // Unmap any pages before the beginning of the text segment
  if (munmap(NULL, p.text) < 0) return NULL;

  // Register trap
  memset(&tact, 0, sizeof(struct sigaction));
  tact.sa_sigaction = (void (*)(int, siginfo_t *, void *)) process_trap;
  sigaction(SIGTRAP, &tact, NULL);

  // Register sigsegv handler
  memset(&sact, 0, sizeof(struct sigaction));
  sact.sa_sigaction = (void (*)(int, siginfo_t *, void *)) process_segv;
  sact.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sact, NULL);

  //set_trap();

  process = p; // Publish process
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

static const struct {
  uint8_t call[5];
  uint8_t shift[11];
  uint8_t ret[1];
} dict = {
  { 0xE8, 0x0C, 0, 0, 0 }, // Push RIP+12 to the stack
  { 0x48, 0xC1, 0x24, 0x24, PROCESS_SCALE+PROCESS_SPACE, 0x66, 0xC1, 0x6C, 0x24, 0xFE, PROCESS_SPACE }, // Shift right by PROCESS_SCALE+PROCESS_SPACE, shift left by PROCESS_SCALE
  { 0xC3 } // Jump by return
};

int branch_translate(uint8_t *text, uint8_t *data) {
  uint8_t reg, mod, rm;

  switch (*data) {
    case 0xFF:
      reg = *data++>>3&7;
      mod = *data>>6;
      rm = *data&7;

      switch (reg) {
        case 2: // Opcode extension for indirect CALL
          memcpy(text, dict.call, sizeof(dict.call));
          text += sizeof(dict.call);

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


#endif
