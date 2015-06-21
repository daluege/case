extern char etext, end;

//TODO: minor add MAP_NORESERVE
#define __USE_GNU

#ifndef case_process_h
#define case_process_h

#include <fcntl.h>
#include <ucontext.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
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
// Number of free highest bits in lowest 2 byte
#define PROCESS_SPACE 3
// Beginning of text segment within space
#define PROCESS_PAGE  (1<<16>>PROCESS_SPACE)
// Cleft due to the high byte of a spring jump having to be shared with the opcode of the next jump
#define PROCESS_CLEFT 0xE8CC0000 // Makes redundant high bytes usable as INT3 and a succeding JMP

static const struct {
  uint8_t call[5];
  uint8_t shift[11];
  uint8_t ret[1];
} dict = {
  { 0xE8, 0x0C, 0, 0, 0 }, // Push RIP+12 to the stack
  { 0x48, 0xC1, 0x24, 0x24, PROCESS_SCALE+PROCESS_SPACE, 0x66, 0xC1, 0x6C, 0x24, 0xFE, PROCESS_SPACE }, // Shift right by PROCESS_SCALE+PROCESS_SPACE, shift left by PROCESS_SCALE
  { 0xC3 } // Jump by return
};

typedef uint32_t spring_t;

struct page {
  uint8_t jump;
  uint8_t trap;
  uint16_t size;
  void *open;
  uint8_t carry[OP_MAX_LENGTH];
  uint8_t text[];
};

struct process {
  size_t pagesize;
  size_t base;
  size_t text;
  size_t data;
  size_t heap;
  int trap;
  void *open;
};

struct context {
  void *text;
  void *data;
  void *spring;
  struct page *page;
  char size;
  ucontext_t *ctx;
};

static struct process process = { 0 };
static struct context context = { 0 };

static inline void *getdata(void *spring) {
  *(uint16_t *) &spring <<= PROCESS_SPACE;
  return (void *) ((size_t) spring>>PROCESS_SPACE>>PROCESS_SCALE);
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

static inline void debug_context() {
#ifdef DEBUG
  printf("Page:\t%p\nData:\t%p\t- %p\nText:\t%p\t- %p\nSpring:\t%p\n", context.page, context.data, *(size_t *) context.data, context.text, *(size_t *) context.text, context.spring);
#endif
}
static inline void debug(const char *message) {
#ifdef DEBUG
  puts(message);
#endif
}
static inline void debug_ctx(ucontext_t *ctx) {
#ifdef DEBUG
  printf("RIP:\t%p\t- %p\nTF:\t%i\nERR:\t%i\n", ctx->uc_mcontext.gregs[REG_RIP],  *(size_t *) ctx->uc_mcontext.gregs[REG_RIP], ctx->uc_mcontext.gregs[REG_EFL]&0x100, ctx->uc_mcontext.gregs[REG_ERR]);
#endif
}

int branch_translate(uint8_t *text, uint8_t *data) {
  uint8_t *destination, reg, mod, rm;
  int size = 0;

  switch (*data) {
    case 0xFF:
      reg = *data++>>3&7;
      mod = *data>>6;
      rm = *data&7;

      switch (reg) {
        case 2: // Opcode extension for indirect CALL
          // Prepend a push of the RIP
          memcpy(text+size, dict.call, sizeof(dict.call));
          size += sizeof(dict.call);

        case 4: // Opcode extension for indirect JMP and CALL
          text[size++] = *data++;
          text[size++] = *data++^reg<<3|6<<3; // Clear opcode extension and change it to 6 for PUSH

          if (rm == 4) text[size++] = *data++; // SIB byte
          if (mod == 1) text[size++] = *data++; // 8-byte displacement
          if (mod == 2) {
            *(int32_t *) (text+size) = *(int32_t *) data; // 32-byte displacement
            size += 4;
            data += 4;
          }

          memcpy(text+size, dict.shift, sizeof(dict.shift));
          size += sizeof(dict.shift);

          memcpy(text+size, dict.ret, sizeof(dict.ret));
          size += sizeof(dict.ret);

          return size;
      }
      break;

    case 0xC3: case 0xCB: // RET context
      memcpy(text, dict.shift, sizeof(dict.shift));
      size += sizeof(dict.shift);

      memcpy(text, dict.ret, sizeof(dict.ret));
      size += sizeof(dict.ret);

      return size;
  }

  // A direct jump of any size to a constant address in the data segment
  destination = branch_resolve(data);
  if (destination) {
    uint8_t *spring = getspring(destination);
    // Data and destination on the same page so the target may be resolved
    if (((size_t) data^(size_t) destination) < process.pagesize) {
      destination = branch_resolve(spring); // Resolve destination spring to text
      if (destination) return branch_link(text, destination, -1);
    }
    // Link the spring to destination
    return branch_link(spring, text, -1);
  }

  return -1;
}

int translate(uint8_t *text, uint8_t *data) {
  int flags = opflags(data), size;

  if (flags&OP_INSECURE) switch (*data) {
    case 0xCC: case 0xCD: case 0xCE:
      *(uint32_t *) text = 0x06CD;
      return 2;
    default:
      size = branch_translate(text, data);
      if (size < 0) error("Not implemented");
      return size;
  }
  if (~flags&OP_KNOWN) {
    *(uint32_t *) text = 0x06CD;
    return 2;
  }
  memcpy(text, data, OP_MAX_LENGTH);
  return 0;
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

int process_seal(uint8_t *data) {
  int i;
  spring_t *spring;
  uint8_t *target;
  struct page *page;

  data -= (size_t) data%process.pagesize;
  spring =  getspring(data);
  page = getpage(data);

  // Reserve spring page
  if (mmap(spring, process.pagesize<<PROCESS_SCALE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) return -1;
  // Reserve text page
  if (mmap(page, (uint16_t) -PROCESS_PAGE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) return -1;
  // Watch the data page for changes
  if (mprotect(data, process.pagesize, PROT_READ) < 0) return -1;

  memset(page, 0, sizeof(struct page));

  // Trap carry field handling old carryover links
  memset(page->carry, OP_INT3, sizeof(page->carry)); // TODO: check sizeof is right

  // Initialize spring field: link all target points to a trap
  for (i = 0, target = page->text; i < process.pagesize; i++) {
    target += footprint(data+i); // Reserve space possibly claimed by context
    *target = OP_INT3; // Signal a trap when calling untranslated positions
    if (i < process.pagesize-1) branch_call(spring+i, target, 5); // Places spring address on the stack and jumps to trap
  }

  return 0;
}
int process_release(uint8_t *data) {
  debug("Release");

  spring_t *spring;

  data -= (size_t) data%process.pagesize;
  spring =  getspring(data);

  // Signal execution attempts on the spring page
  if (mprotect(spring, process.pagesize<<PROCESS_SCALE, PROT_READ) < 0) return -1;
  // Release the data page from monitoring
  if (mprotect(data, process.pagesize, PROT_READ|PROT_WRITE) < 0) return -1;

  return 0;
}
int process_open(void *data) {
  struct page *page;
  data -= (size_t) data%process.pagesize;

  if (process.open == data) return; // Optimization
  if (!process.open && mprotect((void *) process.data, process.heap-process.data, PROT_READ|PROT_WRITE) < 0) return -1;

  if (data) {
    page = getpage(data);
    if (mprotect(page, (uint16_t) -PROCESS_PAGE, PROT_READ|PROT_WRITE|PROT_EXEC) < 0) return -1;
    if (mprotect(getspring(data), PROCESS_PAGE, PROT_READ|PROT_WRITE|PROT_EXEC) < 0) return -1;
    // Insert opened page into linked list
    page->open = process.open;
  }
  process.open = data;
}
int process_close() {
  struct page *page;

  // Close all open pages
  while (process.open) {
    page = getpage(process.open);
    if (mprotect(page, (uint16_t) -PROCESS_PAGE, PROT_READ|PROT_EXEC) < 0) return -1;
    if (mprotect(getspring(process.open), PROCESS_PAGE, PROT_READ|PROT_EXEC) < 0) return -1;
    process.open = page->open; // Remove origin page from linked list
  }
  if (mprotect((void *) process.data, process.heap-process.data, PROT_READ) < 0) return -1;
}

int leave() {
  debug("Leave");
  
  process_close();
  process_open(NULL);
  ctx_unset_tf(context.ctx);

  return 0;
}
int step(void *text, ucontext_t *ctx) {
  debug("Step");

  struct context origin;
  int flags;
  ptrdiff_t size;
  size_t dest;

  // Skip step if the current pointer is within the translation (multiple context unit)
  if (context.size > 0 && text >= context.text && text < context.text+context.size) return 0;

  // Stop tracing once program has reached the core text segment (security of destination is ensured at jump level)
  if ((size_t) text < process.data) return leave();

  // Any write access in the data segment requires process_open
  if (process_open(context.data) < 0) return -1;

  origin = context;
  context.text = text;
  context.ctx = ctx;

  // Revise the last instruction pointer
  if (origin.text) {
    int branch;

    flags = opflags(origin.data);

    // For the set of jump instructions, we know their size
    size = branch_size(origin.data);
    if (size >= 0 && size != context.text-origin.text) return leave();

    // Other sizes will be determined based on the RIP
    if (size < 0) size = context.text-origin.text;

    // Last instruction is not a jump if the size is reasonable
    if (size > 0 && size <= OP_MAX_LENGTH) {
      // Move the data pointer along with text
      context.data += size;
      context.page = getpage(context.data);
      context.spring = getspring(context.data);

      if (context.page == origin.page) {
        // Create a link in the spring field
        branch_link(origin.spring, origin.text, 5);
      } else { // A page transition with the last instruction covering the page boundary is about to happen
        if (process_open(context.data) < 0) return -1; // Open the next page
        size = context.text-origin.text; // Text difference to last step
        context.text = branch_resolve(context.spring); // Find entry point
        // TODO: handle (impossible) NULL return
        memcpy(context.text, origin.text-size, size); // Carry over crossing instruction
        // Cross-page link carry instruction
        branch_link(origin.spring, context.text-size, 5);
        branch_link(origin.text, context.text-size, -1);
      }
    }
  }

  // TODO: loop over next following regular instructions, disable TF and come back by INT3

  context.size = translate(context.text, context.data);
  debug_context();

  // Write-protect page and sensitive segments
  if (origin.page != context.page) {
    if (process_close() < 0) return -1; // Always as origin page is being abandoned
  } else {
    int secure;
    // The next operation is secure if the destination is known and does not point to an unprotected core segment
    dest = (size_t) resolve(context.text, context.ctx);
    secure = dest && dest >= process.heap && (dest^(size_t) context.page) > INT16_MAX && (dest^(size_t) context.spring) > INT16_MAX;
    // Only write-protect if next operation behavior unknown, otherwise leave open saves 3 syscalls
    if (!secure && process_close() < 0) return -1;
  }

  return 0;
}
int enter(void *data, ucontext_t *ctx) {
  debug("Enter");
  
  uint8_t *spring, *text;
  struct page *page;

  spring = getspring(data);
  page = getpage(data);
  text = branch_resolve(spring);
  if (!text) error("No spring instruction found");

  process_open(NULL);
  context.text = NULL;
  context.data = data;
  context.page = page;
  context.spring = spring;

  ctx_set_tf(ctx);
  ctx_set_rip(ctx, text);
  return step(text, ctx);
}


int process_exec(void *data, ucontext_t *ctx) {
  debug("Exec");
  
  if (process_seal(data) < 0) return -1;

  return enter(data, ctx);
}
int process_write(void *data, ucontext_t *ctx) {
  debug("Write");
  
  if (process_release(data) < 0) return -1;
  debug_ctx(ctx);

  return 0;
}
int process_breakpoint(uint8_t *text, ucontext_t *ctx) {
  debug("Breakpoint");
  
  error("Unimplemented");
  uint8_t *spring, *data;
  struct page *page;

  // Breakpoints are always induced by a CALL
  asm("pop %0" : "=r" (spring)); // Get return address from the stack pointer
  // Get context before (on 4-byte spring boundary)
  spring -= 2;
  spring -= (size_t) spring%(1<<PROCESS_SCALE);
  return enter(getdata(spring), ctx);
}

void process_raise(int sig) {
  debug("Raise");

  struct sigaction ract, sact;

  // TODO: implement trigger signal handler installed by application (custom sys_sigaction)

  // Restore default signal action
  memset(&sact, 0, sizeof(struct sigaction));
  sact.sa_sigaction = SIG_DFL;
  sigaction(SIGTRAP, &sact, &ract);
  // Raise signal
  raise(sig);
  // Restore program signal action (if signal handler returns)
  sigaction(sig, &ract, NULL);
}

void process_trap(int signum, siginfo_t *info, ucontext_t *ctx) {
  debug("Trap");
  debug_ctx(ctx);

  uint8_t *rip = (uint8_t *) ctx->uc_mcontext.gregs[REG_RIP];
  int trapno = ctx->uc_mcontext.gregs[REG_TRAPNO];

  //if (trapno != 1) process_breakpoint(rip); else
  if (trapno == 1 && step(rip, ctx) >= 0) return;

  process_raise(SIGSEGV);
}
void process_segv(int signum, siginfo_t *info, ucontext_t *ctx) {
  debug("Segv");
  debug_ctx(ctx);
  
  void *dest = info->si_addr;
  void *rip = (void *) ctx->uc_mcontext.gregs[REG_RIP];
  unsigned long err = ctx->uc_mcontext.gregs[REG_ERR];

  // See enum x86_pf_error_code
  if (err&16) {
    if (process_exec(dest, ctx) >= 0) return;
  } else if (err&2) {
    if (process_write(dest, ctx) >= 0) return;
  }

  process_raise(SIGSEGV);
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
  p.base >>= 2*(PROCESS_SCALE+PROCESS_SPACE); // Minimum address whose scaled spring or pages won't intersect with data segments with address space

  // End of the data segment is provided by POSIX
  p.heap = (size_t) &end;
  p.data = p.heap-(p.heap-1)%p.pagesize-1+p.pagesize;
  p.text = (size_t) &etext;
  p.text -= (p.text-1)%p.pagesize+1+p.pagesize;

  if (p.data < p.text) return NULL;

  // Find beginning of the data segment
  while (p.data-p.pagesize >= (size_t) &etext && mprotect((void *) p.data-p.pagesize, p.pagesize, PROT_READ|PROT_WRITE) >= 0) p.data -= p.pagesize;

  if (p.heap < p.data) return NULL;

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

#endif
