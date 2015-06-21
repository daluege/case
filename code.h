#ifndef case_code_h
#define case_code_h

#include "op.h"

// TODO: system specific
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

static inline void set_tf() {
  asm("pushfq; orl $0x100, (%rsp); popfq");
}
static inline void unset_tf() {
  asm("pushfq; xorl $0x100, (%rsp); popfq");
}

int branch_link(void *addr, void *dest, int limit) {
  uint8_t *text = addr;
  int32_t rel = (size_t) dest-(size_t) addr;
  // Sum asserts that 16 bits are not exceeded
  if (addr+rel != dest || (unsigned int) limit < 5) error("Not implemented");
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
    case 0xEB: return addr+2+(int8_t) *text;
    case 0xE9: case 0xE8: return addr+5+*(int32_t *) text;
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

void *resolve(void *addr, ucontext_t *ctx) {
  // TODO: resolve at runtime by LEA if ctx == NULL
  
  size_t result = 0;
  uint8_t *data = addr, s, d, reg, mod, rm, scale, index, base;
  int flags;

  flags = opflags(data);
  if (flags&OP_REGULAR == 0) return branch_resolve(addr); // Not regular, try to resolve branch
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

#endif
