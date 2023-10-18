#pragma once
#include <stddef.h>
#include <stdint.h>

#include "probe_state.h"

#define UNSET_BIT(x, n) ((uint64_t)(x) & (~((uint64_t)(1) << (n))))
#define SET_BIT(x, n) ((uint64_t)(x) | ((uint64_t)(1) << (n)))
#define CARRY_FLAG_BIT 0
#define PARITY_FLAG_BIT 2
#define AUX_FLAG_BIT 4
#define ZERO_FLAG_BIT 6
#define SIGN_FLAG_BIT 7
#define TRAP_FLAG_BIT 8
#define OVERFLOW_FLAG_BIT 11

extern int last_signum;
extern void* const MEM_FOR_HIT_ADDR;
extern const size_t MEM_FOR_HIT;
extern void* mem_before_hit;
extern struct probe_state before_hit;
extern void* mem_after_hit;
extern struct probe_state after_hit;

void run_instruction(uint64_t addr);
void init_probe();