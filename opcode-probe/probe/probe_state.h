#pragma once

#include <stdint.h>

struct probe_regs
{
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t rflags;
};

struct probe_state {
    int trap_signal;
    uint64_t fault_addr;
    struct probe_regs regs;
};

void save_state(struct probe_state* probe_state, int signum, void* idc, void* o_uc);
void load_state(struct probe_state* probe_state, int signum, void* idc, void* o_uc);
