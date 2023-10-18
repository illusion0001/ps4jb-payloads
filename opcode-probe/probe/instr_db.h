#pragma once

#include <stddef.h>
#include <stdint.h>

struct signature {
    uint64_t trap_signal;
    uint64_t fault_addr;
    uint64_t mem_after_hit_hsh;
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

struct instr_entry {
    struct signature abs_sig;
    struct signature delta_rip_sig;
    size_t instr;
    size_t instr_size;
    size_t good;
};

int init_instr_db();
void free_instr_db();

void print_instr(size_t instr, size_t instr_size);
void print_signature(struct signature* sig);
void get_instruction_signature(uint64_t addr, struct instr_entry* instr);
int64_t lookup_one_byte(uint64_t addr, struct instr_entry* test_entry);