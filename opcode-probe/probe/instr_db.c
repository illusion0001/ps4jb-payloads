#include "instr_db.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <unistd.h>

#include "hash.h"
#include "probe.h"

#include "../symbols.h"
#include "../loging.h"

#define NUM_INSTR 0x100
static struct instr_entry* instr_db;
static struct hshtbl_node* abs_sig_hshtbl;
static struct hshtbl_node* abs_sig_hshtbl_end;
static struct hshtbl_node* delta_rip_sig_hshtbl;
static struct hshtbl_node* delta_rip_sig_hshtbl_end;


int is_equal(struct instr_entry* lhs, struct instr_entry* rhs) {
    if (memcmp(&lhs->abs_sig, &rhs->abs_sig, sizeof(struct signature)) == 0) {
        return 1;
    }
    if (memcmp(&lhs->delta_rip_sig, &rhs->delta_rip_sig, sizeof(struct signature)) == 0) {
        return 1;
    }
    return 0;
}

#define JIT_BUF_SIZE 0x20000
#define INSTR_POS 0x10000
#define TEST_INSTR_POS 0x18000
#define MAPPING_ADDR 0x936100000
#define SHADOW_ADDR 0x930100000
static int jit_buf_x_fd;
static int jit_buf_rw_fd;
static uint8_t* jit_buf_x;
static uint8_t* jit_buf_rw;

void get_instruction_signature(uint64_t addr, struct instr_entry* instr) {
    run_instruction(addr);
    instr->abs_sig.trap_signal = after_hit.trap_signal;
    instr->abs_sig.fault_addr = after_hit.fault_addr;
    instr->abs_sig.mem_after_hit_hsh = memhash(mem_after_hit, MEM_FOR_HIT);
    instr->abs_sig.rax = after_hit.regs.rax;
    instr->abs_sig.rbx = after_hit.regs.rbx;
    instr->abs_sig.rcx = after_hit.regs.rcx;
    instr->abs_sig.rdx = after_hit.regs.rdx;
    instr->abs_sig.rsi = after_hit.regs.rsi;
    instr->abs_sig.rdi = after_hit.regs.rdi;
    instr->abs_sig.rbp = after_hit.regs.rbp;
    instr->abs_sig.rsp = after_hit.regs.rsp;
    instr->abs_sig.r8 = after_hit.regs.r8;
    instr->abs_sig.r9 = after_hit.regs.r9;
    instr->abs_sig.r10 = after_hit.regs.r10;
    instr->abs_sig.r11 = after_hit.regs.r11;
    instr->abs_sig.r12 = after_hit.regs.r12;
    instr->abs_sig.r13 = after_hit.regs.r13;
    instr->abs_sig.r14 = after_hit.regs.r14;
    instr->abs_sig.r15 = after_hit.regs.r15;
    instr->abs_sig.rip = after_hit.regs.rip;
    instr->abs_sig.rflags = after_hit.regs.rflags;

    memcpy(&instr->delta_rip_sig, &instr->abs_sig, sizeof(struct signature));
    instr->delta_rip_sig.rip = after_hit.regs.rip - before_hit.regs.rip;
}

void print_signature(struct signature* sig) {
    printf("Signature:\n");
    printf("  sig->trap_signal: %d\n", (int)(sig->trap_signal));
    printf("  sig->fault_addr: %zx\n", sig->fault_addr);
    printf("  sig->mem_after_hit_hsh: %zx\n", sig->mem_after_hit_hsh);
    printf("  sig->rax: %zx\n", sig->rax);
    printf("  sig->rbx: %zx\n", sig->rbx);
    printf("  sig->rcx: %zx\n", sig->rcx);
    printf("  sig->rdx: %zx\n", sig->rdx);
    printf("  sig->rsi: %zx\n", sig->rsi);
    printf("  sig->rdi: %zx\n", sig->rdi);
    printf("  sig->rbp: %zx\n", sig->rbp);
    printf("  sig->rsp: %zx\n", sig->rsp);
    printf("  sig->r8: %zx\n", sig->r8);
    printf("  sig->r9: %zx\n", sig->r9);
    printf("  sig->r10: %zx\n", sig->r10);
    printf("  sig->r11: %zx\n", sig->r11);
    printf("  sig->r12: %zx\n", sig->r12);
    printf("  sig->r13: %zx\n", sig->r13);
    printf("  sig->r14: %zx\n", sig->r14);
    printf("  sig->r15: %zx\n", sig->r15);
    printf("  sig->rip: %zx\n", sig->rip);
    printf("  sig->rflags: %zx\n", sig->rflags);
}

void print_instr(size_t instr, size_t instr_size) {
    for (size_t i = 0; i < instr_size; ++i) {
        printf("%02zx", instr & 0xFF);
        instr >>= 8;
    }
}

void init_lookup() {
    abs_sig_hshtbl = malloc(sizeof(*abs_sig_hshtbl) * NUM_INSTR);
    abs_sig_hshtbl_end = abs_sig_hshtbl + NUM_INSTR;
    delta_rip_sig_hshtbl = malloc(sizeof(*delta_rip_sig_hshtbl) * NUM_INSTR);
    delta_rip_sig_hshtbl_end = delta_rip_sig_hshtbl + NUM_INSTR;
    for (size_t i = 0; i < NUM_INSTR; ++i) {
        abs_sig_hshtbl[i].hash = memhash(&instr_db[i].abs_sig, sizeof(instr_db[i].abs_sig));
        abs_sig_hshtbl[i].value = i;
        delta_rip_sig_hshtbl[i].hash = memhash(&instr_db[i].delta_rip_sig, sizeof(instr_db[i].delta_rip_sig));
        delta_rip_sig_hshtbl[i].value = i;
    }
    sort_hshtbl(abs_sig_hshtbl, NUM_INSTR);
    sort_hshtbl(delta_rip_sig_hshtbl, NUM_INSTR);
}

int64_t lookup_one_byte(uint64_t addr, struct instr_entry* test_entry) {
    int64_t result = -1;

    get_instruction_signature(addr, test_entry);
    size_t abs_sig_hash = memhash(&(test_entry->abs_sig), sizeof(test_entry->abs_sig));
    struct hshtbl_node* abs_sig_node = find_hshtbl(abs_sig_hshtbl, NUM_INSTR, abs_sig_hash);
    while (abs_sig_node != NULL && abs_sig_node != abs_sig_hshtbl_end && abs_sig_node->hash == abs_sig_hash) {
        size_t j = abs_sig_node->value;
        if (is_equal(test_entry, instr_db + j)) {
            if (result != -1) {
                // multiple candidates
                return -1;
            }
            result = j;
        }
        ++abs_sig_node;
    }
    size_t delta_rip_sig_hash = memhash(&(test_entry->delta_rip_sig), sizeof(test_entry->delta_rip_sig));
    struct hshtbl_node* delta_rip_sig_node = find_hshtbl(delta_rip_sig_hshtbl, NUM_INSTR, delta_rip_sig_hash);
    while (delta_rip_sig_node != NULL && delta_rip_sig_node != delta_rip_sig_hshtbl_end && delta_rip_sig_node->hash == delta_rip_sig_hash) {
        size_t j = delta_rip_sig_node->value;
        if (is_equal(test_entry, instr_db + j)) {
            if (result != -1) {
                // multiple candidates
                return -1;
            }
            result = j;
        }
        ++delta_rip_sig_node;
    }
    if (result != -1 && instr_db[result].good == 0) {
        printf("%zx: one candidate %zd, but not good", addr, result);
        return -1;
    }
    return result;
}

int init_instr_db() {
    printf("start init_instr_db\n");
    instr_db = malloc(sizeof(*instr_db) * NUM_INSTR);

    printf("creating jit\n");
    // jit_buf = mmap(0, JIT_BUF_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
    // memset(jit_buf, 0x90, JIT_BUF_SIZE);
    int ret = sceKernelJitCreateSharedMemory(0, JIT_BUF_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, &jit_buf_x_fd);
    printf("sceKernelJitCreateSharedMemory, ret %d, fd %d\n", ret, jit_buf_x_fd);
    if (jit_buf_x_fd == 0) {
        return -1;
    }
    ret = sceKernelJitCreateAliasOfSharedMemory(jit_buf_x_fd, PROT_READ|PROT_WRITE, &jit_buf_rw_fd);
    printf("sceKernelJitCreateAliasOfSharedMemory, ret %d, fd %d\n", ret, jit_buf_rw_fd);
    if (jit_buf_rw_fd == 0) {
        return -1;
    }
    jit_buf_x = mmap((void*)(MAPPING_ADDR), JIT_BUF_SIZE, PROT_EXEC, MAP_FIXED|MAP_SHARED, jit_buf_x_fd, 0);
    printf("mmap jit_buf_x, ret %p\n", jit_buf_x);
    if (jit_buf_x == 0) {
        return -1;
    }
    jit_buf_rw = mmap((void*)(SHADOW_ADDR), JIT_BUF_SIZE, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_SHARED, jit_buf_rw_fd, 0);
    printf("mmap jit_buf_rw, ret %p\n", jit_buf_rw);
    if (jit_buf_rw == 0) {
        return -1;
    }
    memset(jit_buf_rw, 0x90, JIT_BUF_SIZE);

    // jit_buf[INSTR_POS] = 0xe9;
    // jit_buf[INSTR_POS + 1] = 0xff;
    // jit_buf[INSTR_POS + 2] = 0xff;
    // jit_buf[INSTR_POS + 3] = 0xff;
    // struct instr_entry instr;
    // get_instruction_signature((uint64_t)(jit_buf) + INSTR_POS, &instr);
    // printf("Recorded signal: %d\n", (int)instr.abs_sig.trap_signal);
    // printf("Recorded rsp: %zx\n", instr.abs_sig.rsp);
    // printf("Recorded delta rip: %zd\n", instr.delta_rip_sig.rip);
    // printf("Recorded rflags: %zx\n", instr.abs_sig.rflags);
    // printf("Recorded fault_addr: %zx\n", instr.abs_sig.fault_addr);
    // print_signature(&instr.abs_sig);

    for (size_t i = 0x0; i <= 0xFF; ++i) {
        struct instr_entry* entry = instr_db + i;
        entry->instr = i;
        entry->instr_size = 1;
        entry->good = 0;

        jit_buf_rw[INSTR_POS] = i & 0xFF;
        printf("Instr: ");
        print_instr(entry->instr, entry->instr_size);
        printf("\n");
        // run_instruction((uint64_t)(jit_buf_x) + INSTR_POS);
        get_instruction_signature((uint64_t)(jit_buf_x) + INSTR_POS, entry);
        if (i == 0xc3) {
            printf("memhash: %zx\n", entry->abs_sig.mem_after_hit_hsh);
            print_signature(&entry->abs_sig);
        }
    }

    init_lookup();

    // Testing
    memset(jit_buf_rw, 0xFF, JIT_BUF_SIZE);
    struct instr_entry test_entry;

    size_t* candidates = malloc(1000 * sizeof(size_t));
    size_t good = 0;
    size_t valid = 0;
    for (size_t i = 0; i < NUM_INSTR; ++i) {
        jit_buf_rw[TEST_INSTR_POS] = i & 0xFF;

        get_instruction_signature((uint64_t)(jit_buf_x) + TEST_INSTR_POS, &test_entry);
        if (test_entry.abs_sig.trap_signal != SIGILL) {
            ++valid;
        }
        size_t limit_candidates = 1000;
        size_t count_candidates = 0;
        size_t abs_sig_hash = memhash(&test_entry.abs_sig, sizeof(test_entry.abs_sig));
        struct hshtbl_node* abs_sig_node = find_hshtbl(abs_sig_hshtbl, NUM_INSTR, abs_sig_hash);
        while (abs_sig_node != NULL && abs_sig_node != abs_sig_hshtbl_end && abs_sig_node->hash == abs_sig_hash) {
            size_t j = abs_sig_node->value;
            if (is_equal(&test_entry, instr_db + j)) {
                candidates[count_candidates] = j;
                ++count_candidates;
                --limit_candidates;
            }
            ++abs_sig_node;
        }
        size_t delta_rip_sig_hash = memhash(&test_entry.delta_rip_sig, sizeof(test_entry.delta_rip_sig));
        struct hshtbl_node* delta_rip_sig_node = find_hshtbl(delta_rip_sig_hshtbl, NUM_INSTR, delta_rip_sig_hash);
        while (delta_rip_sig_node != NULL && delta_rip_sig_node != delta_rip_sig_hshtbl_end && delta_rip_sig_node->hash == delta_rip_sig_hash) {
            size_t j = delta_rip_sig_node->value;
            if (is_equal(&test_entry, instr_db + j)) {
                candidates[count_candidates] = j;
                ++count_candidates;
                --limit_candidates;
            }
            ++delta_rip_sig_node;
        }
        if (count_candidates == 1 && candidates[0] == i) {
        //if (count_candidates >= 1) {
            ++good;
            instr_db[i].good = 1;
            printf("Test instr: ");
            print_instr(i, 1);
            printf("\n");
            printf("Candidates: ");
            for (size_t k = 0; k < count_candidates; ++k) {
                print_instr(instr_db[candidates[k]].instr, instr_db[candidates[k]].instr_size);
                printf(", ");
            }
            printf("\n");
        }
    }
    printf("%zu good out of %zu (valid %zu)\n", good, (uint64_t)NUM_INSTR, valid);
    return 0;
}

void free_instr_db() {
    if (abs_sig_hshtbl != 0) {
        free(abs_sig_hshtbl);
        abs_sig_hshtbl = 0;
    }
    if (delta_rip_sig_hshtbl != 0) {
        free(delta_rip_sig_hshtbl);
        delta_rip_sig_hshtbl = 0;
    }
    // if (jit_buf_rw != 0) {
    //     munmap(jit_buf_rw, JIT_BUF_SIZE);
    //     jit_buf_rw = 0;
    // }
    // if (jit_buf_x != 0) {
    //     munmap(jit_buf_x, JIT_BUF_SIZE);
    //     jit_buf_x = 0;
    // }
    // if (jit_buf_rw_fd != 0) {
    //     close(jit_buf_rw_fd);
    //     jit_buf_rw_fd = 0;
    // }
    // if (jit_buf_x_fd != 0) {
    //     close(jit_buf_x_fd);
    //     jit_buf_x_fd = 0;
    // }
}