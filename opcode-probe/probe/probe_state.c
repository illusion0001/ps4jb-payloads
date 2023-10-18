#define _GNU_SOURCE
#include "probe_state.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ucontext.h>
#include <signal.h>

void save_state(struct probe_state* probe_state, int signum, void* idc, void* o_uc) {
    siginfo_t* si = (siginfo_t*)idc;
    ucontext_t* uc = (ucontext_t*)o_uc;
    mcontext_t* mc = (mcontext_t*)(((char*)&uc->uc_mcontext)+48); // wtf??

    probe_state->trap_signal = signum;
    if (signum == SIGILL || signum == SIGFPE || signum == SIGSEGV || signum == SIGBUS) {
        probe_state->fault_addr = (uint64_t)si->si_addr;
    } else {
        probe_state->fault_addr = 0;
    }

    probe_state->regs.rax = mc->mc_rax;
    probe_state->regs.rbx = mc->mc_rbx;
    probe_state->regs.rcx = mc->mc_rcx;
    probe_state->regs.rdx = mc->mc_rdx;
    probe_state->regs.rsi = mc->mc_rsi;
    probe_state->regs.rdi = mc->mc_rdi;
    probe_state->regs.rbp = mc->mc_rbp;
    probe_state->regs.rsp = mc->mc_rsp;
    probe_state->regs.r8 = mc->mc_r8;
    probe_state->regs.r9 = mc->mc_r9;
    probe_state->regs.r10 = mc->mc_r10;
    probe_state->regs.r11 = mc->mc_r11;
    probe_state->regs.r12 = mc->mc_r12;
    probe_state->regs.r13 = mc->mc_r13;
    probe_state->regs.r14 = mc->mc_r14;
    probe_state->regs.r15 = mc->mc_r15;
    probe_state->regs.rip = mc->mc_rip;
    probe_state->regs.rflags = mc->mc_rflags;
}

void load_state(struct probe_state* probe_state, int signum, void* idc, void* o_uc) {
    ucontext_t* uc = (ucontext_t*)o_uc;
    mcontext_t* mc = (mcontext_t*)(((char*)&uc->uc_mcontext)+48); // wtf??
    mc->mc_rax = probe_state->regs.rax;
    mc->mc_rbx = probe_state->regs.rbx;
    mc->mc_rcx = probe_state->regs.rcx;
    mc->mc_rdx = probe_state->regs.rdx;
    mc->mc_rsi = probe_state->regs.rsi;
    mc->mc_rdi = probe_state->regs.rdi;
    mc->mc_rbp = probe_state->regs.rbp;
    mc->mc_rsp = probe_state->regs.rsp;
    mc->mc_r8 = probe_state->regs.r8;
    mc->mc_r9 = probe_state->regs.r9;
    mc->mc_r10 = probe_state->regs.r10;
    mc->mc_r11 = probe_state->regs.r11;
    mc->mc_r12 = probe_state->regs.r12;
    mc->mc_r13 = probe_state->regs.r13;
    mc->mc_r14 = probe_state->regs.r14;
    mc->mc_r15 = probe_state->regs.r15;
    mc->mc_rip = probe_state->regs.rip;
    mc->mc_rflags = probe_state->regs.rflags;
}
