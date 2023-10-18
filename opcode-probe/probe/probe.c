#include "probe.h"

#include "../gdb_stub/dbg.h"
#include "../symbols.h"
#include "../loging.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/ucontext.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <signal.h>
#include <string.h>
#include <machine/sysarch.h>

#include "probe_state.h"
#include "rng.h"

static uint64_t initial_rflags = 0;

enum TrapState {
    TRAP_AFTER_HIT = 0,
    TRAP_BEFORE_HIT,
    TRAP_PREPARE,
};

static uint64_t trap_target_rip = 0;
static int trap_status = 0;
int last_signum;
void* const MEM_FOR_HIT_ADDR = (void*)0x208e00000;
const size_t MEM_FOR_HIT = 0x3000;
const size_t RSP_MEM_FOR_HIT = 0x1000;
const size_t RBP_MEM_FOR_HIT = 0x2000;
void* mem_before_hit;
struct probe_state before_hit;
void* mem_after_hit;
struct probe_state after_hit;

int in_probe_signal_handler = 0;
static int ctx_buf_init = 0;
static jmp_buf ctx_buf;

static void recover() {
    __atomic_exchange_n(&in_probe_signal_handler, 0, __ATOMIC_RELEASE);
    if (ctx_buf_init) {
        longjmp_ptr(ctx_buf, 1);
    }
}

static uint64_t saved_fs;
static uint64_t saved_gs;

static void save_segments() {
    sysarch(AMD64_GET_FSBASE, &saved_fs);
    sysarch(AMD64_GET_GSBASE, &saved_gs);
}

static void restore_segments() {
    sysarch(AMD64_SET_FSBASE, &saved_fs);
    sysarch(AMD64_SET_GSBASE, &saved_gs);
}

static void signal_handler(int signum, siginfo_t* idc, void* o_uc)
{
    while(__atomic_exchange_n(&in_probe_signal_handler, 1, __ATOMIC_ACQUIRE));
    restore_segments();
    //printf("Hello, signal handler %d!\n", signum);
    ucontext_t* uc = (ucontext_t*)o_uc;
    mcontext_t* mc = (mcontext_t*)(((char*)&uc->uc_mcontext)+48); // wtf??
    uint64_t rip = mc->mc_rip;
    if (signum == SIGTRAP) {
        // continue single stepping
        mc->mc_rflags = SET_BIT(mc->mc_rflags, TRAP_FLAG_BIT);
    }
    last_signum = signum;
    if (trap_status == TRAP_PREPARE && rip == trap_target_rip) {
        trap_status = TRAP_BEFORE_HIT;
        load_state(&before_hit, signum, idc, o_uc);
    } else if (trap_status == TRAP_BEFORE_HIT) {
        trap_status = TRAP_AFTER_HIT;
    }
    if (signum == SIGTRAP) {
        if (trap_status == TRAP_AFTER_HIT) {
            save_state(&after_hit, signum, idc, o_uc);
            recover();
        }
    } else {
        save_state(&after_hit, signum, idc, o_uc);
        recover();
    }
    __atomic_exchange_n(&in_probe_signal_handler, 0, __ATOMIC_RELEASE);
}

static void set_trap_flag(void) {
    uint64_t q;
    asm volatile("pop %0\npushfq\norb $1, 1(%%rsp)\npopfq\npush %0":"=r"(q));
}

static uint64_t get_rflags(void) {
    uint64_t q;
    asm volatile("pushfq\nmov (%%rsp), %0\npopfq":"=r"(q));
    return q;
}

static void set_rflags(uint64_t val) {
    asm volatile("pushfq\nmov %0, (%%rsp)\npopfq"::"r"(val));
}

static void init_global() {
    trap_status = TRAP_AFTER_HIT;
    trap_target_rip = 0;
    in_probe_signal_handler = 0;
    ctx_buf_init = 0;
}

static void init_signals() {
    save_segments();
    printf("fs: %zx\n", saved_fs);
    printf("gs: %zx\n", saved_gs);
    stack_t alt_stack = {
        .ss_sp = malloc(SIGSTKSZ),
        .ss_flags = 0,
        .ss_size = SIGSTKSZ,
    };
    // printf("ss_sp: %zx\n", (size_t)alt_stack.ss_sp);
    // printf("ss_flags: %d\n", alt_stack.ss_flags);
    // printf("ss_size: %zx\n", alt_stack.ss_size);
    stack_t old_alt_stack;
    sigaltstack(&alt_stack, &old_alt_stack);
    // printf("old ss_sp: %zx\n", (size_t)old_alt_stack.ss_sp);
    // printf("old ss_flags: %d\n", old_alt_stack.ss_flags);
    // printf("old ss_size: %zx\n", old_alt_stack.ss_size);
    struct sigaction siga = {
        .sa_sigaction = signal_handler,
        .sa_flags = SA_SIGINFO | SA_ONSTACK
    };
    int a = sigaction(SIGTRAP, &siga, NULL);
    int b = sigaction(SIGILL, &siga, NULL);
    int c = sigaction(SIGBUS, &siga, NULL);
    int d = sigaction(SIGINT, &siga, NULL);
    int e = sigaction(SIGSYS, &siga, NULL);
    int f = sigaction(SIGSEGV, &siga, NULL);
    int g = sigaction(SIGFPE, &siga, NULL);
}

static void init_regs() {
    init_rng(0x1337133713371337);
    mem_before_hit = malloc(MEM_FOR_HIT);
    if (mem_after_hit == NULL) {
        mem_after_hit = malloc(MEM_FOR_HIT);
    }
    printf("mem_after_hit: %p\n", mem_after_hit);
    memset(mem_before_hit, 0, MEM_FOR_HIT);
    for (size_t i = 0; i < MEM_FOR_HIT; ++i) {
        ((uint8_t*)mem_before_hit)[i] = random_uint8_t();
    }

    before_hit.trap_signal = 0;  // not used
    before_hit.fault_addr = 0;  // not used

    before_hit.regs.rax = 0x00000457de1b1ca5;
    before_hit.regs.rbx = 0x000007ed466f1c82;
    before_hit.regs.rcx = 0x00000d09b94be88c;
    before_hit.regs.rdx = 0x00000a338a685c74;
    before_hit.regs.rsi = 0x00000cb40e681ed1;
    before_hit.regs.rdi = 0x000002cd7b424603;
    before_hit.regs.rbp = 0;  // filled later
    before_hit.regs.rsp = 0;  // filled later
    before_hit.regs.r8  = 0x00000d4b7c7855ea;
    before_hit.regs.r9  = 0x00000e5f3152f503;
    before_hit.regs.r10 = 0x000003effc295c5c;
    before_hit.regs.r11 = 0x000006cfe47584c7;
    before_hit.regs.r12 = 0x00000b5981305576;
    before_hit.regs.r13 = 0x000005e26da84296;
    before_hit.regs.r14 = 0x00000196f57934e8;
    before_hit.regs.r15 = 0x00000eacf0ccc73a;

    before_hit.regs.rip = 0;  // filled later

    before_hit.regs.rflags = initial_rflags;
    before_hit.regs.rflags = SET_BIT(before_hit.regs.rflags, TRAP_FLAG_BIT);
    before_hit.regs.rflags = UNSET_BIT(before_hit.regs.rflags, CARRY_FLAG_BIT);
    before_hit.regs.rflags = UNSET_BIT(before_hit.regs.rflags, PARITY_FLAG_BIT);
    before_hit.regs.rflags = UNSET_BIT(before_hit.regs.rflags, AUX_FLAG_BIT);
    before_hit.regs.rflags = UNSET_BIT(before_hit.regs.rflags, ZERO_FLAG_BIT);
    before_hit.regs.rflags = UNSET_BIT(before_hit.regs.rflags, SIGN_FLAG_BIT);
    before_hit.regs.rflags = UNSET_BIT(before_hit.regs.rflags, OVERFLOW_FLAG_BIT);
    printf("before_hit.regs.rflags: %zx\n", before_hit.regs.rflags);
}

static void prepare_regs(uint64_t rip) {
    memcpy(mem_after_hit, mem_before_hit, MEM_FOR_HIT);
    before_hit.regs.rsp = (uint64_t)(mem_after_hit + RSP_MEM_FOR_HIT);
    before_hit.regs.rbp = (uint64_t)(mem_after_hit + RBP_MEM_FOR_HIT);
    //uint64_t rsp_value = (uint64_t)(mem_after_hit + 0x10000) & ~((uint64_t)0xFFFF) | (1ULL << TRAP_FLAG_BIT);
    uint64_t rsp_value = before_hit.regs.rflags;
    //printf("mem_after_hit: %zx\n", (uint64_t)mem_after_hit);
    //printf("rsp_value: %zx\n", rsp_value);
    *(uint64_t*)(mem_after_hit + RSP_MEM_FOR_HIT) = rsp_value;
    before_hit.regs.rip = rip;
}

static void unblock_signals(void)
{
    sigset_t ss = {0};
	ss.__bits[_SIG_WORD(SIGTRAP)] |= _SIG_BIT(SIGTRAP);
	ss.__bits[_SIG_WORD(SIGILL)] |= _SIG_BIT(SIGILL);
	ss.__bits[_SIG_WORD(SIGBUS)] |= _SIG_BIT(SIGBUS);
	ss.__bits[_SIG_WORD(SIGINT)] |= _SIG_BIT(SIGINT);
	ss.__bits[_SIG_WORD(SIGSYS)] |= _SIG_BIT(SIGSYS);
	ss.__bits[_SIG_WORD(SIGSEGV)] |= _SIG_BIT(SIGSEGV);
	ss.__bits[_SIG_WORD(SIGFPE)] |= _SIG_BIT(SIGFPE);
    sigprocmask(SIG_UNBLOCK, &ss, NULL);
}

void run_instruction(uint64_t addr) {
    ctx_buf_init = 1;

    trap_target_rip = addr;
    trap_status = TRAP_PREPARE;
    prepare_regs(addr);
    set_rflags(initial_rflags);
    // uint64_t new_flags = get_rflags();
    // if (get_rflags() != initial_rflags) {
    //     printf("new_flags: %zx\n", new_flags);
    //     exit(1);
    // }
    sigset_t saved_signal_set;
    sigprocmask(SIG_SETMASK, NULL, &saved_signal_set);
    unblock_signals();
    if (!setjmp_ptr(ctx_buf)) {
label1:
        set_trap_flag();
        __asm__("jmp *%0" :: "r"(addr));
    }
    ctx_buf_init = 0;
    sigprocmask(SIG_SETMASK, &saved_signal_set, NULL);
    // printf("Recorded signal: %d\n", (int)after_hit.trap_signal);
    // printf("Recorded signal fault_addr: %zx\n", (int)after_hit.fault_addr);
    // printf("Recorded rsp: %zx\n", after_hit.regs.rsp);
    // printf("Recorded rip: %zx\n", after_hit.regs.rip);
    // //printf("label1 rip: %zx\n", &&label1);
    // //printf("Recorded rip instr: %zd\n", *(uint64_t*)(after_hit.regs.rip));
    // printf("Recorded delta rip: %zd\n", after_hit.regs.rip - before_hit.regs.rip);
    // printf("Recorded rflags: %zx\n", after_hit.regs.rflags);
}

static int test_var = 0;

static void test() {
    test_var = 1;
}

void init_probe() {
    printf("starting init probe\n");
    initial_rflags = get_rflags();
    printf("initial_rflags: %zx\n", initial_rflags);
    init_global();
    init_regs();
    init_signals();
    printf("running test instruction\n");
    run_instruction((uint64_t)test + 0x14);
    printf("done init probe\n");
}