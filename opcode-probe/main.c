#include "../gdb_stub/dbg.h"
#include "../prosper0gdb/offsets.h"
#include "../prosper0gdb/r0gdb.h"
#include "symbols.h"
#include "loging.h"
#include "probe/probe.h"
#include "probe/instr_db.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PC_IP "192.168.0.20"
#define PC_LOG_PORT 5655
#define PC_DUMP_PORT 5656

extern uint64_t kdata_base;
static uint64_t kdata_base_phys;
static uint64_t kdata_base_dmap;

const uint64_t skip_offset_list[] = {0x0};

int record_ktext_instr(uint64_t addr, struct instr_entry* test_entry) {
    uint64_t offset = kdata_base - addr;
    for (uint64_t i = 0; i < sizeof(skip_offset_list) / sizeof(skip_offset_list[0]); ++i) {
        if (offset == skip_offset_list[i]) {
            printf("skipped %zx\n", offset);
            return -1;
        }
    }
    uint64_t dmap_addr = kdata_base_dmap - offset;
    get_instruction_signature(dmap_addr, test_entry);
    return 0;
}

#define WINDOW 0x200

void scan_offset(uint64_t offset_addr, struct instr_entry** instrs_it) {
    for (uint64_t addr = offset_addr - WINDOW; addr <= offset_addr + WINDOW; ++addr) {
        record_ktext_instr(addr, *instrs_it);
        ++(*instrs_it);
    }
}

#define INSTR_SIZE (WINDOW * 2 * 128)

int instrs_send(const char* ipaddr, int port, struct instr_entry* instrs, size_t sz);

void scan_offsets() {
    struct instr_entry* instrs = malloc(sizeof(struct instr_entry) * INSTR_SIZE);
    struct instr_entry* instrs_it = instrs;
#define OFFSET(x) \
    printf(#x "\n"); \
    scan_offset(offsets.x, &instrs_it)

    OFFSET(sigaction_fix_start);
    OFFSET(sigaction_fix_end);
    OFFSET(sceSblServiceMailbox);
    OFFSET(sceSblAuthMgrSmIsLoadable2);
    OFFSET(mdbg_call_fix);
    OFFSET(syscall_before);
    OFFSET(syscall_after);
    OFFSET(malloc);
    OFFSET(loadSelfSegment_epilogue);
    OFFSET(loadSelfSegment_watchpoint);
    OFFSET(loadSelfSegment_watchpoint_lr);
    OFFSET(decryptSelfBlock_watchpoint);
    OFFSET(decryptSelfBlock_watchpoint_lr);
    OFFSET(decryptSelfBlock_epilogue);
    OFFSET(decryptMultipleSelfBlocks_watchpoint_lr);
    OFFSET(decryptMultipleSelfBlocks_epilogue);
    OFFSET(sceSblServiceMailbox_lr_verifyHeader);
    OFFSET(sceSblServiceMailbox_lr_loadSelfSegment);
    OFFSET(sceSblServiceMailbox_lr_decryptSelfBlock);
    OFFSET(sceSblServiceMailbox_lr_decryptMultipleSelfBlocks);
    OFFSET(sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize);
    OFFSET(sceSblServiceMailbox_lr_verifySuperBlock);
    OFFSET(sceSblServiceMailbox_lr_sceSblPfsClearKey_1);
    OFFSET(sceSblServiceMailbox_lr_sceSblPfsClearKey_2);
    OFFSET(sceSblPfsSetKeys);
    OFFSET(panic);
    OFFSET(sceSblServiceCryptAsync);
    OFFSET(sceSblServiceCryptAsync_deref_singleton);
    OFFSET(copyin);
    OFFSET(copyout);
    OFFSET(crypt_message_resolve);
#undef OFFSET
    instrs_send(PC_IP, PC_DUMP_PORT, instrs, instrs_it - instrs);
}

int instrs_send(const char* ipaddr, int port, struct instr_entry* instrs, size_t len)
{
    int sock = r0gdb_open_socket(ipaddr, port);
    if(sock < 0)
        return -1;
    char* p = (char*)instrs;
    size_t sz = len * sizeof(instrs[0]);
    while(sz)
    {
        ssize_t chk = write(sock, p, sz);
        if(chk <= 0)
        {
            close(sock);
            return -1;
        }
        p += chk;
        sz -= chk;
    }
    close(sock);
    return 0;
}

struct flat_pmap {
  uint64_t mtx_name_ptr;
  uint64_t mtx_flags;
  uint64_t mtx_data;
  uint64_t mtx_lock;
  uint64_t pm_pml4;
  uint64_t pm_cr3;
};

void read_kernel_pmap_store(struct flat_pmap* kernel_pmap_store) {
    uint64_t pmap_offset = offsets.kernel_pmap_store;
    printf("[+] kernel_pmap_store offset 0x%zx\n", pmap_offset);

    copyout(kernel_pmap_store, pmap_offset, sizeof(struct flat_pmap));
}

void init_mapping(uint64_t dmap_base, uint64_t cr3);

const uint64_t r0gdb_ints[] = {1, 6, 9, 179};

char orig_gate[sizeof(r0gdb_ints) / sizeof(r0gdb_ints[0])][16];

void save_orig_idt() {
    uint64_t intr = 0;
    for (uint64_t i = 0; i < sizeof(r0gdb_ints) / sizeof(r0gdb_ints[0]); ++i) {
        intr = r0gdb_ints[i];
        copyout(orig_gate[i], offsets.idt+(intr)*16, 16);
    }
}

void restore_orig_idt() {
    uint64_t intr = 0;
    for (uint64_t i = 0; i < sizeof(r0gdb_ints) / sizeof(r0gdb_ints[0]); ++i) {
        intr = r0gdb_ints[i];
        printf("restore int%zx\n", i);
        copyin(offsets.idt+(intr)*16, orig_gate[i], 16);
    }
}

const uint64_t protected_ints[] = {0x44, 0x45, 0x92};

void protect_ints() {
    char gate[16] = {0};
    uint64_t intr = 0;
    for (uint64_t i = 0; i < sizeof(protected_ints) / sizeof(protected_ints[0]); ++i) {
        intr = protected_ints[i];
        copyout(gate, offsets.idt+(intr)*16, 16);
        gate[5] = 0x8e;
        copyin(offsets.idt+(intr)*16, gate, 16);
    }
}

#define PAGE_SIZE 16384ull
extern char _start[];
extern char _end[];

int mprotect_rwx()
{
    unsigned long long start = (unsigned long long)_start;
    unsigned long long end = (unsigned long long)_end;
    start &= ~(PAGE_SIZE-1);
    end = ((end - 1) | (PAGE_SIZE-1)) + 1;
    return mprotect20((void*)start, end-start, PROT_READ|PROT_WRITE|PROT_EXEC);
}

int try_alloc_fixed_mem() {
    // mem_after_hit =
    //     mmap(MEM_FOR_HIT_ADDR, MEM_FOR_HIT, PROT_READ | PROT_WRITE,
    //            MAP_FIXED | MAP_SHARED | MAP_ANON, -1, 0);
    int ret = munmap(MEM_FOR_HIT_ADDR, MEM_FOR_HIT);
    printf("munmap returned %d\n", ret);
    mem_after_hit = mmap(MEM_FOR_HIT_ADDR, MEM_FOR_HIT, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    printf("mem_after_hit = %p\n", mem_after_hit);
    if ((size_t)mem_after_hit == (size_t)-1) {
        return -1;
    }
    return 0;
}

int dealloc_fixed_mem() {
    if (mem_after_hit && ((size_t)mem_after_hit != (size_t)-1)) {
        munmap(mem_after_hit, MEM_FOR_HIT);
    }
    return 0;
}

int main(void* ds, int a, int b, uintptr_t c, uintptr_t d)
{
    symbols_init();
    int ret = loging_init(PC_IP, PC_LOG_PORT);
    if (ret != 0) {
       return ret;
    }
    r0gdb_init(ds, a, b, c, d);
    //dbg_enter();

    kdata_base_phys = ~0xffffffffc0000000ULL & kdata_base;  // sometimes wrong?
    kdata_base_dmap = kdata_base_phys + 0xffff800000000000;
    printf("kdata_base = %zx, kdata_base_phys = %zx, kdata_base_dmap = %zx\n", kdata_base, kdata_base_phys, kdata_base_dmap);

    ret = try_alloc_fixed_mem();
    printf("alloc_fixed_mem returned %d\n", ret);

    struct flat_pmap kernel_pmap_store;
    read_kernel_pmap_store(&kernel_pmap_store);

    //uint64_t dmap_base = 0xffff800000000000;
    uint64_t dmap_base = kernel_pmap_store.pm_pml4 - kernel_pmap_store.pm_cr3;

    // Print pmap info
    printf(
        "[+] pm_pml4 0x%p, pm_cr3 0x%p, "
        "dmap_base 0x%p\n",
        kernel_pmap_store.pm_pml4, kernel_pmap_store.pm_cr3, dmap_base);

    printf("save_orig_idt\n", main);
    save_orig_idt();
    printf("r0gdb_trace(0)\n", main);
    r0gdb_trace(0);

    ret = mprotect_rwx();
    printf("mprotect_rwx returned %d\n", ret);

    uint64_t cr3 = r0gdb_read_cr3();
    printf("CR3 = %zx\n", cr3);
    init_mapping(dmap_base, cr3);

    // after that, r0gdb functions are unusable
    printf("disable trap flag in MSR 0xc0000084\n");
    r0gdb_wrmsr(0xc0000084, r0gdb_rdmsr(0xc0000084) | 0x100);
    printf("restore_orig_tss_idt\n");
    restore_orig_idt();
    printf("protect_ints\n");
    protect_ints();
    printf("r0gdb is disabled\n");


    printf("initialising probe\n");
    init_probe();
    printf("scanning offsets\n");
    scan_offsets();

    dealloc_fixed_mem();
    printf("all done\n");
    return 0; //p r0gdb() for magic
}

#define PML4_ADDR_MASK 0xffffffffff800ULL

void init_mapping(uint64_t dmap_base, uint64_t cr3) {
    uint64_t pml4[512];
    copyout(pml4, dmap_base + cr3, 0x1000);

    for (int i = 0; i < 512; ++i) {
        if (pml4[i] != 0) {
            printf("pml4[%x] = %zx\n", i, pml4[i]);
        }
    }

    uint64_t dmap_page_idx = (dmap_base >> 39) & ((1ULL << 9) - 1);
    printf("dmap_page_idx %zx\n", dmap_page_idx);

    uint64_t dmap_page_addr = pml4[dmap_page_idx] & PML4_ADDR_MASK;
    printf("dmap_page_addr %zx\n", dmap_page_addr);

    uint64_t pml3[512];
    copyout(pml3, dmap_base + dmap_page_addr, 0x1000);

    if (pml4[0x100] & 1) {
        printf("mapping is already initialized\n");
        return;
    }
    
    // for kernel
    // pml4[0x100] = dmap_page_addr | (1ULL << 0) | (1ULL << 1) | (1ULL << 52) | (1ULL << 53) | (1ULL << 54) | (1ULL << 55);
    // pml3[0x000] = (1ULL << 0) | (1ULL << 1) | (1ULL << 7) | (1ULL << 63);

    // for user
    pml4[0x100] = dmap_page_addr | (1ULL << 0) | (1ULL << 1) | (1ULL << 2) | (1ULL << 52) | (1ULL << 53) | (1ULL << 54) | (1ULL << 55);
    // pml3[0x000] = (1ULL << 0) | (1ULL << 2) | (1ULL << 7) | (1ULL << 10);  // rx
    pml3[0x000] = (1ULL << 0) | (1ULL << 2) | (1ULL << 7) | (1ULL << 10) | (1ULL << 58);  // x
    // pml3[0x000] = (1ULL << 0) | (1ULL << 1) | (1ULL << 2) | (1ULL << 7) | (1ULL << 10) | (1ULL << 63);  // rw
    for (size_t i = 1; i < 64; ++i) {
        pml3[i] = (i << 30) | pml3[0x000];
    }

    // say no to cache
    for (size_t i = 0; i < 100; ++i) {
        copyin(dmap_base + dmap_page_addr, pml3, 0x1000);
        copyin(dmap_base + cr3, pml4, 0x1000);
    }

    printf("updating cr3\n");
    r0gdb_write_cr3(cr3);
    uint64_t cr32 = r0gdb_read_cr3();
    printf("CR3 = %zx\n", cr32);
}
