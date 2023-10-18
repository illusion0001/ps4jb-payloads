#include "symbols.h"

#include <setjmp.h>
#include <stdio.h>

#include <sys/mman.h>

int (*_printf)(const char *__restrict __format, ...);
int (*_sprintf)(char *__restrict __s, const char *__restrict __format, ...);
int (*_vprintf)(const char *__restrict __format, __gnuc_va_list __arg);
int (*_vsprintf)(char *__restrict __s, const char *__restrict __format,
                 __gnuc_va_list __arg);

int (*_fprintf)(FILE *__restrict __stream, const char *__restrict __format,
                ...);
int (*_vfprintf)(FILE *__restrict __s, const char *__restrict __format,
                 __gnuc_va_list __arg);

FILE *(*_fdopen)(int __fd, const char *__modes);
int (*_fflush)(FILE *);

int (*_socket)(int __domain, int __type, int __protocol);
int (*_inet_pton)(int, const char * __restrict, void * __restrict);
uint16_t (*_htons)(uint16_t __hostshort);
int (*_connect)(int __fd, const struct sockaddr* __addr, socklen_t __len);

int	(*setjmp_ptr)(jmp_buf);
void (*longjmp_ptr)(jmp_buf env, int val);

void *(*malloc_ptr)(size_t size);
void (*free_ptr)(void *);

void *(*memset_ptr)(void *__s, int __c, size_t __n);
void *(*memcpy_ptr)(void *__restrict __dest, const void *__restrict __src, size_t __n);
int (*memcmp_ptr)(const void *__s1, const void *__s2, size_t __n);

void (*qsort_ptr)(void *, size_t, size_t, int (*)(const void *, const void *));
void *(*bsearch_ptr)(const void *, const void *, size_t, size_t, int (*)(const void *, const void *));

int (*sceKernelJitCreateSharedMemory)(int flags, size_t size, int protection, int *destinationHandle);
int (*sceKernelJitCreateAliasOfSharedMemory)(int handle, int protection, int *destinationHandle);
int (*sceKernelJitMapSharedMemory)(int handle, int protection, void **destination);

void* dlsym(void*, const char*);

void *malloc(size_t size) {
    //return mmap(0, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
    return malloc_ptr(size);
}

void free(void *ptr) {
    free_ptr(ptr);
}

void *memset(void *__s, int __c, size_t __n) {
    return memset_ptr(__s, __c, __n);
}

void *memcpy(void *__restrict __dest, const void *__restrict __src, size_t __n) {
    return memcpy_ptr(__dest, __src, __n);
}

int memcmp(const void *__s1, const void *__s2, size_t __n) {
    return memcmp_ptr(__s1, __s2, __n);
}

void qsort(void *__base, size_t __nmemb, size_t __size, int (*__compar)(const void *, const void *)) {
    qsort_ptr(__base, __nmemb, __size, __compar);
}

void *bsearch(const void *__key, const void *__base, size_t __nmemb, size_t __size, int (*__compar)(const void *, const void *)) {
    return bsearch_ptr(__key, __base, __nmemb, __size, __compar);
}

void symbols_init() {
    _printf = dlsym((void*)0x2, "printf");
    _sprintf = dlsym((void*)0x2, "sprintf");
    _vprintf = dlsym((void*)0x2, "vprintf");
    _vsprintf = dlsym((void*)0x2, "vsprintf");
    _fprintf = dlsym((void*)0x2, "fprintf");
    _vfprintf = dlsym((void*)0x2, "vfprintf");
    _fdopen = dlsym((void*)0x2, "fdopen");
    _fflush = dlsym((void*)0x2, "fflush");
    setjmp_ptr = dlsym((void*)0x2, "setjmp");
    longjmp_ptr = dlsym((void*)0x2, "longjmp");
    malloc_ptr = dlsym((void*)0x2, "malloc");
    free_ptr = dlsym((void*)0x2, "free");
    memset_ptr = dlsym((void*)0x2, "memset");
    memcpy_ptr = dlsym((void*)0x2, "memcpy");
    memcmp_ptr = dlsym((void*)0x2, "memcmp");
    qsort_ptr = dlsym((void*)0x2, "qsort");
    bsearch_ptr = dlsym((void*)0x2, "bsearch");

    // libkernel
    sceKernelJitCreateSharedMemory = dlsym((void*)0x2001, "sceKernelJitCreateSharedMemory");
    sceKernelJitCreateAliasOfSharedMemory = dlsym((void*)0x2001, "sceKernelJitCreateAliasOfSharedMemory");
    sceKernelJitMapSharedMemory = dlsym((void*)0x2001, "sceKernelJitMapSharedMemory");
    _socket = dlsym((void*)0x2001, "socket");
    _connect = dlsym((void*)0x2001, "connect");
    _inet_pton = dlsym((void*)0x2001, "inet_pton");
    _htons = dlsym((void*)0x2001, "htons");
}