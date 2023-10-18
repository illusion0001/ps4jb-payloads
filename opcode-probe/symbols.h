#pragma once

#include <stdint.h>
#include <stdio.h>
#include <setjmp.h>
#include <netinet/in.h>

extern int (*_printf)(const char *__restrict __format, ...);
extern int (*_sprintf)(char *__restrict __s, const char *__restrict __format,
                       ...);
extern int (*_vprintf)(const char *__restrict __format, __gnuc_va_list __arg);
extern int (*_vsprintf)(char *__restrict __s, const char *__restrict __format,
                        __gnuc_va_list __arg);

extern int (*_fprintf)(FILE *__restrict __stream,
		    const char *__restrict __format, ...);
extern int (*_vfprintf)(FILE *__restrict __s, const char *__restrict __format,
		     __gnuc_va_list __arg);

extern FILE *(*_fdopen)(int __fd, const char *__modes);

extern int (*_fflush)(FILE *);

extern int (*_socket)(int __domain, int __type, int __protocol);
extern int (*_inet_pton)(int, const char * __restrict, void * __restrict);
extern uint16_t (*_htons)(uint16_t __hostshort);
extern int (*_connect)(int __fd, const struct sockaddr* __addr, socklen_t __len);

extern int	(*setjmp_ptr)(jmp_buf);
extern void (*longjmp_ptr)(jmp_buf env, int val);

extern void *(*malloc_ptr)(size_t size);
extern void (*free_ptr)(void *);

extern void *(*memset_ptr)(void *__s, int __c, size_t __n);
extern void *(*memcpy_ptr)(void *__restrict __dest, const void *__restrict __src, size_t __n);
extern int (*memcmp_ptr)(const void *__s1, const void *__s2, size_t __n);

extern void (*qsort_ptr)(void *, size_t, size_t, int (*)(const void *, const void *));
extern void *(*bsearch_ptr)(const void *, const void *, size_t, size_t, int (*)(const void *, const void *));

extern int (*sceKernelJitCreateSharedMemory)(int flags, size_t size, int protection, int *destinationHandle);
extern int (*sceKernelJitCreateAliasOfSharedMemory)(int handle, int protection, int *destinationHandle);
extern int (*sceKernelJitMapSharedMemory)(int handle, int protection, void **destination);

extern void *malloc(size_t size);
extern void	free(void *);

extern void symbols_init();
