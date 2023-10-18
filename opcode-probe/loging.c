#include "loging.h"
#include "symbols.h"

#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../prosper0gdb/r0gdb.h"

static int log_sock;
static FILE* log_file;

void* dlsym(void*, const char*);

int printf(const char *__restrict format, ...) {
    va_list args;
    va_start(args, format);
    int ret = _vfprintf(log_file, format, args);
    _fflush(log_file);
    va_end(args);
    return ret;
}

void notify(const char* s) {
    struct
    {
        char pad1[0x10];
        int f1;
        char pad2[0x19];
        char msg[0xc03];
    } notification = {.f1 = -1};
    char* d = notification.msg;
    while(*d++ = *s++);
    ((void(*)())dlsym((void*)0x2001, "sceKernelSendNotificationRequest"))(0, &notification, 0xc30, 0);
}

void notifyf(const char *__restrict format, ...) {
    va_list args;
    va_start(args, format);
    struct
    {
        char pad1[0x10];
        int f1;
        char pad2[0x19];
        char msg[0xc03];
    } notification = {.f1 = -1};
    _vsprintf(notification.msg, format, args);
    ((void(*)())dlsym((void*)0x2001, "sceKernelSendNotificationRequest"))(0, &notification, 0xc30, 0);
}

int loging_init(const char* pc_ip, int pc_port) {
    log_sock = r0gdb_open_socket(pc_ip, pc_port);
    log_file = _fdopen(log_sock, "a");
    return 0;
}
