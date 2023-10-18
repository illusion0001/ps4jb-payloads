#pragma once

extern int loging_init(const char* pc_ip, int pc_port);

extern int printf(const char *__restrict __format, ...);
extern void notify(const char* s);
extern void notifys(const char* s);
extern void notifyf(const char *__restrict format, ...);
