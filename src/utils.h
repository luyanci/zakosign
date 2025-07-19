#ifndef ZAKOSIGN_HEADER_UTILS_H
#define ZAKOSIGN_HEADER_UTILS_H

#include "prelude.h"

#define ConsoleWrite(...) printf(__VA_ARGS__); printf("\n");
#define ConsoleWriteOK(...) printf("[+] "); printf(__VA_ARGS__); printf("\n");
#define ConsoleWriteFAIL(...) printf("[-] "); printf(__VA_ARGS__); printf("\n");

#define ApplyOffset(ptr, off) (void*)(((size_t) ptr) off)

#define OnFlag(var, fl) if ((var & fl) > 0)
#define OnNotFlag(var, fl) if ((var & fl) == 0)


/**
 * Allocate with malloc but in a safe way.
 */
uint8_t* zako_allocate_safe(size_t len);

#define ZakoAllocateStruct(struct_name) (struct struct_name*) zako_allocate_safe(sizeof(struct struct_name))

bool zako_streq(const char* a, const char* b);

bool zako_strstarts(char* base, char* prefix);

unsigned char* base64_encode(const unsigned char* src, size_t len, size_t* out_len);
unsigned char* base64_decode(const unsigned char* src, size_t len, size_t* out_len);

long linux_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6);

int zako_opencopy(char* path, char* new, bool overwrite);

#endif