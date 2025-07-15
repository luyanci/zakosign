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
inline uint8_t* zako_allocate_safe(size_t len) {
    uint8_t* buff = (uint8_t*) malloc(len);

    if (buff == NULL) {
        return NULL;
    }

    memset(buff, 0, len);

    return buff;
}

#define ZakoAllocateStruct(struct_name) (struct struct_name*) zako_allocate_safe(sizeof(struct struct_name))

inline bool zako_streq(const char* a, const char* b) {
    if (a == NULL && b == NULL) { 
        return true;
    }

    if (a == NULL || b == NULL) {
        return false;
    }

    return strcmp(a, b) == 0;
}

inline bool zako_strstarts(char* base, char* prefix) {
    while (true) {
        char b = *base++;
        char p = *prefix++;

        if (p == '\0') {
            return true;
        }

        if (b != p) {
            return false;
        }

    }
}

inline bool zako_i8_inrange(char num, char min, char max) {
    return num >= min && num <= max;
}

unsigned char* base64_encode(const unsigned char* src, size_t len, size_t* out_len);
unsigned char* base64_decode(const unsigned char* src, size_t len, size_t* out_len);

inline long linux_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
#if defined(__aarch64__)
    long ret;
    asm volatile ("svc #0" : "=r"(ret) : "r"(n), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6) : "memory");
    return ret;
#else
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    asm volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
#endif
}

int zako_opencopy(char* path, char* new, bool overwrite);

#endif