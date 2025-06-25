#ifndef ZAKOSIGN_HEADER_ELF_HELPER_H
#define ZAKOSIGN_HEADER_ELF_HELPER_H

#include "prelude.h"
#include "hasher.h"
#include "esignature.h"

#include <openssl/evp.h>
#include <libelf.h>
#include <gelf.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

struct elf_signing_buffer;

struct elf_signing_buffer {
    struct elf_signing_buffer* next;

    const char* name;
    size_t size;
    void* buffer;
    uint8_t checksum[ZAKO_HASHER_SIZE];
};

/**
 * Generate a (linked) list of important section hash
 * that will be used for signing.
 */
struct elf_signing_buffer* zako_elf_get_signing_buffer(Elf* elf);

/**
 * Sign buffer with key, and then write the signature to result.
 * 
 * The raw payload will be concation of all the hashes.
 * If an important section is absent, 32 bytes of zero will be filled.
 * If an important section has 0 length, 32 bytes of zero will be filled.
 * The raw payload will always has the same size.
 */
bool zako_elf_sign(struct elf_signing_buffer* buff, EVP_PKEY* key, uint8_t* result);

/**
 * Write the esignature to '.zakosign' section
 */
bool zako_elf_write_esig(Elf* elf, struct zako_esignature* esignature, size_t len);

/**
 * Open an Elf file located at path with mmaps (if possible)
 */
Elf* zako_elf_open_rw(char* path);

/**
 * Open a copy of Elf file located at path with mmaps (if possible)
 */
Elf* zako_elf_opencopy_rw(char* path, char* new);

/**
 * Free struct Elf* and also close fd (with hack)
 */
void zako_elf_close(Elf* elf);

#endif