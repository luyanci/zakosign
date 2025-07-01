#ifndef ZAKOSIGN_HEADER_ELF_HELPER_H
#define ZAKOSIGN_HEADER_ELF_HELPER_H

#include "prelude.h"
#include "hasher.h"
#include "esignature.h"

#include <openssl/evp.h>
#include <gelf.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define ZAKO_ELFV_MMAP_FAILED    (1 << 16)
#define ZAKO_ELFV_INVALID_HEADER (1 << 17)

bool zako_elf_sign(int fd, EVP_PKEY* key, uint8_t* result);
bool zako_elf_write_esig(int fd, struct zako_esignature* esignature, size_t len);

/**
 * Open path and return fd
 */
int zako_elf_open_rw(char* path);

/**
 * Copy input path to new and then open new.
 */
int zako_elf_opencopy_rw(char* path, char* new, bool overwrite);

uint32_t zako_elf_verify_esig(int fd, uint32_t flags);

#endif