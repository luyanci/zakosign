#ifndef ZAKOSIGN_HEADER_FILE_HELPER_H
#define ZAKOSIGN_HEADER_FILE_HELPER_H

#include "prelude.h"
#include "hasher.h"
#include "esignature.h"

#include <openssl/evp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define ZAKO_FV_MMAP_FAILED    (1 << 16)
#define ZAKO_FV_INVALID_HEADER (1 << 17)

bool zako_file_sign(int fd, EVP_PKEY* key, uint8_t* result, uint8_t* hash);
bool zako_file_write_esig(int fd, struct zako_esignature* esignature, size_t len);

/**
 * Open path and return fd
 */
int zako_file_open_rw(char* path);

/**
 * Copy input path to new and then open new.
 */
int zako_file_opencopy_rw(char* path, char* new, bool overwrite);

uint32_t zako_file_verify_esig(int fd, uint32_t flags);

struct zako_esignature* zako_file_read_esig(int fd);

#endif