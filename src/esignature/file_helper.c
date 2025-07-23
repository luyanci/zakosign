#include "file_helper.h"

#include <openssl/err.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "ed25519_sign.h"

bool zako_file_sign(int fd, EVP_PKEY* key, uint8_t* result, uint8_t* hash) {

    struct stat st;
    fstat(fd, &st);

    void* buffer = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    
    zako_hash_buffer(buffer, st.st_size, hash);

    if (!zako_sign_buffer(key, hash, ZAKO_HASH_LENGTH, result)) {
        ZakoOSSLPrintError("Failed to sign buffer!");
    }

    munmap(buffer, st.st_size);

    return true;
}

bool zako_file_write_esig(int fd, struct zako_esignature* esignature, size_t len) {
    if (lseek(fd, 0, SEEK_END) == -1) {
        return false;
    }

    uint64_t magic = ZAKO_ESIGNATURE_MAGIC;

    write(fd, esignature, len);
    write(fd, &len, sizeof(size_t));
    write(fd, &magic, sizeof(uint64_t));

    return true;
}

int zako_file_open_rw(char* path) {
    int fd = open(path, O_RDWR);
    if (fd == -1) {
        ConsoleWriteFAIL("Failed to open %s", path);
        return -1;
    }

    return fd;
}

int zako_file_opencopy_rw(char* path, char* new, bool overwrite) {
    return zako_opencopy(path, new, overwrite);
}

uint32_t zako_file_verify_esig(int fd, uint32_t flags) {
    struct stat st;
    fstat(fd, &st);

    void* buffer = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    
    if (buffer == NULL) {
        return ZAKO_FV_MMAP_FAILED;
    }

    void* buff_end = ApplyOffset(buffer, +(st.st_size));
    uint64_t* r_magic = (uint64_t*) ApplyOffset(buff_end, -8);
    
    if (*r_magic != ZAKO_ESIGNATURE_MAGIC) {
        return ZAKO_FV_INVALID_HEADER;
    }

    uint64_t* sz = (uint64_t*) ApplyOffset(buff_end, -16);
    if (*sz == 0 || *sz > st.st_size) {
        return ZAKO_FV_INVALID_HEADER;
    }

    struct zako_esignature* esign_buf = (struct zako_esignature*) ApplyOffset(sz, -*sz);

    /* Entire file footer is ESignature + ESignatureSize + ESignatureMagic 
         which is *sz + sizeof(sz) + 8 = *sz + 16
       So, original file buffer will be FileSize - *sz - 16 */
    uint32_t result = zako_esign_verify(esign_buf, buffer, st.st_size - *sz - 16, flags);

    munmap(buffer, st.st_size);
    return result;
}
