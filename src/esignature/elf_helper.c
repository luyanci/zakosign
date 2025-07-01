#include "elf_helper.h"

#include <openssl/err.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "ed25519_sign.h"

bool zako_elf_sign(int fd, EVP_PKEY* key, uint8_t* result) {

    struct stat st;
    fstat(fd, &st);

    void* buffer = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

    if (!zako_sign_buffer(key, buffer, st.st_size, result)) {
        ZakoOSSLPrintError("Failed to sign buffer!");
    }

    munmap(buffer, st.st_size);

    return true;
}

bool zako_elf_write_esig(int fd, struct zako_esignature* esignature, size_t len) {
    if (lseek(fd, 0, SEEK_END) == -1) {
        return false;
    }

    uint64_t magic = ZAKO_ESIGNATURE_MAGIC;

    write(fd, esignature, len);
    write(fd, &len, sizeof(size_t));
    write(fd, &magic, sizeof(uint64_t));

    return true;
}

int zako_elf_open_rw(char* path) {
    int fd = open(path, O_RDWR);
    if (fd == -1) {
        ConsoleWriteFAIL("Failed to open %s", path);
        return -1;
    }

    return fd;
}

int zako_elf_opencopy_rw(char* path, char* new, bool overwrite) {
    if (access(new, F_OK) == 0) {
        if (overwrite) {
            if (remove(new) == -1) {
                ConsoleWriteFAIL("File %s exists! (Failed to overwrite: %i)", new, errno);
                return -1;
            }
        } else {
            ConsoleWriteFAIL("File %s exists!", new);
            return -1;
        }
    }

    /* Reference: https://man7.org/linux/man-pages/man2/copy_file_range.2.html#EXAMPLES */

    int          fd_in, fd_out;
    off_t        size, ret;
    struct stat  stat;
    
    fd_in = open(path, O_RDONLY);
    if (fd_in == -1) {
        ConsoleWriteFAIL("Failed to open %s", path);
        return -1;
    }
        
    if (fstat(fd_in, &stat) == -1) {
        ConsoleWriteFAIL("Failed to get file stats of %s (%s)", path, strerror(errno));

        close(fd_in);
        return -1;
    }
        
    size = stat.st_size;
        
    fd_out = open(new, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd_out == -1) {
        ConsoleWriteFAIL("Failed to open %s", new);
        return -1;
    }
        
    do {
        /* For some reason, copy_file_range is not defined in unistd...
           For some reason, syscall is not defined in unistd either....

           .... I am very confused ...
           
           In order to not copy from kernel to userspace and vise versa multiple times
           we are going to manually do a syscall. Yay! */
        ret = linux_syscall6(__NR_copy_file_range, fd_in, (long) NULL, fd_out, (long) NULL, size, 0);
        if (ret == -1) {
            ConsoleWriteFAIL("Failed copy %s to %s", path, new);
            return -1;
        }
            
        size -= ret;
    } while (size > 0 && ret > 0);
        
    close(fd_in);

    return fd_out;
}

uint32_t zako_elf_verify_esig(int fd, uint32_t flags) {
    struct stat st;
    fstat(fd, &st);

    void* buffer = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    
    if (buffer == NULL) {
        return ZAKO_ELFV_MMAP_FAILED;
    }

    void* buff_end = ApplyOffset(buffer, +(st.st_size));
    uint64_t* r_magic = (uint64_t*) ApplyOffset(buff_end, -8);
    
    if (*r_magic != ZAKO_ESIGNATURE_MAGIC) {
        return ZAKO_ELFV_INVALID_HEADER;
    }

    uint64_t* sz = (uint64_t*) ApplyOffset(buff_end, -16);
    if (*sz == 0 || *sz > st.st_size) {
        return ZAKO_ELFV_INVALID_HEADER;
    }

    struct zako_esignature* esign_buf = (struct zako_esignature*) ApplyOffset(sz, +*sz);

    uint32_t result = zako_esign_verify(esign_buf, buffer, *sz, flags);

    munmap(buffer, st.st_size);
    return result;
}
