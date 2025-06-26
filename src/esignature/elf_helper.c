#include "elf_helper.h"

#include <openssl/err.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "ed25519_sign.h"

static char* signing_sections[] = {
    ".text",
    ".data",
    ".kpm.init",
    ".kpm.exit",
    ".kpm.info"
};

static struct elf_signing_buffer* zako_elf_create_signing_buffer() {
    struct elf_signing_buffer* root = ZakoAllocateStruct(elf_signing_buffer);
    struct elf_signing_buffer* curr = root;

    /* Starting at index = 1 to avoid allocate extra empty section 
       We also need to assign the first one manually */
    curr->name = signing_sections[0];

    for (size_t i = 1; i < (sizeof(signing_sections) / sizeof(char*)); i ++) {
        curr->next = ZakoAllocateStruct(elf_signing_buffer);
        curr = curr->next;

        curr->name = signing_sections[i];
    }

    return root;
}

void zako_elf_close_signing_buffer(struct elf_signing_buffer* buff) {
    struct elf_signing_buffer* curr = buff;

    while (curr != NULL) {
        struct elf_signing_buffer* next = curr->next;

        free(curr);
        
        curr = next;
    }
}

static uint8_t* zako_get_finalize_signing_buffer(struct elf_signing_buffer* buff, size_t* hash_buff_sz) {
    struct elf_signing_buffer* curr = buff;
    size_t count = 0;

    /* Find total blocks */
    while (curr != NULL) { 
        count ++;
        curr = curr->next;
    }
    curr = buff;

    *hash_buff_sz = count * ZAKO_HASHER_SIZE;
    uint8_t* hash_buff = zako_allocate_safe(*hash_buff_sz);

    for (size_t i = 0; i < count; i ++) {
        memcpy((&hash_buff[i * ZAKO_HASHER_SIZE]), curr->checksum, ZAKO_HASHER_SIZE);

        curr = curr->next;
    }

    zako_elf_close_signing_buffer(buff);

    return hash_buff;
}

struct elf_signing_buffer* zako_elf_get_signing_buffer(Elf* elf) {
    if (elf == NULL) {
        ConsoleWriteFAIL("%s (%d)", elf_errmsg(elf_errno()), elf_errno());
        return NULL;
    }

    struct elf_signing_buffer* root = zako_elf_create_signing_buffer();
    struct elf_signing_buffer* curr = root;
    
    size_t shstrndx;
    elf_getshdrstrndx(elf, &shstrndx);

    Elf_Scn* section = NULL;
    while ((section = elf_nextscn(elf, section)) != NULL) {
        GElf_Shdr shdr;
        gelf_getshdr(section, &shdr);
        
        char* name = elf_strptr(elf, shstrndx, shdr.sh_name);

        while (curr != NULL) {
            const char* expected = curr->name;

            if (zako_streq(expected, name)) {
                Elf_Data* data = elf_getdata(section, NULL);

                if (data->d_size == 0) {
                    break;
                }

                
                curr->buffer = data->d_buf;
                curr->size = data->d_size;

                if (zako_hash_buffer(curr->buffer, curr->size, curr->checksum)) {
                    ConsoleWriteOK("Found %s at %p (size=%lu), checksum: %s", name, data->d_buf, data->d_size, base64_encode(curr->checksum, ZAKO_HASHER_SIZE, NULL));
                } else {
                    ConsoleWriteFAIL("Found %s at %p (size=%lu), checksum: FAILED", name, data->d_buf, data->d_size);
                }

            }

            curr = curr->next;
        }
        curr = root;
    }

    return root;
}

bool zako_elf_sign(struct elf_signing_buffer* buff, EVP_PKEY* key, uint8_t* result) {
    struct elf_signing_buffer* curr = buff;
    
    size_t sign_buff_sz = 0;
    uint8_t* sign_buff = zako_get_finalize_signing_buffer(buff, &sign_buff_sz);
    
    if (!zako_sign_buffer(key, sign_buff, sign_buff_sz, result)) {
        ZakoOSSLPrintError("Failed to sign buffer!");
    }

    free(sign_buff);

    return true;
}

bool _setshstrndx (Elf *elf, size_t ndx) {
    GElf_Ehdr ehdr_mem;
    GElf_Ehdr *ehdr = gelf_getehdr (elf, &ehdr_mem);
    if (ehdr == NULL) {
        return false;
    }

    if (ndx < SHN_LORESERVE) {
        ehdr->e_shstrndx = ndx;
    } else {
        ehdr->e_shstrndx = SHN_XINDEX;
        Elf_Scn *zscn = elf_getscn (elf, 0);
        GElf_Shdr zshdr_mem;
        GElf_Shdr *zshdr = gelf_getshdr (zscn, &zshdr_mem);

        if (zshdr == NULL) {
            return false;
        }

        zshdr->sh_link = ndx;

        if (gelf_update_shdr (zscn, zshdr) == 0) {
            return false;
        }
    }

    if (gelf_update_ehdr (elf, ehdr) == 0) {
        return false;
    }

    return true;
}

bool zako_elf_write_esig(Elf* elf, struct zako_esignature* esignature, size_t len) {
    /* Reference: elfutils/tests/addsections.c */
    /* We need to create a new shstr table at the end of the file
       so that we can add our '.zakosign' section w/o updating
       relocations and pc relative offsets
       
       We'll also need to change the name of the old shstr table
       because Elf is strict... */

    size_t shstr_index = 0;

    elf_getshdrstrndx(elf, &shstr_index);
    Elf_Scn* shstrtbl = elf_getscn(elf, shstr_index);
    Elf_Data* shstrtbl_d = elf_getdata(shstrtbl, NULL);

    /* Pre-calculate string length to avoid calling strlen
       '.shstrtbl_backup' (16 + 1)
       '.zakosign' (9 + 1)
        = 27 */
    
    size_t shstrtbl_new_size = shstrtbl_d->d_size + 27;
    uint8_t* shstrtbl_new_d = zako_allocate_safe(shstrtbl_new_size);
    memcpy(shstrtbl_new_d, shstrtbl_d->d_buf, shstrtbl_d->d_size);
    memcpy(ApplyOffset(shstrtbl_new_d, +shstrtbl_d->d_size), ".shstrtbl_backup", 17);
    memcpy(ApplyOffset(shstrtbl_new_d, +(shstrtbl_d->d_size + 17)), ".zakosign", 10);

    /* Change the name to .shstrtbl_backup */
    GElf_Shdr strtbl_header_c = { 0 };
    GElf_Shdr* strtbl_header = gelf_getshdr(shstrtbl, &strtbl_header_c);

    size_t shstrtbl_name_backup = strtbl_header->sh_name;
    strtbl_header->sh_name = shstrtbl_d->d_size;

    gelf_update_shdr(shstrtbl, strtbl_header); /* Done */

    /* Time to create .zakosign section */
    Elf_Scn* zakosign_section = elf_newscn(elf);
    Elf_Data* zakosign_data = elf_newdata(zakosign_section);

    zakosign_data->d_size = len;
    zakosign_data->d_buf = esignature;
    zakosign_data->d_align = 1;
    zakosign_data->d_type = ELF_T_BYTE;

    GElf_Shdr zakosign_header_c = { 0 };
    GElf_Shdr* zakosign_header = gelf_getshdr(zakosign_section, &zakosign_header_c);

    zakosign_header->sh_type = SHT_PROGBITS;
    zakosign_header->sh_flags = 0;
    zakosign_header->sh_addr = 0;
    zakosign_header->sh_link = SHN_UNDEF;
    zakosign_header->sh_info = SHN_UNDEF;
    zakosign_header->sh_addralign = 1;
    zakosign_header->sh_entsize = 0;
    zakosign_header->sh_size = len;
    zakosign_header->sh_name = shstrtbl_d->d_size + 17;

    gelf_update_shdr(zakosign_section, zakosign_header); /* We're done! */

    /* Time to do the same thing to our new strtable section */

    Elf_Scn* strtbl_n_section = elf_newscn(elf);
    Elf_Data* strtbl_n_data = elf_newdata(strtbl_n_section);

    strtbl_n_data->d_size = shstrtbl_new_size;
    strtbl_n_data->d_buf = shstrtbl_new_d;
    strtbl_n_data->d_type = ELF_T_BYTE;
    strtbl_n_data->d_align = 1;

    GElf_Shdr strtbl_n_header_c = { 0 };
    GElf_Shdr* strtbl_n_header = gelf_getshdr(zakosign_section, &zakosign_header_c);

    strtbl_n_header->sh_type = SHT_STRTAB;
    strtbl_n_header->sh_flags = 0;
    strtbl_n_header->sh_addr = 0;
    strtbl_n_header->sh_link = SHN_UNDEF;
    strtbl_n_header->sh_info = SHN_UNDEF;
    strtbl_n_header->sh_addralign = 1;
    strtbl_n_header->sh_entsize = 0;
    strtbl_n_header->sh_size = shstrtbl_new_size;
    strtbl_n_header->sh_name = shstrtbl_name_backup;
 
    gelf_update_shdr(strtbl_n_section, strtbl_n_header); /* We're done! */

    _setshstrndx(elf, elf_ndxscn(strtbl_n_section)); /* Set our new string table */
    int64_t err = elf_update(elf, ELF_C_WRITE); /* We're ALL done! */
    
    free(shstrtbl_new_d);

    if (err < 0) {
        ConsoleWriteFAIL("Failed to write target file: %s", elf_errmsg(err));

        return false;
    }

    return true;
}

static Elf* zako_elf_openfd_rw(int fd) {
    elf_version(EV_CURRENT);
    Elf* elf = elf_begin(fd, ELF_C_RDWR_MMAP, NULL);

    return elf;
}

Elf* zako_elf_open_rw(char* path) {
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        ConsoleWriteFAIL("Failed to open %s", path);
        return NULL;
    }

    return zako_elf_openfd_rw(fd);
};

Elf* zako_elf_opencopy_rw(char* path, char* new) {

    if (access(new, F_OK) == 0) {
        ConsoleWriteFAIL("File %s exists!", new);
        return NULL;
    }

    /* Reference: https://man7.org/linux/man-pages/man2/copy_file_range.2.html#EXAMPLES */

    int          fd_in, fd_out;
    off_t        size, ret;
    struct stat  stat;
    
    fd_in = open(path, O_RDONLY);
    if (fd_in == -1) {
        ConsoleWriteFAIL("Failed to open %s", path);
        return NULL;
    }
        
    if (fstat(fd_in, &stat) == -1) {
        ConsoleWriteFAIL("Failed to get file stats of %s (%s)", path, strerror(errno));

        close(fd_in);
        return NULL;
    }
        
    size = stat.st_size;
        
    fd_out = open(new, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd_out == -1) {
        ConsoleWriteFAIL("Failed to open %s", new);
        return NULL;
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
            return NULL;
        }
            
        size -= ret;
    } while (size > 0 && ret > 0);
        
    close(fd_in);
    // close(fd_out); /* idk why zako_elf_openfd_rw(fd_out) won't work... */

    return zako_elf_openfd_rw(fd_out);
}

void zako_elf_close(Elf* elf) {
    /*
        Lets' do some fancy elf struct hack to get the fd from struct Elf;

        No complete definition of struct Elf 
        in libelf.h, so we have to do this hack.

        struct Elf
        {
          void *map_address;             8 (ptr)
          Elf *parent;                   8 (ptr)
          Elf *next;                     8 (ptr)

          Elf_Kind kind;                 4 (enum)
          Elf_Cmd cmd;                   4 (enum)
          unsigned int class;            4 (uint32)
          int fildes;                    8 + 8 + 8 + 4 + 4 + 4
          ....
        }

        No 32bit support and never will be.
        So ptr = 8 bytes, int = 4 bytes. */
    int elffd = *(int*) ((size_t) elf + 8 + 8 + 8 + 4 + 4 + 4);

    if (fcntl(elffd, F_GETFD) != -1 || errno != EBADF) {
        close(elffd); /* we dont really need to close this... but yeah whatever */
    }

    /* Also we don't really need to free this... 
       I'm doing this just to mute address sanitizers
       Maybe someday I'm going to make a address sanitizer fork
       that has no memory leak detection. */
    elf_end(elf);
}

