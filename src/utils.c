#include "utils.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

__hide uint8_t* zako_allocate_safe(size_t len) {
    uint8_t* buff = (uint8_t*) malloc(len);

    if (buff == NULL) {
        return NULL;
    }

    memset(buff, 0, len);

    return buff;
}

__hide bool zako_streq(const char* a, const char* b) {
    if (a == NULL && b == NULL) { 
        return true;
    }

    if (a == NULL || b == NULL) {
        return false;
    }

    return strcmp(a, b) == 0;
}

__hide bool zako_strstarts(char* base, char* prefix) {
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

__hide long linux_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;

#if defined(__aarch64__)
    asm volatile ("svc #0" : "=r"(ret) : "r"(n), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6) : "memory");
#else
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    asm volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
#endif

    return ret;
}

/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
__hide unsigned char * base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	out = zako_allocate_safe(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}


/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
__hide unsigned char * base64_decode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	size_t i, count, olen;
	int pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = zako_allocate_safe(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					free(out);
					return NULL;
				}
				break;
			}
		}
	}

    if (out_len != NULL) {
    	*out_len = pos - out;
    }

	return out;
}


__hide int zako_opencopy(char* path, char* new, bool overwrite) {
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
