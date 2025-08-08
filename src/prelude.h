#ifndef ZAKOSIGN_HEADER_PRELUDE_H
#define ZAKOSIGN_HEADER_PRELUDE_H

#if __has_include(<unistd.h>)
#define ZAKO_TARGET_POSIX 1
#endif

#if defined(__WIN32)
#define ZAKOO_TARGET_NT 1
#endif 

#if defined(__APPLE__)
#define ZAKOO_TARGET_APPLE 1
#define ZAKO_TARGET_POSIX 1
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define __hide __attribute__((visibility("hidden")))

#include "sys.h"
#include "utils.h"

#endif
