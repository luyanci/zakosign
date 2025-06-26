#ifndef ZAKOSIGN_HEADER_CONSTANTS_H
#define ZAKOSIGN_HEADER_CONSTANTS_H

#include "prelude.h"

#define ZakoDefineConstant(file) \
    extern const uint8_t _binary_src_##file##_start[]; \
    extern const uint8_t _binary_src_##file##_end[]; \
    extern const size_t _binary_src_##file##_size;

#define ZakoDefineStrConstant(file) \
    extern const char* _binary_src_##file##_start; \
    extern const char* _binary_src_##file##_end; \
    extern const size_t _binary_src_##file##_size;

ZakoDefineConstant(help_bin);
ZakoDefineConstant(rootca_bin);



#endif