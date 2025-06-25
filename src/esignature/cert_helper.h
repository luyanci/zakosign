#ifndef ZAKOSIGN_HEADER_CERT_HELPER_H
#define ZAKOSIGN_HEADER_CERT_HELPER_H

#include "prelude.h"

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>

struct zako_trustchain {
    X509_STORE* trusted_ca;
    STACK_OF(X509)* cert_chain;
    X509* leaf;
};

X509* zako_x509_parse_pem(char* certificate);
X509* zako_x509_load_pem(char* path);
X509* zako_x509_parse_der(uint8_t* data, size_t len);

struct zako_trustchain* zako_trustchain_new();
bool zako_trustchain_add_intermediate_str(struct zako_trustchain* chain, char* certificate);
bool zako_trustchain_add_intermediate_der(struct zako_trustchain* chain, uint8_t* data, size_t len);
bool zako_trustchain_add_intermediate(struct zako_trustchain* chain, X509* certificate);
bool zako_trustchain_set_leaf_str(struct zako_trustchain* chain, char* certificate);
bool zako_trustchain_set_leaf_der(struct zako_trustchain* chain, uint8_t* data, size_t len);
bool zako_trustchain_set_leaf(struct zako_trustchain* chain, X509* certificate);
bool zako_trustchain_verify(struct zako_trustchain* chain);
bool zako_trustchain_verifykey(struct zako_trustchain* chain, EVP_PKEY* key);

void zako_trustchain_free(struct zako_trustchain* chain);


#endif