#include "esignature.h"
#include "ed25519_sign.h"

struct zako_esign_context* zako_esign_new() {
    struct zako_esign_context* ctx = ZakoAllocateStruct(zako_esign_context);

    ctx->key.trustchain[0] = 255; /* L4 */
    ctx->key.trustchain[1] = 255; /* L3 */
    ctx->key.trustchain[2] = 255; /* L2 */
    
    return ctx;
}

static void zako_esign_free(struct zako_esign_context* ctx) {
    for (uint8_t i = 0; i < ctx->cert_count; i ++) {
        if (ctx->cstbl[i] != NULL) {
            free(ctx->cstbl[i]);
        }
    }

    free(ctx);
}

uint8_t zako_esign_add_certificate(struct zako_esign_context* ctx, X509* certificate) {
    if (ctx->cert_count >= 200) {
        return 255;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    i2d_X509_bio(bio, certificate);

    uint8_t* der_data = NULL;
    size_t der_len = BIO_get_mem_data(bio, (char**)&der_data);

    if (der_len == 0) {
        return 254;
    }

    uint8_t id = ctx->cert_count;
    ctx->cert_count += 1;

    struct zako_der_certificate* fin_cert = (struct zako_der_certificate*) zako_allocate_safe(sizeof(struct zako_der_certificate) + der_len);

    fin_cert->len = der_len;
    fin_cert->id = id;
    memcpy(&fin_cert->data, der_data, der_len);

    ctx->cstbl[id] = fin_cert;

    BIO_free(bio);

    return id;
}

void zako_esign_set_publickey(struct zako_esign_context* ctx, EVP_PKEY* key) {
    zako_get_public_raw(key, &ctx->key.public_key);
}

void zako_esign_add_keycert(struct zako_esign_context* ctx, uint8_t id) {
    if (ctx->key.trustchain[0] == 255) {
        ctx->key.trustchain[0] = id;
    } else if (ctx->key.trustchain[1] == 255) {
        ctx->key.trustchain[1] = id;
    } else {
        ctx->key.trustchain[2] = id;
    }
}

void zako_esign_set_signature(struct zako_esign_context* ctx, uint8_t* signature) {
    memcpy(&ctx->signature, signature, ZAKO_SIGNATURE_LENGTH);
}

void zako_esign_set_timestamp(struct zako_esign_context* ctx, uint64_t ts) {
    ctx->ts.timestamp = ts;
}

struct zako_esignature* zako_esign_create(struct zako_esign_context* ctx, size_t* len) {
    size_t esig_sz = sizeof(struct zako_esignature);

    for (uint8_t i = 0; i < ctx->cert_count; i ++) {
        if (ctx->cstbl[i] != NULL) {
            esig_sz += sizeof(struct zako_der_certificate) + ctx->cstbl[i]->len;
        }
    }

    *len = esig_sz;

    struct zako_esignature* esignature = (struct zako_esignature*) zako_allocate_safe(esig_sz);
    esignature->magic = ZAKO_ESIGNATURE_MAGIC;
    esignature->version = ZAKO_ESIGNATURE_VERSION;

    memcpy(&esignature->key, &ctx->key, sizeof(struct zako_keychain));
    memcpy(&esignature->ts, &ctx->ts, sizeof(struct zako_timestamp));
    memcpy(&esignature->signature, &ctx->signature, ZAKO_SIGNATURE_LENGTH);

    esignature->certificate_store.len = ctx->cert_count;

    size_t off = (size_t) &esignature->certificate_store.data;
    for (uint8_t i = 0; i < ctx->cert_count; i ++) {
        if (ctx->cstbl[i] != NULL) {
            size_t sz = sizeof(struct zako_der_certificate) + ctx->cstbl[i]->len;
            memcpy((void*) off, ctx->cstbl[i], sz);

            off += sz;
        }
    }

    zako_esign_free(ctx);

    return esignature;
}
