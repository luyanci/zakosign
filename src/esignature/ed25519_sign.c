#include "ed25519_sign.h"
#include "esignature.h"

#include <openssl/decoder.h>
#include <openssl/objects.h>
#include <openssl/err.h>

static EVP_PKEY* zako_load_anykey(const char* path, char* password) {
    FILE* fkey = fopen(path, "r");

    if (fkey == NULL) {
        ConsoleWriteFAIL("Failed to open %s", path);

        return NULL;
    }

    EVP_PKEY* key = NULL;
    OSSL_DECODER_CTX* dctx = OSSL_DECODER_CTX_new_for_pkey(&key, NULL, NULL, NULL, EVP_PKEY_KEYPAIR, NULL, NULL);;

    if (dctx == NULL) {
        ZakoOSSLPrintError("OpenSSL Failed to load private key: %s", path);

        return NULL;
    }

    if (password != NULL) {
        if (OSSL_DECODER_CTX_set_passphrase(dctx, (const unsigned char* )password, strlen(password)) != 1) {
            ZakoOSSLPrintError("OpenSSL Failed to load private key: %s", path);

            goto done;
        }
    }
    
    if (OSSL_DECODER_from_fp(dctx, fkey) != 1) {
        ZakoOSSLPrintError("OpenSSL Failed to load private key: %s", path);

        goto done;
    }

    int id = EVP_PKEY_get_id(key);

    ConsoleWriteOK("%s (%s) Loaded successfully!", path, OBJ_nid2ln(id));

done:
    OSSL_DECODER_CTX_free(dctx);
    fclose(fkey);

    return key;
}

static EVP_PKEY* zako_parse_anykey(const char* data, char* password) {
    EVP_PKEY* key = NULL;
    OSSL_DECODER_CTX* dctx = OSSL_DECODER_CTX_new_for_pkey(&key, NULL, NULL, NULL, EVP_PKEY_KEYPAIR, NULL, NULL);;

    if (dctx == NULL) {
        ZakoOSSLPrintError("OpenSSL Failed to load private key: ");

        return NULL;
    }

    if (password != NULL) {
        if (OSSL_DECODER_CTX_set_passphrase(dctx, (const unsigned char* )password, strlen(password)) != 1) {
            ZakoOSSLPrintError("OpenSSL Failed to load private key: ");

            goto done;
        }
    }
    
    size_t sz = strlen(data) + 1;
    if (OSSL_DECODER_from_data(dctx, (const unsigned char**) &data, &sz) != 1) {
        ZakoOSSLPrintError("OpenSSL Failed to load private key: ");

        goto done;
    }

    int id = EVP_PKEY_get_id(key);

    ConsoleWriteOK("Key (%p, %s) Loaded successfully!", data, OBJ_nid2ln(id));

done:
    OSSL_DECODER_CTX_free(dctx);

    return key;
}

EVP_PKEY* zako_load_private(const char* path, char* password) {
    return zako_load_anykey(path, password);
}
 
EVP_PKEY* zako_parse_private(const char* data, char* password) {
    return zako_parse_anykey(data, password);
}
 
EVP_PKEY* zako_load_public(const char* path) {
    return zako_load_anykey(path, NULL);
}
 
EVP_PKEY* zako_parse_public(const char* data) {
    return zako_parse_anykey(data, NULL);
}

EVP_PKEY* zako_parse_public_raw(uint8_t* data) {
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, data, ZAKO_PUBKEY_LENGTH);
}

bool zako_get_public_raw(EVP_PKEY* key, uint8_t* data) {
    size_t len = ZAKO_PUBKEY_LENGTH;
    return EVP_PKEY_get_raw_public_key(key, data, &len);
}

bool zako_sign_buffer(EVP_PKEY* key, uint8_t* buffer, size_t len, uint8_t* signature) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t signature_len = 0;

    bool result = true;

    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) != 1) {
        result = false;
        goto exit;
    }

    if (EVP_DigestSign(ctx, NULL, &signature_len, buffer, len) != 1) {
        result = false;
        goto exit;
    }

    if (signature_len != ZAKO_SIGNATURE_LENGTH) {
        result = false;
        goto exit;
    }

    if (EVP_DigestSign(ctx, signature, &signature_len, buffer, len) != 1) {
        result = false;
        goto exit;
    }

exit:
    EVP_MD_CTX_free(ctx);
    return result;
}

bool zako_verify_buffer(EVP_PKEY* key, uint8_t* buffer, size_t len, uint8_t* signature) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool result = false;

    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) != 1) {
        goto exit;
    }

    result = EVP_DigestVerify(ctx, signature, ZAKO_SIGNATURE_LENGTH, buffer, len);

exit:
    EVP_MD_CTX_free(ctx);
    return result;
}

struct zako_stream_sign_context* zako_sign_stream_new(EVP_PKEY* key) {
    struct zako_stream_sign_context* ctx = ZakoAllocateStruct(zako_stream_sign_context);
    ctx->private = key;
    ctx->ctx = EVP_MD_CTX_new();

    if (ctx->ctx == NULL) {
        ZakoOSSLPrintError("OpenSSL Failed create evp_md context ")

        return NULL;
    }

    if (EVP_DigestSignInit(ctx->ctx, NULL, NULL, NULL, key) != 1) {
        ZakoOSSLPrintError("OpenSSL Failed initialize evp_md context ")
        
        EVP_MD_CTX_free(ctx->ctx);
        free(ctx);

        return NULL;
    }



    return ctx;
}

static bool zako_sign_stream_do_final(struct zako_stream_sign_context* context, uint8_t** result) {
    size_t sig_len = 0;

    if (EVP_DigestSignFinal(context->ctx, NULL, &sig_len) != 1) {
        EVP_MD_CTX_free(context->ctx);
        free(context);

        return false;
    }
    
    *result = zako_allocate_safe(sig_len);
    if (EVP_DigestSignFinal(context->ctx, *result, &sig_len) != 1) {
        EVP_MD_CTX_free(context->ctx);
        free(context);

        return false;
    }

    if (sig_len != ZAKO_SIGNATURE_LENGTH) {
        return false;
    }

    EVP_MD_CTX_free(context->ctx);
    free(context);

    return true;
}

static bool zako_sign_stream_update(struct zako_stream_sign_context* context, uint8_t* buffer, size_t len) {
    if (EVP_DigestSignUpdate(context->ctx, buffer, len) != 1) {

        EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(context->ctx));
        ConsoleWriteOK("Signing block with public Key Context: %s, size:%d", EVP_PKEY_get0_description(pkey), EVP_PKEY_get_size(pkey));

        ZakoOSSLPrintError("Failed to sign block ");

        return false;
    } else {
        return true;
    }
}

bool zako_sign_stream(struct zako_stream_sign_context* context, uint8_t* buffer, size_t len, uint8_t** result) {
    if (buffer == NULL) {
        return zako_sign_stream_do_final(context, result);
    } else {
        return zako_sign_stream_update(context, buffer, len);
    }
}
