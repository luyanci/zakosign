#include "prelude.h"
#include "param.h"
#include "constants.h"

#include "esignature/ed25519_sign.h"
#include "esignature/file_helper.h"
#include "esignature/esignature.h"
#include "esignature/cert_helper.h"

#include <openssl/x509.h>
#include <unistd.h>

ZakoCommandHandler(root) {
    ConsoleWrite("zakosign - A ELF signing tool");
    ConsoleWrite("  -> OpenSSL %s", OPENSSL_VERSION_TEXT);
    ConsoleWrite("  -> Zako E-Signature %i", ZAKO_ESIGNATURE_VERSION);
    ConsoleWrite("For help, please use 'zakosign help'")
    return 0;
}

ZakoCommandHandler(root_help) {
    ConsoleWrite("%s", ZakoConstant(help));
    return 0;
}

ZakoCommandHandler(root_verify) {
    char* input = ZakoParamAt(0);
    bool strict_mode = ZakoFlagParam("strict");
    bool integrity_only = ZakoFlagParam("integrity");

    if (input == NULL) {
        ConsoleWrite("Usage: zakosign verify [options...] <input.elf>")
    }

    if (access(input, F_OK) != 0) {
        ConsoleWriteFAIL("%s does not exist!", input);
        return 1;
    }

    int fd = zako_file_open_rw(input);
    uint32_t results = zako_file_verify_esig(fd, 
                            (strict_mode ? ZAKO_ESV_STRICT_MODE : 0) + 
                            (integrity_only ? ZAKO_ESV_INTEGRITY_ONLY : 0));

    if (results != 0) {
        OnFlag(results, ZAKO_ESV_IMPORTANT_ERROR) {
            ConsoleWriteFAIL("Verification failed! (%u)", results);
        } else {
            ConsoleWriteFAIL("Verification partially passed. (%u)", results);
        }
    } else {
        ConsoleWriteOK("Verification passed!");
        goto exit;
    }

    for (uint8_t i = 0; i < sizeof(uint32_t) * 8; i ++) {
        if ((results & (1 << i)) == 0) {
            continue;
        }

        const char* message = zako_esign_verrcidx2str(i);
        ConsoleWriteFAIL("  %s", message);
    }

exit:
    close(fd);

    exit(results);
    return results;
}

ZakoCommandHandler(root_sign) {
    char* input = ZakoParamAt(0);
    char* key = ZakoParam("key");
    char* password = ZakoParam("password");
    char* output = ZakoParam("output");
    char* pubkey_path = ZakoParam("pubkey");
    bool overwrite = ZakoFlagParam("force") || ZakoFlag('f');

    if (input == NULL) {
        ConsoleWrite("Usage: zakosign sign [options...] --key <private.key> <input.elf>");
        return 1;
    }

    if (key == NULL) {
        ConsoleWrite("Usage: zakosign sign [options...] --key <private.key> <input.elf>");
        return 1;
    }

    if (access(input, F_OK) != 0) {
        ConsoleWriteFAIL("%s does not exist!", input);
        return 1;
    }

    if (access(key, F_OK) != 0) {
        ConsoleWriteFAIL("%s does not exist!", key);
        return 1;
    }

    struct zako_esign_context* es_ctx = zako_esign_new();

    /* Gather certificate info */
    struct zako_trustchain* chain = zako_trustchain_new();

    {
        struct zako_param* pr_curr = params;
        bool leaf_set = false;
        while (pr_curr != NULL) {
            if (zako_streq(pr_curr->name, "certificate")) {
                if (!leaf_set) {
                    X509* cert = zako_x509_load_pem(pr_curr->value);

                    if (cert == NULL) {
                        exit(1);
                    }

                    zako_esign_add_keycert(es_ctx, zako_esign_add_certificate(es_ctx, cert));
                    zako_trustchain_set_leaf(chain, cert);

                    leaf_set = true;
                } else {
                    X509* cert = zako_x509_load_pem(pr_curr->value);

                    if (cert == NULL) {
                        exit(1);
                    }

                    zako_esign_add_keycert(es_ctx, zako_esign_add_certificate(es_ctx, cert));
                    zako_trustchain_add_intermediate(chain, cert);
                }
            }

            pr_curr = pr_curr->next;
        }
    }

    /* Gather key info */
    EVP_PKEY* pkey = zako_load_private(key, password);
    EVP_PKEY* pubkey;

    if (pubkey_path != NULL) {
        pubkey = zako_load_public(pubkey_path);

        if (pubkey == NULL) {
            pubkey = pkey;
        }
    } else {
        pubkey = pkey;
    }

    /* Verify public key is valid */
    if (chain->leaf != NULL) { /* Only verify when we have a certificate */
        /* Do full certificate chain verify*/
        int verification = zako_trustchain_verifykey(chain, pubkey);
        if (verification != 0) {
            ConsoleWriteFAIL("Certificate Error! Invalid certificate: ")

            if (verification == -100) {
                ConsoleWriteFAIL("  Public key mismatch (-100)");
            } else {
                ConsoleWriteFAIL("  %s (%i)", X509_verify_cert_error_string(verification), verification)
            }
            
            // exit(1);
        }
    }

    zako_esign_set_publickey(es_ctx, pubkey);

    /* Load input / output ELF file */
    int target;

    if (output == NULL) {
        target = zako_file_open_rw(input);
    } else {
        target = zako_file_opencopy_rw(input, output, overwrite);
    }

    if (target == -1) {
        exit(1);
    }
    
    ConsoleWriteOK("Signing...")

    uint8_t result[ZAKO_SIGNATURE_LENGTH] = { 0 };
    uint8_t hash[ZAKO_HASH_LENGTH] = { 0 };
    /* Signature is a known size, so we can safely ignore this */
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
    if (!zako_file_sign(target, pkey, &result, &hash)) {
        ConsoleWriteFAIL("Failed to sign input file")
        return 1;
    }
    struct stat st;
    fstat(target, &st);

    ConsoleWriteOK("File Signature created: %s (%li bytes digested)", base64_encode(result, ZAKO_SIGNATURE_LENGTH, NULL), st.st_size);
    
    zako_esign_set_signature(es_ctx, hash, result);
    
    size_t len = 0;
    struct zako_esignature* esig = zako_esign_create(es_ctx, &len);

    ConsoleWriteOK("Writing E-Signature info (%lu bytes)...", len);
    if (!zako_file_write_esig(target, esig, len)) {
        exit(1);
    }

    close(target);
    free(esig);
    zako_trustchain_free(chain);
    EVP_PKEY_free(pkey);

    ConsoleWriteOK("Done")

    return 0;
}

ZakoCommandHandler(root_key) {
    ConsoleWrite("Usage: zakosign key <option> [args...]")

    return 0;
}

static void zako_cli_write_certificate_info(struct zako_der_certificate* der) {
    X509* x509 = zako_x509_parse_der(der->data, der->len);

    if (x509 == NULL) {
        return;
    }

    {
        X509_NAME* name = X509_get_issuer_name(x509);
        char* line = X509_NAME_oneline(name, NULL, 0);
        ConsoleWriteOK("      Issued by: %s", line);
        OPENSSL_free(line);
    }
 
    {
        X509_NAME* name = X509_get_subject_name(x509);
        char* line = X509_NAME_oneline(name, NULL, 0);
        ConsoleWriteOK("      Subject: %s", line);
        OPENSSL_free(line);
    }

    {
        ASN1_INTEGER* serial = X509_get_serialNumber(x509);
        BIGNUM* bn = ASN1_INTEGER_to_BN(serial, NULL);
        char* hex = BN_bn2hex(bn);
        ConsoleWriteOK("      Serial Number: %s", hex);
        OPENSSL_free(hex);
        BN_free(bn);
    }
    
    {
        BASIC_CONSTRAINTS* constraints = X509_get_ext_d2i(x509, NID_basic_constraints, NULL, NULL);
        if (constraints) {
            ConsoleWriteOK("      CA: %s", constraints->ca ? "Yes" : "No");
            BASIC_CONSTRAINTS_free(constraints);
        }
    }

    {
        BIO* bio = BIO_new(BIO_s_mem());
    
        printf("[+]       Not Before: ");
        ASN1_TIME_print(bio, X509_get0_notBefore(x509));
        char* notBefore;
        long notBefore_len = BIO_get_mem_data(bio, &notBefore);
        printf("%.*s\n", (int)notBefore_len, notBefore);
        BIO_reset(bio);
        
        printf("[+]       Not After : ");
        ASN1_TIME_print(bio, X509_get0_notAfter(x509));
        char* notAfter;
        long notAfter_len = BIO_get_mem_data(bio, &notAfter);
        printf("%.*s\n", (int)notAfter_len, notAfter);

        BIO_free(bio);
    }    
}

ZakoCommandHandler(root_info) {
    char* input = ZakoParamAt(0);

    if (input == NULL) {
        ConsoleWrite("Usage: zakosign info <file>")
    }

    if (access(input, F_OK) != 0) {
        ConsoleWriteFAIL("%s does not exist!", input);
        return 1;
    }

    int fd = zako_file_open_rw(input);
    struct zako_esignature* esig = zako_file_read_esig(fd);

    if (esig == NULL) {
        ConsoleWriteFAIL("File does not contains a valid E-Signature.");
        return 0;
    }

    ConsoleWriteOK("E-Signature V%lu (%u Certificates, %u Extra fields)", esig->version, esig->cert_sz, esig->extra_fields_sz);
    ConsoleWriteOK("  Checksum: %s", base64_encode(esig->hash, ZAKO_HASH_LENGTH, NULL));
    ConsoleWriteOK("  Signed by: %s", base64_encode(esig->key.public_key, ZAKO_PUBKEY_LENGTH, NULL));

    if (esig->key.trustchain[0] == 255) {
        goto no_cert;
    }

    uint8_t cert_count = esig->cert_sz;
    struct zako_der_certificate* cstbl[200] = { 0 };

    uint8_t* data = &esig->data;
    size_t off = (size_t) 0;
    for (uint8_t i = 0; i < cert_count; i ++) {
        struct zako_der_certificate* cert = ApplyOffset(data, +off);
        cstbl[i] = cert;

        off += sizeof(struct zako_der_certificate) + cert->len;
    }

    ConsoleWriteOK("  Certificates: ");
    ConsoleWriteOK("    Leaf:");
    zako_cli_write_certificate_info(cstbl[esig->key.trustchain[0]]);

    if (esig->key.trustchain[1] == 255) {
        goto no_cert;
    }

    if (esig->key.trustchain[2] == 255) {
        ConsoleWriteOK("    L2:");
        zako_cli_write_certificate_info(cstbl[esig->key.trustchain[1]]);

        goto no_cert;
    } else {
        ConsoleWriteOK("    L3:");
        zako_cli_write_certificate_info(cstbl[esig->key.trustchain[1]]);
    }

    ConsoleWriteOK("    L2:");
    zako_cli_write_certificate_info(cstbl[esig->key.trustchain[2]]);

no_cert:;
    
    struct tm* timeinfo = gmtime((const time_t*) &esig->created_at);
    char time_buffer[32];
    if (timeinfo) {
        strftime(time_buffer, 32, "%Y-%m-%dT%H:%M:%SZ", timeinfo);
        ConsoleWriteOK("  Signed At: %s", time_buffer);
    } else {
        ConsoleWriteOK("  Signed At: <Unknown>");
    }

    ConsoleWriteOK("  Signature: %s", base64_encode(esig->signature, ZAKO_SIGNATURE_LENGTH, NULL));

    return 0;    
}

ZakoCommandHandler(root_key_new) {
    char* foutput = ZakoParamAt(0);

    if (foutput == NULL) {
        ConsoleWrite("Usage: zakosign key new <file>");

        return 1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);;
    EVP_PKEY *pkey = NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        ZakoOSSLPrintError("Failed to generate signing key!");

        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        ZakoOSSLPrintError("Failed to generate signing key!");

        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    BIO* out = BIO_new_file(foutput, "w+");

    if (out == NULL) {
        ZakoOSSLPrintError("Failed to create and open output file: %s", foutput);
    }

    if (PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL) <= 0) {
        ZakoOSSLPrintError("Failed to write signing private key!");
    }
    
    BIO_flush(out);
    BIO_free(out);

    BIO* pubout = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(pubout, pkey) <= 0) {
        ZakoOSSLPrintError("Failed to write signing public key!");
    }
    
    BUF_MEM* buffer;
    BIO_get_mem_ptr(pubout, &buffer);

    ConsoleWrite("%.*s", (int32_t)buffer->length, buffer->data)


    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return 0;
}

int main(int argc, char* argv[]) {
    ZakoNewCliApp(true);
        ZakoCommand(root, help);
        ZakoCommand(root, verify);
        ZakoCommand(root, sign);
        ZakoCommand(root, info);
        ZakoCommand(root, key);
            ZakoCommand(root_key, new);
    ZakoRunCliApp();
}
