#include "prelude.h"
#include "param.h"
#include "constants.h"

#include "esignature/ed25519_sign.h"
#include "esignature/file_helper.h"
#include "esignature/esignature.h"
#include "esignature/cert_helper.h"

#include <openssl/opensslv.h>
#include <openssl/provider.h>
#include <unistd.h>

ZakoCommandHandler(root) {
    ConsoleWrite("zakosign - A ELF signing tool");
    ConsoleWrite("  -> OpenSSL %s", OPENSSL_VERSION_TEXT);
    ConsoleWrite("  -> Zako E-Signature %i", ZAKO_ESIGNATURE_VERSION);
    ConsoleWrite("For help, please use 'zakosign help'")
    return 0;
}

ZakoCommandHandler(root_help) {
    ConsoleWrite("%s", _binary_src_help_bin_start);
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
            ConsoleWriteFAIL("Verification failed!");
        } else {
            ConsoleWriteFAIL("Verification partially passed");
        }
    } else {
        ConsoleWriteOK("Verification passed!");
        goto exit;
    }

    for (uint8_t i = 0; i < sizeof(uint32_t); i ++) {
        if ((results & (1 << i)) == 0) {
            continue;
        }

        const char* message = zako_esign_verrcidx2str(i);
        ConsoleWriteFAIL("%s", message);
    }

exit:
    close(fd);

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
    OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(NULL, "default");
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
    /* Signature is a known size, so we can safely ignore this */
#pragma clang diagnostic ignored "-Wincompatible-pointer-types"
    if (!zako_file_sign(target, pkey, &result)) {
        ConsoleWriteFAIL("Failed to sign input file")
        return 1;
    }
    struct stat st;
    fstat(target, &st);

    ConsoleWriteOK("File Signature created: %s (%li bytes digested)", base64_encode(result, ZAKO_SIGNATURE_LENGTH, NULL), st.st_size);
    
    zako_esign_set_signature(es_ctx, result);
    
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
    OSSL_PROVIDER_unload(default_provider);

    ConsoleWriteOK("Done")

    return 0;
}

ZakoCommandHandler(root_keypair) {
    ConsoleWrite("Usage: zakosign keypair <option> [args...]")

    return 0;
}

int main(int argc, char* argv[]) {
    ZakoNewCliApp(true);
        ZakoCommand(root, help);
        ZakoCommand(root, verify);
        ZakoCommand(root, sign);
        ZakoCommand(root, keypair);
    ZakoRunCliApp();
}
