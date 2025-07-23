# zakosign Integration Guide

**NOTICE: This document is still WIP. Changes may occur anytime without notice.**

This guide is for integrating zakosign into modern root implementation manager.
This guide is split into three parts: integration overview, verification, recommended user-end design notes.

## Integration Overview
### Purpose

The purpose of zakosign is simple: to verify magisk module and KPM integrity.
These days, fake modules that pretend to be a popular module existed everywhere,
which is a growing threat for some beginners who can't differenciate them.
By signing Magisk Modules and Kernel Patch Modules, this problem can be solved.

### Terminology

- zakosign: This project and the Command-Line Interface Tool for signing and verifing
- zakosign E-Signature: Also known as `E-Signature` or `esig`, refers to the signature structure.
- TSA: Time Stamping Authority, is used to proof signing date. TSA issues a timestamp with a signature.
- OSS Certificate: A special certificate that issues only to opensource modules and requires to be signed on Github Actions or other transperent CI server.

### Basic Functionality

zakosign can sign a Magisk Module (PK) or Kernel Patch Module (ELF) file by adding a E-Signature data at the end of the file.
E-Signature contains public key, certificate chain, timestamp, timestamp signature, file hash, hash signature.

zakosign provides signing routines and verifing routines. 
Verifing routines supports basic data verification and certificate verification. 
Root manager implementation can add trusted root certificate freely through provided API.

## Integration and data verification

zakosign does not break any existing code. 
zakosign should be implemented in userspace only.

To integrate zakosign into your root manager implementation, 
please refer to the following example C code

```c
int fd = zako_file_open_rw(input);
uint32_t results = zako_file_verify_esig(fd, 0);

if (results != 0) {
    /* If important error occured, verification process should 
       be considered as failed due to unexpected modification
       potentially happened. */
    if ((results & ZAKO_ESV_IMPORTANT_ERROR) != 0) {
        ConsoleWriteFAIL("Verification failed!");
    } else {
        /* This is for manager that doesn't want to do certificate checks */
        ConsoleWriteFAIL("Verification partially passed");
    }
} else {
    ConsoleWriteOK("Verification passed!");
    goto exit;
}

/* Go through all bit fields */
for (uint8_t i = 0; i < sizeof(uint32_t); i ++) {
    if ((results & (1 << i)) == 0) {
        continue;
    }

    /* Convert error bit field index into human readable string */
    const char* message = zako_esign_verrcidx2str(i);
    ConsoleWriteFAIL("%s", message);
}

exit:
    close(fd);
```

Below is a table of all error codes.

| Field Index | Field                              | Important |
| ----------- | ---------------------------------- | --------- |
| 0           | ZAKO_ESV_INVALID_HEADER            | Yes       |
| 1           | ZAKO_ESV_UNSUPPORTED_VERSION       | Yes       |
| 2           | ZAKO_ESV_OUTDATED_VERSION          | Yes       |
| 3           | ZAKO_ESV_MISSING_CERTIFICATE       |           |
| 4           | ZAKO_ESV_UNTRUST_CERTIFICATE_CHAIN | Yes       |
| 5           | ZAKO_ESV_MISSING_TIMESTAMP         |           |
| 6           | ZAKO_ESV_UNTRUSTED_TIMESTAMP       | Yes       |
| 7           | ZAKO_ESV_VERFICATION_FAILED        | Yes       |
| 8           | ZAKO_ESV_CERTIFICATE_EXPIRED       |           |
| 9           | ZAKO_ESV_CERTIFICATE_ERROR         |           |
| 10          | ZAKO_ESV_CERTKEY_MISMATCH          | Yes       |

Errors that are related to inconsistency are considered as unexpected modifications,
and thus, they are considered as important errors that will fail the verification entirely.

## User-end design notes

- Manager should give developer at least one month migration window.
- Manager should not stop user from installing an untrusted module.
- Manager should only warn user if verification failed and point out potential risks.
- Manager can optionally support OSS verification and show user that the module is Opensource


