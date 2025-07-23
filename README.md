# zakosign - WIP

An ELF and PK file signing tool.

[![996.icu](https://img.shields.io/badge/link-996.icu-red.svg)](https://996.icu)
[![LICENSE](https://img.shields.io/badge/license-Anti%20996-blue.svg)](https://github.com/996icu/996.ICU/blob/master/LICENSE)

---

## For Root Implementations

Please read `docs/INTEGRATION_GUIDE.md` for more information on integrating zakosign.

## For Developers

To sign your module, you will first need a ED25519 keypair. RSA keypair is not supported.
If you already have one, you can skip this step.

```shell
$ zakosign key new yourkey.pem
```

Signing your module
```shell
$ zakosign sign example.zip --key yourkey.pem --output example.signed.zip
```

If you wish to add certificates, specify them by using `--certificate` repeatly. 
You can add maximium of four certificates.
```shell
$ zakosign sign example.kpm --key l3.pem --output example.signed.kpm --certificate l3.crt --certificate l2.crt --force
```
