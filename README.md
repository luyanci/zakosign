# zakosign

An ELF and PK file signing tool.

[![996.icu](https://img.shields.io/badge/link-996.icu-red.svg)](https://996.icu)
[![LICENSE](https://img.shields.io/badge/license-Anti%20996-blue.svg)](https://github.com/996icu/996.ICU/blob/master/LICENSE)

---

## Purpose

Magisk Modules or Kernel Patch Modules have the highest permissions in your system,
yet they are not signed.
At the same time, regular Android Apps, which does not aquire the HIGHEST permissions on your device, are all signed by the developers.
By signing modules, suspicious and unwanted modification to the module can be prevented.
An example can be that a virus module pretend to be a popular module by simply cloning module properties. 
As Android root managers (Magisk, KernelSU, APatch, and their forks) does not
verify the integrity of Magisk Modules or Kernel Patch Modules,
this project is here to solve the problem without introducing any breaking changes.
`zakosign` provides a complete solution for signing both PK (aka ZIP) and ELF files.

It is important to verify before installation but not after installation because
with root privileges you can basically bypass all signature verification in your system.
So, it is important to prevent the installation of suspicious modules.

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
