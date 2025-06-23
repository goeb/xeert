# Xfon, a X509 certificate analysis tool

Features:
- print trees of x509 certificates
- show fields of x509 certificates
- do not use system-wide certificates (unless explicitely told)
- detect signature errors
- detect duplicates
- detect and break circular dependencies

Relies on:
- openssl for verification of signatures


## Print a tree of certificates

Example:

```
$ xfon tree test/set01/*crt
│ cn:root
│ 2022-12-24 07:15:42Z .. 2042-12-19 07:15:42Z
│ test/set01/root.crt
└──┬─────────────────────────────────────────────────────────────────
   ├──┤ cn:level1-a
   │  │ 2022-12-24 07:15:42Z .. 2042-12-19 07:15:42Z
   │  │ test/set01/level1-a.crt
   │  └──┬─────────────────────────────────────────────────────────────────
   │     ├──┤ cn:level2-a
   │     │  │ 2022-12-24 07:15:42Z .. 2042-12-19 07:15:42Z
   │     │  │ test/set01/level2-a.crt
   │     │  └────────────────────────────────────────────────────────────────────
   │     └──┤ cn:level2-b
   │        │ 2022-12-24 07:15:42Z .. 2042-12-19 07:15:42Z
   │        │ test/set01/level2-b.crt
   │        └──┬─────────────────────────────────────────────────────────────────
   │           └──┤ cn:level3-a
   │              │ 2022-12-24 07:15:42Z .. 2042-12-19 07:15:42Z
   │              │ test/set01/level3-a.crt
   │              └────────────────────────────────────────────────────────────────────
   └──┤ cn:level1-b
      │ 2022-12-24 07:15:42Z .. 2042-12-19 07:15:42Z
      │ test/set01/level1-b.crt
      └──┬─────────────────────────────────────────────────────────────────
         └──┤ cn:level2-c
            │ 2022-12-24 07:15:42Z .. 2042-12-19 07:15:42Z
            │ test/set01/level2-c.crt
            └────────────────────────────────────────────────────────────────────
```

Example with a signature error:

```
$ xfon tree test/set02/*crt
Error: Claimed child test/set02/level1-a.crt not verified by authority certificate test/set02/root.crt
│ cn:level1-a, o:abcdefxx
│ 2022-12-24 07:15:42Z .. 2042-12-19 07:15:42Z
│ test/set02/level1-a.crt
└────────────────────────────────────────────────────────────────────
│ cn:root
│ 2022-12-24 07:15:42Z .. 2042-12-19 07:15:42Z
│ test/set02/root.crt
└────────────────────────────────────────────────────────────────────
```

## Show contents of a certificate
```
$ xfon show test/set01/test/set01/level1-a.crt
subject: cn:level1-a
version: 0x02
serial: 0x67908A8509C8378C7458ED6C172D547BD33EE475
tbssignaturealgo: ecdsa-with-SHA256
issuer: cn:root
notbefore: 2022-12-24 07:15:42Z
notafter: 2042-12-19 07:15:42Z
pubkeyalgo: ecPublicKey (06082A8648CE3D030107)
pubkeybytes: 0004ED6B9D93A728E58DF968EEF8F59D52B890AD27943A1CEB7155C3AFCFF9B10B5036FB84BE44A490BF40197CE24D2934629C02CF519D9CF0E7D6D023B86363CCC3
subjectKeyIdentifier: ED01E16D375B6E2C3BF9BD1865744151A48264F3
basicConstraints: cA:true
authorityKeyIdentifier: EA2806C23E08C738E87009B37C93594B542D1AE1
signaturealgo: ecdsa-with-SHA256
signaturebytes: 0030450220481DA425F7F29F81B1A145D6738BBDFEB1BBA835AD722825B7CE786CACB590A5022100A7521EEAFA0114C7E603B79294A9748D7B8A33361B9D0D17A337B1D3BF33B04A
```
