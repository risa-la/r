## Appendix A. Checking a Server by Hand

Every conversation is end to end encrypted, so none of them can be used
by typing lines. A terminal is still enough to look at a server, and to
check its certificate through another channel. This needs OpenSSL 3.5
or later, for the post-quantum key exchange (2.1).

**Connect, and ask what the server offers:**

```
openssl s_client -connect chat.example.org:7472 -quiet
```

Then type `info`. Keep `-quiet`, or use `-nocommands`. Without either,
`s_client` treats lines that start with `Q`, `R`, `k` or `K` as its own
commands.

**Check a server's fingerprint** (Section 2.2):

```
openssl s_client -connect chat.example.org:7472 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256
```

If the hash printed is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, the
handshake failed and this is the hash of nothing, not a fingerprint. The
usual cause is an OpenSSL older than 3.5.

**Make a device key.** `openssl genpkey -algorithm ML-DSA-44` writes a
private key in PKCS#8 with both the 32-byte seed and the expanded
private key. Adding `-provparam ml-dsa.output_formats=seed-only` writes
the shorter seed-only form that Appendix B shows. Clients that read
private keys from PEM files MUST accept both forms, and use the seed
(4.3). A key file (4.4) needs records signed with RisalaSign, which
OpenSSL alone does not build.
