# openmls_traits, patched for risala

This is openmls_traits 0.6.0 from crates.io, unchanged except for one
value: the cipher suite
`MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44` is `0x0020`, the
value draft-ietf-mls-pq-ciphersuites-07 requests, instead of OpenMLS's
placeholder `0x0052` (the spec, 12.2 and 15). The root Cargo.toml puts it in
place of the crates.io release with `[patch.crates-io]`.

Drop the patch once an OpenMLS release uses `0x0020`. risala-mls tests
that the value is `0x0020`, so an upgrade cannot change it unnoticed.
