## Appendix B. Test Vectors

These keys are for testing only.

ML-DSA signing normally mixes in fresh randomness, so each signature
differs. The signature below uses the deterministic variant of
[FIPS204], so every correct implementation of that variant produces
exactly these bytes. Verifiers accept signatures from either variant.
With OpenSSL, add `-pkeyopt deterministic:1` to `openssl pkeyutl -sign`.

Private key (the 32-byte seed, hex):

```
c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8
```

The same private key as PEM:

```
-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMRBCKAIMEfrlxZLhO+Z9yW9uhQBNMukoYV968f06bF
2eoKtsuo
-----END PRIVATE KEY-----
```

Public key (1312 bytes, base64). It is shown wrapped at 64 characters,
but is a single line in key files and commands. Its SHA-256 hash is
`d9d69ac9b18f42759e43edba0106410c07045a1edab642925b7496ea40baccdf`.

```
xjgGNXnY2mHZ3KDuXsHq19lnJd7U5fdp0TNCHpsz6xf7jMhE9181WJAPmoeTW0Bn
URbEsAPsYPUiBIunfbRrvADeL/bfXGDlU5cZwg3n6zkLeUm9dx3+Jz1+ZHcuHPIB
JvZ1fJrfFwJ68vdGFxDTQo3pUBEEejtwqB3L2WXeboCtNEB/6IlKJfCr1droLXLW
nckZiRpCoJRmv4g4hxVfNP4Uubjc2Fde4NxJmV8oW0wsRRnyzCYLI4QW7MDWz3uU
EsQJ9q9okdUTb0eSfm4TQ3FMeL39/9iBQaeidHXCdrFCHSfKndH/DH3jY18Oaogz
Q6S7TlHTwPmU12VVZbPEHIJtakRF9G4DS0ps0H8T3NKipFo6BpbtwpPqLR2EAX5M
gL7FI/Jv171G5/sD3nnsJ4A5jfXwHWr6UPlIB/VtKOfXzKRYWy37Y5EaQzEirdrb
9+xRouAS9gov36hlUYxwvFIRTF1XG1L5R2453DCE6drWUGNkLSCXRloO+RvXrdvA
Qm+fmqS2OuEs9+GsEHN531Duz2yOzM4DAn+IAIeU2kLGUZy54VTZV49nBI+rPh1X
wpoqw6BPgWVAdGK5XqyZYu2X1AjM2XvnRe4vDEg7UsfYv2JWeqWbu4c7KBx8F1ZE
SHTchYKRAvWfKBOF3PWifoIXqm0wtXuqu06Mne1LqYdwxilPiJDyt745mOG6K59V
WCeXFxGqebiy5R9FBkb3OLTJXU6OVXX/iumCRAdK/dbKb7+54OholPVj/PDAH2EY
anMXrumWy7B1dTH/jgI2MpkTYgjJ3bwsidZpF9Dx2eVuscgsRrXNKbbZ5mSYbTx+
WTCEpgPDGD6K6GRBjbCg5bwz4iCqMs2+Rv55bV2vwCaJmeu9SVevrmKtk4iBTiLp
ZO+nRBIAuhNJ2ftbJ67dNt2pz5ZacqP4TxbyKaknlsLMMoYrsrq8QVid0mz+9FR7
U7La2NoCPcMcDgWWOoDKlKNGIQx23v1x/z1YsnWpi7dt9FtJxvFa8mbsrVd4kci9
h2zjIsJXrBXpBO+iWzzoxDHiI8eOXTag8yOuEQHaUVVdwxQ0r4nwZUNL34WuuED6
FDF6/TE/nfkffQVzW52PkixgxmC5OIrWNcc0GXGAdxa2p3KxwMBbfk27in3wESIM
g4CDmmfdH65prjzxG47TSEqMZHxAM5bTfNLqjUN3QRGaVd2b3BecnplFXrjyKp8a
MyDUPJNolLq4dJG/n1wby85wino837kaodjRZeYryU0RyzLgqY1UHyzmU+AMu4q7
HM+jwSvdGQXX60Q7NLxSk+ClmoO+YEDrj3ki9WSp3NWG538oiGV4EqBJi+apjuPC
aWWtNm1DILZDAOjCCOyU9TEllzsjv8heU2bVmsLe1oRfIiDBQw7/Z9ZQFUjXka1B
e/JFUyiujtH+oLJVr3clrsZWPl9bawODt/znveuHTYZHf1j7azTcCBm5JZjjW8r8
guknfhcKPKOaTQUzqpXiALNhvcSO4RRtDFyn7L4VAz7K1uHbnXKHSeMnMRjpZnMZ
QoqyhEjNllb06dD0s4xDd1wJgGmWEd2KVHnLKhwKp1ED775+034shRb2v8W+DFIp
y3hVp9PEdnc9aJwzIreZHEJymMosqXo7mZaJNM+i+oYo2daWHMQYL1sOwzOTwEK2
xewaE3w/Xkq+iY4TC++t/oNTt5BdWJrJ90PPw6arr7MbXCEkTgNElxgTC7gcwdLS
nnO/Wp68V/V/przmVp4j4g==
```

This key is used as a device key (4.3). Signing in to
`chat.example.org` as `alice@example.org` with the nonce
`6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e`. These are the signed bytes, 82 in
total, with each line ending in LF:

```
risala-auth-1
chat.example.org
6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e
alice@example.org
```

Signature (2420 bytes, base64, wrapped at 64 characters in the same
way). Its SHA-256 hash is
`eeda7aa7dd2ffa7cc2fa6683e7d8d2b94cf46716484b784d6a53b4928df58906`.

```
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
AAAAAAAAAAAAAAAAAAAAAAkXJzM=
```

The command, on one line:

```
AUTH alice@example.org 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
```

Test vectors for the formats below will be added. They need values
made by an implementation of this document. Items marked † already have
values from the first implementation, which will be copied here once
they have been checked; the rest have none yet.

Identity and the key log:

- RisalaSign (4.3)†, and the encoding and signature of each kind of
  Record (4.4)†, with a LogKey, its verifier key, key ID and `log`
  line†, a device id and its short id (12.14)†, and a RecordList (4.4)
- a whole key file, valid†, and one that fails for each rule of 4.4's
  parsing and replaying†, and a chain's generation (4.4)†
- a key log entry of each type† (4.5), a checkpoint with the log's
  ML-DSA-44 signature and k cosignatures, an inclusion and a
  consistency proof, the files `risala/uid/<hash>`, `risala/next` and
  `risala/key` (4.5), and a hand-off request body (4.10)
- the `<keyfile>` of REGISTER and the `<records>` of KEYS PUT (4.7)†
- a recovery key in its text form, and the derivation of the master key
  from it (4.8)†
- a PairingCode and its QR text†, the keys and ids derived from the
  pairing secret†, a signed NewDevice† and its SealedNewDevice†, and a
  SealedBundle from a fixed X-Wing seed and encapsulation randomness†
  (4.8)
- a safety number, as digits and as QR text (12.14)†

Lines:

- the line grammar: tags, escaping, `ref` echo, the three kinds of
  parameter, and lines that are too long or get `bad-syntax` (2.3,
  3.1-3.7), including a number above 2^63-1
- a server (3.5) with and without a port, and links (Section 15), valid
  and invalid
- a box, a PAIR id and a link's group id in base32, with the last
  character's unused bits (3.5, 4.8, Section 15)

MLS and messages:

- an X-Wing key pair expanded from a fixed 32-byte seed, as used for
  leaf keys and attestation keys (12.2)
- a chain of period key seeds, and the period key derived from one
  (12.10)
- the send token export and its hash, and a commit's POST with its
  `next` (7.2, 12.6)
- the pseudonym export for a leaf index, and the box export of a
  mailbox move (7.3, 7.8)
- an AnnotatedWelcome and an AnnotatedCommit, from a fixed tree (12.6)
- the group id, epoch, content type and RisalaAAD that a server reads
  from a PrivateMessage and from a PublicMessage (5.2)
- PrivateMessage padding to a multiple of 256 bytes, and Padmé padding
  of commits and SealedWelcomes, including small lengths (12.6, 12.8,
  12.9)
- an RFC 8291 push body and the `NOTIFY` line inside it (9.3)
- the period number of a given time (12.10)
- a SealedWelcome, from a fixed KeyPackage, Welcome and HPKE
  randomness (12.8)
- a RisalaIdentity credential, a DeviceBinding and a RisalaProfile
  (12.3)
- a RisalaConversation extension for each kind of conversation (12.4)
- a RisalaAAD and a RisalaMessage, with its franking tag, and a whole
  application message from a fixed group state (12.9)
- READ's `<check>` from an `epoch_authenticator` (12.9)
- a CHALLENGE and ANSWER pair, from a fixed X-Wing seed and
  encapsulation randomness (12.10)
- a PeriodCert, an AttestContent and their signatures, and a REVEAL
  (12.10)
- group checks as decisions: a group state and a post with a commit,
  and whether the commit is valid, for each group check of 12.7,
  including the stale-leaf median with activity times, `streak` per
  identity, the bounds on `updated`, signature key changes, copies,
  removals for a check and the bulk limit (12.3, 12.7), since every
  implementation must reach the same answer (7.2)

Files, history and reports:

- an encrypted file of two chunks with Padmé padding†, and a history
  archive encrypted under its own label† (12.11)
- a HistoryArchive with `more`, an ArchivedFile and a TransferRef†, a
  history split over two archives, a backup key of a given
  generation† and a WrappedKey† (12.13), and a BACKUP `files` list
  (12.13)
- a RisalaReport, and a ReportedPost whose `frank_key` is wrong (5.8)

Each format also needs cases that MUST fail, so that implementations
can show that they reject them:

- key files: a non-shortest vector length, bytes after a Record's last
  field, base64 that is not strict, a public key repeated across roles,
  a `removed` list out of order or with repeats, a `time` that does not
  increase, a Record over 16 KiB, a `log` line whose `<url>` is not
  `https://` followed by its origin, and each failing rule of 4.4 (some
  of these are among the cases above†)
- the key log: a LogEntry of type 0 or with bytes after it, a
  checkpoint with an extension line, a cosignature with a zero
  timestamp, an Ed25519 cosignature, a cosignature whose key ID matches
  but whose key does not, the log's own signature counted as a
  witness, a witnessed checkpoint that is not fresh, and a checkpoint
  with entries after a hand-off (4.5, 4.10)
- signatures: AUTH over another host or nonce, an ML-DSA signature with
  a non-empty context string, and RisalaSign with another label (4.3,
  4.6)
- a recovery key whose last 4 bits are not zero (4.8)
- pairing: a NewDevice whose hash is not `keys_hash` or whose signature
  fails, a `pairing_key` equal to another key, a SealedNewDevice or
  SealedBundle with a version other than 1, a SealedBundle opened with
  the wrong `old_key`, and an IdentityBundle whose `hosts` is empty or
  repeats a server (4.8)
- a file cut short at a chunk boundary, two chunks swapped, the
  last-chunk flag on a middle chunk, an extra chunk after the last, a
  wrong version byte, an archive decrypted with the file label, padding
  that is not zero, a plain text longer than Padmé of 8 plus its length,
  and a length larger than the plain text (12.11)
- a franking tag that does not match (12.9)
- a SealedWelcome with padding bytes that are not zero (12.8)
- an X-Wing key that fails the FIPS 203 check, and an MLS object with
  a cipher suite other than `0x0020` or a version other than `mls10`
  (12.2)
- a commit whose `next` is not the hash of the new epoch's send token,
  a KeyPackage whose lifetime does not cover the commit's `t`, one of
  7261201 seconds, lifetimes just inside and just outside `t` ± 1 hour,
  a DeviceBinding whose `device_id` is not its credential's, and one
  with a bad signature (12.3, 12.5, 12.7)
- an ATTEST outside its period and grace hour, after a REVEAL, or with a
  wrong `leaf_key_hash`; a REVEAL seed that does not derive the period
  key; and an ANSWER with a wrong MAC (12.10)
- a RisalaReport whose context seqs do not increase, or are not below
  the target's (5.8)
- archives merged out of seq order, a later archive with another `uid`
  or `made`, and a split archive whose later part has a `more` of its
  own (12.13)
- a wrapped backup key unwrapped with the wrong generation, uid or
  blob-ref, and a BACKUP `files` list with a wrong version byte or
  length (12.13)

For the cipher suite (12.2), implementations run the known-answer tests
published with X-Wing [XWING], ML-KEM [FIPS203] and ML-DSA [FIPS204],
and those of RFC 8439 for ChaCha20-Poly1305 and RFC 5869 for HKDF. The
X-Wing seed expansion vector above pins the X-Wing version in use (16).
