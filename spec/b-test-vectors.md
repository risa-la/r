## Appendix B. Test Vectors

These keys are for testing only.

Each vector is a block of lines `name: value`: first its inputs, then,
after an empty line, its outputs, and last any cases that MUST fail.
Hex is lower case. A value too long for one line goes on in the lines
after it, each indented by two spaces, and the parts are joined with
nothing between them. A name followed by `(file F)` gives the SHA-256
hash of a value too long to print here: the value itself is the file F,
as bytes, in the folder `crates/risala-proto/tests/vectors/` of the
risala source code. Files named `.txt` hold text with LF line endings,
and files named `.bin` hold binary values. The value `rejected` marks a
case that implementations MUST reject. The vectors were made by risala's
implementation, whose tests check them against this appendix.

ML-DSA signing normally mixes in fresh randomness, so each signature
differs. The signatures here use the deterministic variant of
[FIPS204], so every correct implementation of that variant produces
exactly these bytes. Verifiers accept signatures from either variant.
With OpenSSL, add `-pkeyopt deterministic:1` to `openssl pkeyutl -sign`.

X-Wing key pairs are made from their 32-byte seeds as in [XWING].
Times are milliseconds since the Unix epoch.

### B.1 An ML-DSA-44 key, and AUTH (4.3, 4.6)

This key is used as a device key (4.3), signing in to
`chat.example.org` as `alice@example.org`. Its private key is a 32-byte
seed, and the hashes are SHA-256:

```
seed:               c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8
public key SHA-256: d9d69ac9b18f42759e43edba0106410c07045a1edab642925b7496ea40baccdf
host:               chat.example.org
uid:                alice@example.org
nonce:              6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e

signature SHA-256: eeda7aa7dd2ffa7cc2fa6683e7d8d2b94cf46716484b784d6a53b4928df58906

the signature checked for host chat.example.net:                  rejected
the signature checked for nonce 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6f: rejected
```

The same private key as PEM:

```
-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMRBCKAIMEfrlxZLhO+Z9yW9uhQBNMukoYV968f06bF
2eoKtsuo
-----END PRIVATE KEY-----
```

The public key (1312 bytes, base64). It is shown wrapped at 64
characters, but is a single line in key files and commands:

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

The signed bytes of AUTH, 82 in total, with each line ending in LF:

```
risala-auth-1
chat.example.org
6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e
alice@example.org
```

The signature (2420 bytes, base64, wrapped at 64 characters in the same
way):

```
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
AAAAAAAAAAAAAAAAAAAAAAkXJzM=
```

The command, on one line:

```
AUTH alice@example.org 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
```

### B.2 RisalaSign (4.3)

RisalaSign with the key of B.1, under the label `record`, of the 6
ASCII bytes `risala`. The RisalaSignContent is the encoded struct that
ML-DSA signs. The same signature MUST NOT verify under another label,
and a signature made with a context string that is not empty MUST NOT
verify at all.

```
key seed: c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8
label:    record
content:  726973616c61

RisalaSignContent: 0f726973616c612f31207265636f726406726973616c61
signature (file risalasign.bin):
  4025525295a548c8210c6f84da29721e6bea74589aed14c2a6fac46af7d48664

the signature verified under label pair:       rejected
the signature verified under label keypackage: rejected
the signature verified under label period:     rejected
the signature verified under label attest:     rejected
the same signed with context string risala (file risalasign-context.bin):
  01e00b4ac805b21c7af0852437eba5477e6555589784a22ef1c1ef2250575e94
that signature verified:                       rejected
```

### B.3 A recovery key and its master key (4.8)

A recovery key, its text form, and the master key it gives for
`alice@example.org`. The case that MUST fail changes the text form's
last character, so that its 4 unused bits are not zero.

```
recovery key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
uid:          alice@example.org

text form: aaaq eaye auda ocaj bifq ydio b4ib ceqt cqkr mfyy denb wha5 dypq
master public key (file master-key.bin):
  45fad3844fceae9f1c361df27aab863d3b52216a267e43faf3ccb250960e2995

the text form with its last character q changed to r: rejected
```

### B.4 A log and a device (4.4, 4.5, 12.14)

Log 1 of `chat.example.org`, with an ML-DSA-44 key made from the seed
below: its key ID, its verifier key (the `<vkey>` of a `log` line) and
its `log` line. Then a device, with the key of B.1 as its device key
and an X-Wing attestation key: its device id and its short id.

```
log origin:   chat.example.org/risala-log/1
log key seed: 0303030303030303030303030303030303030303030303030303030303030303
log URL:      https://chat.example.org/risala-log/1

key ID: a49fcad3
verifier key (file log-vkey.txt):
  ac4e6f46664b3e59cc404029bd4851aca7644ce4c3b394cb261a01576c7c6123
log line (file log-line.txt):
  60c4aa18bcf4d3e3e5fd114fd8988469638364f9e2bc74338413dc7c5ba2c649

device key seed:      c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8
attestation key seed: 0404040404040404040404040404040404040404040404040404040404040404

attestation key (file attestation-key.bin):
  bb4ce870113dc866909cc20bb80054c0b811cd3d20ad40ee0e60d9e256188509
device id:
  9dd34a4b2e6712ac7d2c679a46caaaaf875c945aefc33a78cefe1a014b9dacfa
  0f7c1460fbe5d395af0b70f54d51a994
short id: txjuuszo
```

### B.5 Records (4.4)

A chain of seven records for `alice@example.org`. Record i is made at
the time of record 0 plus i minutes:

0. `master`: the master key of B.3, the device-signing key below, and
   the log of B.4. Signed by the master key.
1. `device`: the device of B.4, labelled `laptop`. Signed by the
   device-signing key, as is record 2.
2. `device`: a second device, labelled `phone`, with the keys below.
3. `signing`: a new device-signing key, removing record 2's device.
   Signed by the master key.
4. `master`: the master key of the second recovery key, a third
   device-signing key, and the same log. Signed by both master keys.
5. `log`: the second log, which has a key made from the seed below.
6. `retire`. Records 5 and 6 are signed by the new master key.

Each record's hash is the `previous` of the record after it.

```
uid:                     alice@example.org
time of record 0:        1793491200000
device-signing key seed: 0202020202020202020202020202020202020202020202020202020202020202
first device label:      laptop
second device key seed:  0505050505050505050505050505050505050505050505050505050505050505
second attestation key seed:
  0606060606060606060606060606060606060606060606060606060606060606
second device label:     phone
new device-signing key seed:
  0707070707070707070707070707070707070707070707070707070707070707
second recovery key:     202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
third device-signing key seed:
  0808080808080808080808080808080808080808080808080808080808080808
second log origin:       keys.example.net/risala-log/1
second log key seed:     0909090909090909090909090909090909090909090909090909090909090909

record 0 (file record-0.bin):
  f9807991562dfc85a84fe5e474f2dc3e858dffd33f3648df38b4054272c8bd10
record 0 hash:
  sha384:ca954572feb91dee8a4bb5ba4298ada56bb638ef4806d3a375556b598
  9efe7e5e8ce2fa4f6366901597271f9b7dc2eb9
record 1 (file record-1.bin):
  362ce66eaaf941c829d820aad76d5c1f0036d5eb188d33e5c540e86065078a5b
record 1 hash:
  sha384:f9e9a0fa73dbc8ba2f32aad07058b423d215911fbc4ced255ac1a2574
  a4108d4e88866e68d7f363ce351a46684e23e4e
record 2 (file record-2.bin):
  de1ba0b45afd3c43a60dfa4bfc879ec9830486c470cc5bc4c1b7aad3b3869d6e
record 2 hash:
  sha384:e2d3882fde8adadec4b59f6f2ee850f5f7ca5957b64f083b61920a5d1
  d382926d53b5432836102916533ddf6d4a2e760
record 3 (file record-3.bin):
  bf69e09e444890632909b6c378e6609e6806122856d15cac1b4d119ca0440a6d
record 3 hash:
  sha384:3216733a4de6530470386c95521124da6b1c11e0bb7832866a9e37bbf
  0e5ca360ed46f8bd7be420d309ab01834ca88d2
record 4 (file record-4.bin):
  36a501d062604bc51d12952a4d74f50953f033a2e140b3da9d6cd349eacac993
record 4 hash:
  sha384:ba0fa8082476e5dd96de337ba0aec1f0d2258b62c876d86b133607597
  c0a6472cf76059834946c76dd36d86b25bbf665
record 5 (file record-5.bin):
  57651e14cc33945d545fcfdc66559ddab0f949677c71b7e271e32872046171c5
record 5 hash:
  sha384:d6a54b63bde87409534c455592fa1e806370739b104f0e85de64b2344
  03b1e393b426cc1f175b6edcd6ae669de8267e3
record 6 (file record-6.bin):
  97c0900ec649c572f60b0fdc3ffeba0ee1778b98aa94a44226057af4f8237645
record 6 hash:
  sha384:7e2540196c3f05a1c4e47c212e861624a695f642d1ae180802526f570
  97a8bb40c0db23a8ad07b99a2c3d707db140d00
generation after records 0 to 5: 2
```

### B.6 Key files (4.4)

Key files of the chain of B.5, with `<url>` `https://chat.example.org/risala-log/1`
for the log of B.4 and `https://keys.example.net/risala-log/1` for the
second log. A device reading them at the time below finds the first
one valid; the two whose records are logged also need the log's
entries (4.5).

```
read at: 1793494800000

records 0 and 1, not logged (file keyfile-1.txt):
  767af2741bed7d25acd70701f1139d3054e6b170f472cf2da0e10b27e4598f5d
records 0 and 1, logged (file keyfile-2.txt):
  18c49c41d5485906603554815f298d00817076ba5aeb56b444065778e4794213
records 0 to 6, 0 to 3 logged (file keyfile-3.txt):
  15f822ecc8c2e408b73bfa9c25bb051aef47684bfd8ea89f2549a41bdd1d0d08
```

Each of these key files breaks one rule of 4.4, named by its list
(parsing or replaying) and number, and MUST be found invalid. Most are
the first key file above with one change.

```
parse 1, no LF after the last line (file keyfile-fail-01.txt):
  1b5e6185e072b0775cda5f909769e312347956cb2de1423678ea2ebcf41f2605
parse 1, a CR before an LF (file keyfile-fail-02.txt):
  be6dc0a6caf0537dec96458cda45a782d0239f116414ee4b4d735dbfd0104156
parse 1, two spaces in a row (file keyfile-fail-03.txt):
  02b6901c33a2fc86f4a925c6a115ea1970cc59d481e10810f87932ed54ba01b1
parse 1, first line is not risala-keys/1 (file keyfile-fail-04.txt):
  961c8f310a9313cd49e5995ffa52e8fec8ac79dd16f8f34a881258d0aacd774e
parse 1, no log line before the records (file keyfile-fail-05.txt):
  d987e57dfca4787df1670755b15365703530d11837b76d2da073d20dad2dc8f5
parse 1, a log line follows another (file keyfile-fail-06.txt):
  fb149b3cdb6e4de97e93a58a4880c82a32237cfa9f6d539cc4b88b8f0533da7c
parse 1, an index line after a - line (file keyfile-fail-07.txt):
  8aebe26d8fb31457df277370137d45aa61906361fb57deaf34bde305ef56c2f2
parse 1, base64 without padding (file keyfile-fail-08.txt):
  f3d72ab6abac502cfed16de6ec83012e9d72c03783f76607036220f41baf6fea
parse 1, base64 whose unused bits are not zero (file keyfile-fail-09.txt):
  305ad7d5c2c51f4cd507ef5d55518648af79f053483b681d85e65350b37a3ac8
parse 1, a log URL that is not https and its origin (file keyfile-fail-10.txt):
  b698d199b360968c91fbeda0524aae16cbf6af85729ee56e996d5e89c8fc72d6
parse 2, uid length in two bytes where one is enough (file keyfile-fail-11.txt):
  c94a66e3d0b11e2b743ada3a90c36a1a7d80ba35d36652eaa29fbf38888690b4
parse 2, a byte after its last field (file keyfile-fail-12.txt):
  a1c16b34ffdffa2ce08910b1ccc67f3b58d1cea8ee23316a3b3e55a77aac8e30
replay 1, a record of another uid (file keyfile-fail-13.txt):
  a5610433b1a0146f5951117a845f6ebfb5d3687cd41eaff88d3806e2d3a9ed4c
replay 2, the first record is not a master record (file keyfile-fail-14.txt):
  e6ce4c953a1e52c47f508e9c88d54aa1f879fa6d584d7f7919f82a486c7a1d44
replay 2, previous is not the record before (file keyfile-fail-15.txt):
  87d2f728d0ad79f1ec1752bb26f584e20392c843f7d6078803e086b92f6145ec
replay 3, a time not later than the one before (file keyfile-fail-16.txt):
  df7efc28e1f416025bb2a8bca5496120617492610e79510ebf9bea1fc4e6f424
replay 4, a device record signed by the master key (file keyfile-fail-17.txt):
  8d1cc8ba6273ddae23684903c5ce45110c522869076946e3f7a643c340574630
replay 4, a later master record with one signature (file keyfile-fail-18.txt):
  fa364396cdbedfe8574c1ea60f876b9e47d2ddcbe1da7089b0702e0efadbbc81
replay 5, a device key that is the device-signing key (file keyfile-fail-19.txt):
  a0fc614563e7b259ae52c746e8abeac119f017ac6f5df98a63da78c289ce0ff7
replay 6, a later master record names another log (file keyfile-fail-20.txt):
  eddafb865f9552adfea3cd8ca6827f22f8888867cfaf31164ab3d6d6920ff0d7
replay 7, removed names a device that is not current (file keyfile-fail-21.txt):
  63970b824a58ebfc79fafae4ba143c12dcfb1d934d2d842d860c9206ba638828
replay 7, removed names a device twice (file keyfile-fail-22.txt):
  d5f5def36c98b72a45e6c2e1e6334c76f81c668a7bcdcf99e12b4a38de1b5336
replay 9, a log record names the current log (file keyfile-fail-23.txt):
  3e3d3cc5b48de327b56578a402923c0b045beb1d77d03f926b6cdb0c7a5e76ca
replay 10, a record after a retire record (file keyfile-fail-24.txt):
  22da997c83b4cdb32cf04fa0c66762fbc0d70bf61710e55fce8740483bc55bef
replay 11, a record listed under another log than its own (file keyfile-fail-25.txt):
  ea8bec82e09370a236f751ff4dad95aaf6f463ff307e9ccec94184274a3090df
```

### B.7 Key log entries (4.5)

The LogEntry of record 0 of B.5, and the LogEntry that hands log 1 of
B.4 off to log 2 of the same host.

```
hand-off to:  chat.example.org/risala-log/2
its key seed: 0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a

record 0's entry (file entry-record.bin):
  10090fec4c5693b0f91a4a978e0e53470a923253bb658804e6927035229bb2c2
hand-off entry (file entry-handoff.bin):
  69bb67521d1f02d8b0b6d4942cf2f0bd08a8ac059e482dfa4e94ad19ab56480a

the hand-off entry with type 0:          rejected
the hand-off entry with a byte after it: rejected
```

### B.8 REGISTER and KEYS PUT (4.7)

The `<keyfile>` of REGISTER for the chain of B.5 with records 0 and 1,
an encoded RecordList, sent in base64; and KEYS PUT adding record 2,
with its `<after>` and its `<records>`.

```
REGISTER keyfile (file register.bin):
  b5813f3047cb877c889f91f3e6ebd498c4bbae4be0e420d53c25459056b15015
KEYS PUT after:
  sha384:f9e9a0fa73dbc8ba2f32aad07058b423d215911fbc4ced255ac1a2574
  a4108d4e88866e68d7f363ce351a46684e23e4e
KEYS PUT records (file keys-put.bin):
  01f25690b8d7ff183880230d13e381c1a5bc795968223153a73a7c8239e6dc02
```

### B.9 A NewDevice and a PairingCode (4.8)

A new device's NewDevice, signed with its device key, and the
PairingCode and QR text that the new device shows. The cases that MUST
fail are the other device's checks of the NewDevice, and the version
bytes.

```
device key seed:      0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a
attestation key seed: 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
label:                new phone
pairing key seed:     0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
host:                 chat.example.org
secret:               0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d

NewDevice (file newdevice.bin):
  0ea249e0bb514683f41661d908cdbad667eb957c379cd81c009b572928f9a4db
keys_hash:
  ea97737d802b2cd5feccbb07769ce8b47ec29e4e9f86e70cf1149c274cff60c9
  21704460a80562454d269274cc7d661c
PairingCode:
  0110636861742e6578616d706c652e6f72670d0d0d0d0d0d0d0d0d0d0d0d0d0d
  0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0dea97737d802b2cd5feccbb07769c
  e8b47ec29e4e9f86e70cf1149c274cff60c921704460a80562454d269274cc7d
  661c
QR text:
  RISALA-PAIR:AEIGG2DBOQXGK6DBNVYGYZJON5ZGODINBUGQ2DINBUGQ2DINBUGQ
  2DINBUGQ2DINBUGQ2DINBUGQ2DIN5KLXG7MAFMWNL7WMXMDXNHHIWR7MFHSOT6DO
  ODHRCSOCOTH7MDESC4CEMCUAKYSFJUTJE5GMPVTBY

the NewDevice checked against keys_hash with its last bit flipped: rejected
the NewDevice with the last bit of its signature flipped:          rejected
a NewDevice whose pairing key is its attestation key:              rejected
the NewDevice with version 2:                                      rejected
the PairingCode with version 2:                                    rejected
```

### B.10 A safety number (12.14)

The safety number of `alice@example.org` with the master key of B.3.

```
uid:                       alice@example.org
master public key SHA-256: 45fad3844fceae9f1c361df27aab863d3b52216a267e43faf3ccb250960e2995

fingerprint:
  3ba74078f5d40243fd9da6052f6eb0f44bb6963ada7fbe644a06b49a7663e645
  287b179e75d9d1b97f49a0f81348c399
digits: 90805 77021 65744 77434 54474 25507 58935 42041
QR text:
  RISALA-FP:AEIWC3DJMNSUAZLYMFWXA3DFFZXXEZZ3U5AHR5OUAJB73HNGAUXW5M
  HUJO3JMOW2P67GISQGWSNHMY7GIUUHWF46OXM5DOL7JGQPQE2IYOMQ
```

### B.11 The pairing secret, and a SealedBundle (4.8)

The ids and keys that both devices derive from a pairing secret, and a
SealedBundle of the IdentityBundle below, sealed to the pairing key
made from the seed below with the `old_key` of this secret. Sealing is
randomized, so the SealedBundle is a vector for opening: it MUST open
to the IdentityBundle.

```
secret:            000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
pairing key seed:  0303030303030303030303030303030303030303030303030303030303030303
uid:               alice@example.org
master_key:        1312 bytes of 50
signing_seed:      5151515151515151515151515151515151515151515151515151515151515151
backup_generation: 2
backup_key:        5252525252525252525252525252525252525252525252525252525252525252
record_hash:
  5353535353535353535353535353535353535353535353535353535353535353
  53535353535353535353535353535353
hosts:             chat.example.org example.net
transfer blob:
  sha384:545454545454545454545454545454545454545454545454545454545
  454545454545454545454545454545454545454
transfer key:      5555555555555555555555555555555555555555555555555555555555555555

new_id:          38395018115278eecb70023050f20bb2
new_id as a box: ha4vagarkj4o5s3qaiyfb4qlwi
new_key:         f730c19cdb093a583cf927c2e8dac3c2c45c75ee3f8b89dcd7a1ed16e4ad6931
old_id:          02cb56f3764824ee4fd02a9b9e1fa29d
old_id as a box: alfvn43wjaso4t6qfknz4h5ctu
old_key:         d7bd4cef94c09a4513dbaacbe8b1eaee53ad8dc9283a37be93943ab16e4eeaad
pairing key (file pairing-key.bin):
  5b8e64e6709228bd7e4ed2942858a210fa08a85e83ee31c65ef17e119f77755c
IdentityBundle (file identity-bundle.bin):
  40c04e11bfd8584c97bb530366d7fa86d733fc749af0aa479a6a95456d41bc0b
a SealedBundle of it (file sealed-bundle.bin):
  4c37b41e80fcc683b3a40d33b17cda822aea9dbd63609814b0c1d46c23920dad

the SealedBundle with version 2:                                             rejected
the SealedBundle opened with the old_key of the secret 32 bytes of 01:       rejected
the SealedBundle opened with the pairing key of seed 32 bytes of 04:         rejected
the IdentityBundle with no hosts:                                            rejected
the IdentityBundle with hosts chat.example.org example.net chat.example.org: rejected
the IdentityBundle with version 2:                                           rejected
```

### B.12 CHALLENGE and ANSWER (12.10)

A CHALLENGE to the leaf at index 3 from the leaf at index 7: X-Wing
encapsulation to the answering device's attestation key, with the
encapsulation randomness below, then the confirm key K and the MAC
that the ANSWER carries. The leaf keys are ML-DSA-44 keys made from
the seeds below.

```
attestation key seed:     5555555555555555555555555555555555555555555555555555555555555555
encapsulation randomness:
  6666666666666666666666666666666666666666666666666666666666666666
  6666666666666666666666666666666666666666666666666666666666666666
group id:                 3333333333333333333333333333333333333333333333333333333333333333
answerer leaf key seed:   4444444444444444444444444444444444444444444444444444444444444444
answerer leaf index:      3
challenger leaf key seed: 7777777777777777777777777777777777777777777777777777777777777777
challenger leaf index:    7

attestation key (file confirm-attestation-key.bin):
  d05c159f31d8ed88cb2d544e09f94a95cb95480b93853858587656d51f36e08e
ciphertext (file confirm-ciphertext.bin):
  7c9841ebc36cd568422c16816c3226177a1cbea9514ebff0a3e5338e1b5db212
shared secret:   1447f492fbfefd103aeeafaea5e8f44b540f9adf1caae810f659f45cdfce17fd
ConfirmContent:
  0120333333333333333333333333333333333333333333333333333333333333
  3333b8c1cec58b43296f6b98a7bed384aa7063cde506a717cd87971fb04c7a9b
  3c176fc4c6c879dbf005710376c91e9c29941100a8d002dcda2dd34f707693c9
  70bedbe13b03a2222c9f5afe77f37b44d4fff02b45841c4e3e56397134896dab
  72afe2f3842c4f0b20e8604fec38b2063fae67f3d9baeb1143505d781291869c
  0487b6fcec5361cc5b4759685e128e7668d3
K:
  b9aa376b058d8bb7a4cee978d24e266a4be19d86268345e7145c1da61d934138
  a7c855c5b475fbf21231fac827d3b0d6
MAC:
  2fa54ceb6262059f0aaaec1ee90f9675c30293931c3e1bfdf4654690caf73c39
  edf45c74af74172137a68edcb12a8904
the CHALLENGE line (file confirm-challenge.txt):
  935075a1dcc182ccc85ca856c9066809078dc72705d956f2107843084fd5846f
the ANSWER line: ANSWER 7 L6VM62JiBZ8Kquwe6Q+WdcMCk5McPhv99GVGkMr3PDnt9Fx0r3QXITemjtyxKokE

the MAC with its last bit flipped:              rejected
the MAC checked with the two leaf keys swapped: rejected
```

### B.13 Period keys, PeriodCert, AttestContent and REVEAL (12.10)

A chain of period seeds whose last period is 20855, the period key of
period 20767, its PeriodCert from a device of `alice@example.org`, an
attestation of the leaf key below in the group below, and the REVEAL
of period 20767. The certificate and the attestation are deterministic
ML-DSA-44 signatures. Last, the period that a time falls in.

```
time:                     1794225600000
last period of the chain: 20855
its seed:                 2222222222222222222222222222222222222222222222222222222222222222
uid:                      alice@example.org
device key seed:          1111111111111111111111111111111111111111111111111111111111111111
period:                   20767
group id:                 3333333333333333333333333333333333333333333333333333333333333333
leaf key seed:            4444444444444444444444444444444444444444444444444444444444444444

period of the time:   20766
seed of period 20854: 4a7b3211acefd7c6e104a416d9c67c77673ad901f62703191fcbe62f88304252
seed of period 20767: c2dc254f79ca131a1154424feaf3ed4bf0ff91c597ca760f5c3d37676e15f916
period key (file period-key.bin):
  540f193e2e8ecb96a7e160bb53f5168202f131dbb266b8fd433ed2e3c299bdf1
device id:
  706ff9b8ffe9c98e9f53503cf1b314ec47eaa4bcbeb46880b3686e646e8ff028
  222c37ef4845cd55821d5caf611be91b
PeriodCert (file periodcert.bin):
  4222ad5a7285891c325e2d567d7885dd4ad562ba511250b730e24036b5f1a5f4
certificate (file period-certificate.bin):
  d8ab25eda2e848a83f7edece61b73d65d02bf68fbb67c2af4b31ec570748e95f
AttestContent:
  0120333333333333333333333333333333333333333333333333333333333333
  33330000511f1100a8d002dcda2dd34f707693c970bedbe13b03a2222c9f5afe
  77f37b44d4fff02b45841c4e3e56397134896dab72af
attestation (file attestation.bin):
  acd66422bb28298d4ffe303d9362ee4aab7fbc5189d350be60914780f636c05e
the REVEAL line:      REVEAL 20767 wtwlT3nKExoRVEJP6vPtS/D/kcWXynYPXD03Z24V+RY=

the attestation checked for a leaf key from the seed 32 bytes of 45: rejected
an ATTEST for period 20767 posted at 1794268799999:                  rejected
an ATTEST for period 20767 posted at 1794358800000:                  rejected
a REVEAL of period 20767 with the seed 32 bytes of 23:               rejected
a REVEAL of period 20767 with the seed of period 20766:              rejected
```

### B.14 A RisalaMessage and its frank (12.9)

The franks of two contents, each under its frank key, and a
RisalaMessage with the first content and frank key. Content 1 is
`TEXT hello` and content 2 is
`@reply=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12`, each with its LF.

```
frank key 1: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
content 1:   544558542068656c6c6f0a
frank key 2: 4242424242424242424242424242424242424242424242424242424242424242
content 2:
  407265706c793d304a7831486b593378397a326235523071576d3166413d3d20
  544558542073656520796f752061742031320a
message_id:  01010101010101010101010101010101
counter:     2
previous:    02020202020202020202020202020202
time:        1800000000000

frank of content 1:
  48d7422d3f6b395988131847f92170c6bcc1925eb05495338e4fd9c480c41fa0
  485cc45e206ed988577a73f3792e8258
frank of content 2:
  8622a996f5638802118e2740494e46d0f03d92424f8e566c6aaf253f7496d591
  49f2c6d9a9629d6d0ac670da68f25f50
RisalaMessage:
  0101010101010101010101010101010101000000000000000210020202020202
  02020202020202020202000001a3185c5000000102030405060708090a0b0c0d
  0e0f101112131415161718191a1b1c1d1e1f0b544558542068656c6c6f0a

the frank of content 1 checked against content 2: rejected
the frank of content 1 with its last bit flipped: rejected
the frank of content 1 checked with frank key 2:  rejected
the RisalaMessage with version 2:                 rejected
```

### B.15 Encrypted files (12.11)

Two files under one file key: file 1, the 14 bytes `hello, risala` and
an LF, which takes one chunk, and file 2, which takes two. File 1 is
also encrypted as an archive.

```
file key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
file 1:   68656c6c6f2c20726973616c610a
file 2:   65529 bytes, byte i being i modulo 251

upload of file 1:
  01695c7cd9310ab87445141243dc38376079825e2cafbb7fb2f4733b92958a61
  462ef6b8fc2908
file-hash of file 1:            NhCQTv1i4+tHqcz5ZpTBHCwVGQ3x1hFYL592D7m0qvnuYSm2BhfToxD1N1yyOGhK
blob-ref of file 1:
  sha384:3610904efd62e3eb47a9ccf96694c11c2c15190df1d611582f9f760fb
  9b4aaf9ee6129b60617d3a310f5375cb238684a
file 1 as an archive:
  01695c7cd9310ab87445141243dc38376079825e2cafbb6a50e919373de1083f
  d8a25c88a12d43
length of the upload of file 2: 67617
blob-ref of file 2:
  sha384:df178956097f8985bee1e44daa2cf41c0f5a54cf7cd23297250ba8072
  3370c93d952bf4838eaa576bfe62949b83d745e

the upload of file 1 with version byte 2:                       rejected
file 1 as an archive, decrypted as a file:                      rejected
the upload of file 2 cut after its first chunk:                 rejected
the upload of file 2 with its two chunks swapped:               rejected
the upload of file 2 with its first chunk again after the last: rejected
file 2 with the last-chunk flag on its first chunk too (file file-flagged.bin):
  a1edbb07e31374f60aaaa745b8ca6afdc6396c15ae58eebb7996786a58c72200
```

These uploads, encrypted under the same file key, MUST fail: the first
has padding that is not zero, the second a plain text longer than
Padmé of 8 plus its length, and the third a length larger than its
plain text.

```
length 1, h, then the padding byte 01:
  01695c7cd9310ab87b4570351fe87db24cc73ee117887d5e7d273b
length 1, h, then 3 zero bytes: 01695c7cd9310ab87b45717e2f73712475a4ac07a00662ef25e123a00b
length 3, then hi:              01695c7cd9310ab87945183224501b984be17bff476dc1ad2fa805
```

### B.16 A HistoryArchive and a TransferRef (12.13)

The HistoryArchive of `alice@example.org` made at 1762600000000, with
two conversations on `example.org`, one with two messages from
`bob@example.net` and one empty, one ArchivedFile, and a TransferRef in
`more` to the next archive.

```
TransferRef blob:
  sha384:e1c9f3884f4b23c88e2991de91e518c8d35a4a9b6d14dbc872904281b
  de8441fe4c0518d85b7904c8b7f38449e40a166
TransferRef key: 0505050505050505050505050505050505050505050505050505050505050505

TransferRef:
  01e1c9f3884f4b23c88e2991de91e518c8d35a4a9b6d14dbc872904281bde844
  1fe4c0518d85b7904c8b7f38449e40a166050505050505050505050505050505
  0505050505050505050505050505050505
HistoryArchive:
  0111616c696365406578616d706c652e6f72670000019a63259a004186200101
  0101010101010101010101010101010101010101010101010101010101010b65
  78616d706c652e6f726701010101010101010101010101010101410901010101
  0101010101010101010101010f626f62406578616d706c652e6e657430d1d1d1
  d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1
  d1d1d1d1d1d1d1d1d1d1d1d1d1000000000000006500000000019a60c3400100
  00019a60c3406500000000000000010754455854206869020202020202020202
  020202020202020f626f62406578616d706c652e6e657430d2d2d2d2d2d2d2d2
  d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2
  d2d2d2d2d2d2d2d2000000000000006610e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2
  e2010000019a60c340020000019a60c3406600000000000000020a5445585420
  7468657265200202020202020202020202020202020202020202020202020202
  0202020202020b6578616d706c652e6f72670202020202020202020202020202
  0202004080303030303030303030303030303030303030303030303030303030
  3030303030303030303030303030303030303030303131313131313131313131
  3131313131313131313131313131313131313131313131313131313131313131
  3131313131323232323232323232323232323232323232323232323232323232
  3232323232405101e1c9f3884f4b23c88e2991de91e518c8d35a4a9b6d14dbc8
  72904281bde8441fe4c0518d85b7904c8b7f38449e40a1660505050505050505
  050505050505050505050505050505050505050505050505

the HistoryArchive with version 2:       rejected
the HistoryArchive with a byte after it: rejected
the TransferRef with version 2:          rejected
```

### B.17 Backup keys and a WrappedKey (12.13)

The backup keys of three generations from the recovery key of B.3, and
the file key of an archive wrapped under the backup key of generation
0, with the nonce below.

```
recovery key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
uid:          alice@example.org
archive:      6261636b7570
file key:     404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
nonce:        a0a1a2a3a4a5a6a7a8a9aaab

backup key of generation 0: bf567b1a74771d13e35f3428b382fe18ae35a8352a7b2b7eff120c991b5fab3d
backup key of generation 1: dab608fa392ada87879cb614886bdf24c06ba42d79bbb73b55dbe4037b255bb3
backup key of generation 3: 8ff5d23bd7c76d43e7fd34e2eda98546e3164ce8e7b7ecc8c8e5173695a2c46c
blob-ref of the archive:
  sha384:8da8347c19d220b72340517b38458f5c23473b055be1bfb496d2da8d8
  bab95f8311017489414b7b3090fbc85f357ef0d
associated data:            risala/1 backup alice@example.org 0 sha384:8da8347c19d220b72340517b38458f5c23473b055be1bfb496d2da8d8bab95f8311017489414b7b3090fbc85f357ef0d
WrappedKey under generation 0:
  01a0a1a2a3a4a5a6a7a8a9aaab6d97c6f02c7c3b1131a3e629e03523ef22fba8
  dabdc18677cb9b30be712ffb6f6ba6efbd70e20f7e0e0eebf3a7a7c97a

the WrappedKey unwrapped under generation 1:                      rejected
the WrappedKey unwrapped with generation 0's key as generation 1: rejected
the WrappedKey unwrapped for uid bob@example.org:                 rejected
the WrappedKey unwrapped for the blob-ref of backup2:             rejected
```

### B.18 A RisalaReport (5.8)

A report of the post with seq 7, frank key 1 and content 1 of B.14,
with one post of context, seq 5 with frank key 2 and content 2. Each
post's frank is its frank in B.14.

```
target seq:  7
context seq: 5
author:      alice@example.org
reason:      spam

RisalaReport:
  010000000000000007000102030405060708090a0b0c0d0e0f10111213141516
  1718191a1b1c1d1e1f0b544558542068656c6c6f0a405c000000000000000542
  4242424242424242424242424242424242424242424242424242424242424233
  407265706c793d304a7831486b593378397a326235523071576d3166413d3d20
  544558542073656520796f752061742031320a11616c696365406578616d706c
  652e6f7267047370616d

the report with context seq 7:                                       rejected
the report with context seqs 5 then 4:                               rejected
the target with frank key 2, checked against the frank of content 1: rejected
```

### Still to come

Vectors for the formats below will be added. They need values made by
an implementation of this document, which does not make them yet.

Identity and the key log:

- a key log checkpoint with the log's ML-DSA-44 signature and k
  cosignatures, an inclusion and a consistency proof, the files
  `risala/uid/<hash>`, `risala/next` and `risala/key` (4.5), and a
  hand-off request body (4.10)
- a SealedNewDevice (4.8), and a SealedBundle from a fixed X-Wing seed
  and encapsulation randomness (4.8)

Lines:

- the line grammar: tags, escaping, `ref` echo, the three kinds of
  parameter, and lines that are too long or get `bad-syntax` (2.3,
  3.1-3.7), including a number above 2^63-1
- a server (3.5) with and without a port, and links (Section 15), valid
  and invalid
- a box, a PAIR id and a link's group id in base32, with the last
  character's unused bits (3.5, 4.8, Section 15)

MLS and messages:

- an X-Wing private key expanded from a fixed 32-byte seed, as used for
  leaf keys and attestation keys (12.2); B.4 and B.12 give public keys
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
- a SealedWelcome, from a fixed KeyPackage, Welcome and HPKE
  randomness (12.8)
- a RisalaIdentity credential, a DeviceBinding and a RisalaProfile
  (12.3)
- a RisalaConversation extension for each kind of conversation (12.4)
- a RisalaAAD, and a whole application message from a fixed group
  state (12.9)
- READ's `<check>` from an `epoch_authenticator` (12.9)
- group checks as decisions: a group state and a post with a commit,
  and whether the commit is valid, for each group check of 12.7,
  including the stale-leaf median with activity times, `streak` per
  identity, the bounds on `updated`, signature key changes, copies,
  removals for a check and the bulk limit (12.3, 12.7), since every
  implementation must reach the same answer (7.2)

Files and history:

- a history split over two archives (12.13), and a BACKUP `files` list
  (12.13)

Cases that MUST fail:

- key files: a Record over 16 KiB, and a `removed` list out of order
  (4.4)
- the key log: a checkpoint with an extension line, a cosignature with
  a zero timestamp, an Ed25519 cosignature, a cosignature whose key ID
  matches but whose key does not, the log's own signature counted as a
  witness, a witnessed checkpoint that is not fresh, and a checkpoint
  with entries after a hand-off (4.5, 4.10)
- pairing: a SealedNewDevice with a version other than 1 (4.8)
- a SealedWelcome with padding bytes that are not zero (12.8)
- an X-Wing key that fails the FIPS 203 check, and an MLS object with
  a cipher suite other than `0x0020` or a version other than `mls10`
  (12.2)
- a commit whose `next` is not the hash of the new epoch's send token,
  a KeyPackage whose lifetime does not cover the commit's `t`, one of
  7261201 seconds, lifetimes just inside and just outside `t` ± 1 hour,
  a DeviceBinding whose `device_id` is not its credential's, and one
  with a bad signature (12.3, 12.5, 12.7)
- an ATTEST after a REVEAL of its period (12.10)
- archives merged out of seq order, a later archive with another `uid`
  or `made`, and a split archive whose later part has a `more` of its
  own (12.13)
- a BACKUP `files` list with a wrong version byte or length (12.13)

For the cipher suite (12.2), implementations run the known-answer tests
published with X-Wing [XWING], ML-KEM [FIPS203] and ML-DSA [FIPS204],
and those of RFC 8439 for ChaCha20-Poly1305 and RFC 5869 for HKDF. The
X-Wing keys made from seeds in B.4, B.11 and B.12 pin the X-Wing
version in use (16).
