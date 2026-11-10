## 15. Assigned Values

- **Port:** 7472/tcp. The digits spell RISA on a phone keypad. The port
  is not yet registered with IANA.
- **ALPN identifier:** `risala/1`.
- **Well-known URI suffix:** `risala` [RFC8615], for key files (4.3).
- **URI scheme:** `risala`, for links to servers and public rooms:

  ```abnf
  link      = "risala://" server [ "/" room-part [ "?g=" group-id ] ]
  room-part = alnum [ *62( alnum / "." / "_" / "-" ) ( alnum / "_" / "-" ) ]
                                                ; a room (3.5) without its "#"
  group-id  = 51( %x61-7A / %x32-37 ) ( "a" / "q" )
                                                ; 32 bytes in base32: a-z 2-7
  ```

  `server`, `alnum` and the room grammar are those of 3.5, so the port
  is left out when it is 7472. `<group-id>` is the room's 32-byte group
  id in lower-case base32 [RFC4648] without padding: 52 characters carry
  260 bits, so the last character's four unused bits are zero. A device
  folds ASCII upper case to lower case, then reads the link by this
  grammar, and treats anything else as an invalid link: a `/` at the
  end, another query key, a fragment, user information or an empty
  part. For example, `risala://chat.example.org/general` points to
  `#general`. A device that follows a link with `g` joins only the
  group with that id (6.1). Private conversations have no links, since
  their boxes are secret.
- **MLS cipher suite:** `0x0020`, for the algorithms of 12.2: X-Wing
  (HPKE KEM `0x647a`), HKDF-SHA384 (`0x0002`), ChaCha20-Poly1305
  (`0x0003`), SHA-384 and ML-DSA-44. This is the value that
  draft-ietf-mls-pq-ciphersuites-07 [MLS-PQ] requests for these
  algorithms; IANA has not assigned it yet. This document fixes the
  meaning of `0x0020` for risala, and implementations check it (12.2).
  If IANA assigns another value, the move comes with a new protocol
  version.
- **TLS key exchange:** X25519MLKEM768, value `0x11EC` [ECDHE-MLKEM].
- **MLS extension types,** from the range for private use:
  - `0xF2A1`, the conversation extension, in the group context (12.4);
  - `0xF2A2`, the device binding, in the leaf node of a KeyPackage
    uploaded with KEYPKG ADD (12.3);
  - `0xF2A3`, the profile, in leaf nodes (12.3).
- **MLS proposal type:** `self_remove` [MLS-EXT], whose value is not yet
  assigned by IANA; [MLS-EXT] suggests `0x000A`.
- **MLS extension and component for last-resort KeyPackages** (12.5):
  the `app_data_dictionary` extension, for which [MLS-EXT] suggests
  `0x0006`, holding the `last_resort_key_package` component, `0x0004`.
  Neither is assigned by IANA yet. [MLS-EXT] replaced the earlier
  `last_resort` extension (`0x000A`) with them in draft-11.
- **Signed-note signature type** of the key log's own checkpoint
  signature and of its witnesses' cosignatures: `0x06`, timestamped
  ML-DSA-44 [SIGNED-NOTE] [TLOG-COSIGNATURE] (4.5, 4.10).
- **Key file record types** (4.4): `master` 1, `signing` 2, `device` 3,
  `log` 4 and `retire` 5. **Key log entry types** (4.5): `record` 1 and
  `handoff` 2. The value 0 of each is reserved.
- **Labels.** All of them carry the protocol version (2.4):
  - the MLS exporter labels `risala/1 send` (7.2), `risala/1 pseudonym`
    (7.3) and `risala/1 box` (7.8);
  - the RisalaSign labels `record` (4.4), `pair` (4.8), `keypackage`
    (12.3), `period` and `attest` (12.10), each signed with the prefix
    `risala/1 ` (4.3);
  - the HPKE info strings `risala/1 welcome` and `risala/1 nudge` (12.8);
  - the HKDF info strings `risala/1 identity ` and `risala/1 backup `
    followed by the uid (4.8, 12.13), `risala/1 pair new id`,
    `risala/1 pair new key`, `risala/1 pair old id` and
    `risala/1 pair old key` (4.8), `risala/1 confirm` and
    `risala/1 period seed` (12.10);
  - the associated data `risala/1 pair` (4.8), `risala/1 file` and
    `risala/1 archive` (12.11, 12.13), and the prefix
    `risala/1 backup ` (12.13);
  - the HPKE `info` and `psk_id` `risala/1 pair` (4.8);
  - the sign-in prefix `risala-auth-1` (4.6), and the safety number label
    `risala-fp-1` (12.14).
- **Text formats:** the key file's first line `risala-keys/1` (4.4); the
  first lines `risala-hint/1` and `risala-log-key/1` of the files a key
  log serves (4.5), and `risala-handoff/1` of the hand-off request
  (4.10); the QR code prefixes `RISALA-PAIR:` (4.8) and `RISALA-FP:`
  (12.14); and the key log origin path `/risala-log/<n>` (4.5).
- **HTTPS paths:** under a key log's URL prefix, which is `https://`
  followed by its origin, `risala/uid/<hash>`, `risala/next` and
  `risala/key` (4.5); under a witness's URL prefix, `risala/handoff`
  (4.10).
