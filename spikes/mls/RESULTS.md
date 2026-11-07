# MLS spike: can OpenMLS 0.9 do what SPEC.md Section 12 (draft-02) asks?

A throwaway crate, outside the workspace. Run it with:

```
cd spikes/mls
cargo run --release            # every check; full output in output.txt
cargo run --release -- storage # only the storage check
```

Timings are from a release build, single-threaded, on an AMD Threadripper
PRO 5995WX. Phones will be several times slower.

| File | What it holds |
|---|---|
| `src/common.rs` | Suite, device key (one ML-DSA-44 key used as the AUTH signer and the MLS `Signer`), basic credential, the `0xF2A1` extension, group creation, line encodings |
| `src/server.rs` | `KEYPKG ADD`, `INIT` and `COMMIT` checks from 12.4 and 12.5, using only `PublicGroup` |
| `src/history.rs` | 12.8 to 12.10 as written: RisalaMessage, SignWithLabel, ExpandWithLabel, franking, backup blobs |
| `src/libcrux_mldsa.rs` | `openmls_libcrux_crypto` with ML-DSA-44 added from `libcrux-ml-dsa` |
| `src/storage.rs` | `openmls_sqlite_storage` on one file shared by two connections, plus the server's `PublicGroup` |
| `src/main.rs` | The checks |
| `output.txt` | Output of the last full run |

## Results

| # | Point | Result |
|---|---|---|
| 1 | Suite `0x0052` end to end, one key for AUTH and MLS | Works. Needs `openmls_rust_crypto`, or a wrapper around libcrux |
| 2 | Conversation extension `0xF2A1` | Works. Devices must do the name check themselves |
| 3 | Server `PublicGroup` checks, cost at 512 leaves | Works, with caveats (GroupInfo check, leaf lifetimes, credential changes) |
| 4 | External commits, out-of-band tree | Works. OpenMLS removes the joiner's old leaf by itself |
| 5 | History keys and ENC | Works. The spec text has a few ambiguities |
| 6 | Server-originated removals | Not applicable: Section 12 uses no external senders |
| 7 | Sizes | Fits. The worst-case line is 80.5% of 8 MiB |
| 8 | Storage | Works with caveats: `openmls_sqlite_storage` can't link next to rusqlite 0.41 |

### 1. Suite `0x0052`: works, but not on `openmls_libcrux_crypto` alone

```
openmls_libcrux_crypto 0.4.0 supports 0x0052: Err(UnsupportedCiphersuite)
openmls_libcrux_crypto 0.4.0 supported list: [..X25519..Ed25519, ..X25519..Ed25519, MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519]
openmls_rust_crypto 0.6.0 supports 0x0052: Ok(())
```

`openmls_libcrux_crypto` 0.4.0, the newest release, has X-Wing but only
Ed25519 signatures. Its `supports()` rejects any suite that doesn't use
Ed25519. `openmls_rust_crypto` 0.6.0 supports `0x0052`, using RustCrypto
`ml-dsa` 0.1.2 and `hpke-rs-rust-crypto` 0.7 (X-Wing over `ml-kem` 0.3.4
and `x25519-dalek`). The spike uses `openmls_rust_crypto`.

I also checked a libcrux option: `src/libcrux_mldsa.rs` is about 150 lines.
It passes every call through to `openmls_libcrux_crypto` and adds
ML-DSA-44 from `libcrux-ml-dsa` 0.0.11. Check 0b shows it creating a
group, adding a RustCrypto device, receiving a commit back, and agreeing
on the history key. So both providers produce the same messages.

AUTH and MLS share one key:

- `DeviceKey` holds the 32-byte seed. It implements `openmls_traits::signatures::Signer`
  with deterministic ML-DSA-44 and an empty context, and it also signs AUTH.
- Appendix B reproduces byte for byte with both libraries (key SHA-256
  `d9d69ac9…`, signature SHA-256 `eeda7aa7…`).
- A KeyPackage made with that key verifies under the key-file key,
  checked with our own SignWithLabel(`"KeyPackageTBS"`) and plain ML-DSA
  verification. This also cross-checks the SignWithLabel encoding that
  12.8 relies on.
- The credential is `BasicCredential(uid)`, and the signature key is the
  raw 1312-byte public key.
- AUTH bytes begin with `risala-auth-1\n`. MLS SignContent begins with a
  varint label length (`0x15` or `0x16` for these labels). Read as a varint,
  "ri" would give a 12905-byte label, so neither message can parse as the
  other. Section 4.5's claim that the labels keep the two uses apart holds.

Everything below also works:

- `KEYPKG ADD` checks (suite, credential = uid, key = device key,
  signatures, lifetime, `last_resort`).
- INIT, then one commit adding three devices with one Welcome. The
  devices join using the server's tree, passed out of band.
- An empty "refresh" commit.
- A stale commit, which the server rejects as `Stale`.
- History keys agree on every device.

One finding: a last-resort KeyPackage whose leaf doesn't list
`last_resort` (`0x000A`) in its capabilities is rejected
(`UnsupportedExtension`). Devices must list it.

### 2. Conversation extension `0xF2A1`: works

- Encoded as TLS-presentation data. `room r7x2k9qp, shared` is
  `02 08 723778326b397170 01`.
- `RequiredCapabilities[0xF2A1]` in the group context. OpenMLS then
  refuses to add a leaf that doesn't list `0xF2A1` ("The capabilities of
  the add proposal are insufficient").
- Members read it with `group.extensions().unknown(0xF2A1)`. The server
  reads it with `public_group.group_context().extensions()`.
- The server rejects an INIT naming the wrong conversation.
- The owner's GroupContextExtensions commit changing `history` to
  `joined` is accepted. The server reports `SET history`, and Bob reads
  the new value.
- The server rejects the same commit from a non-owner, and rejects a GCE
  that renames the conversation.
- **Caveat:** OpenMLS on Bob's device processes the renaming commit
  without error. The 12.6 rule that devices must reject it is needed,
  and has to be application code.
- OpenMLS refuses to build a GCE that keeps `0xF2A1` but drops
  `required_capabilities`.

### 3. Server side: works, with caveats

`PublicGroup::from_external(tree, GroupInfo)` builds the group at INIT.
`process_message` then `merge_commit` checks and applies each commit
with no private keys. `src/server.rs` implements every rule in 12.5, and
each one is exercised: stale epoch, wrong connection, key missing from
the key file, plain member adding a non-member, removal with no reason
(allowed after KICK), Welcome missing, GroupInfo from the old epoch, GCE
by a non-owner, a 513th leaf.

Caveats:

- **GroupInfo check.** No single OpenMLS call verifies a new-epoch
  GroupInfo against a `StagedCommit`, and `GroupInfo::confirmation_tag`
  and the signer field are crate-private. The spike checks it by hand:
  - The bytes start with `staged.group_context()`.
  - The confirmation tag equals the commit's (`PublicMessageIn::confirmation_tag()`).
  - The `signer` u32 is the committer's leaf, or for an external commit
    `ext_commit_sender_index()`.
  - The signature verifies through the public `Verifiable` trait.
  - It has `external_pub` and no `ratchet_tree`.

  The server can't check the confirmation tag itself, or that path
  secrets decrypt. A member can send a commit the server accepts and
  every other device rejects.
- **Credential changes.** OpenMLS lets a commit's UpdatePath change the
  committer's credential. Bob's device renamed its leaf to
  `carol@example.com`, and Alice's OpenMLS accepted it. The spike's
  server refuses it, but the spec doesn't say to (spec change C).
- **Re-adding a key.** "Add a key that already has a leaf, and remove
  that leaf in the same commit" is rejected by the Remove rule as
  written (spec change D). OpenMLS itself handles Remove + Add of the
  same key fine.
- **Expired lifetimes.** A leaf keeps its KeyPackage's lifetime (default
  12 weeks) until that device commits. Once it has expired:
  - Joining by Welcome fails, and so does joining by external commit
    (`LeafNodeValidation(Lifetime(Expired))`), unless the joiner calls
    `skip_lifetime_validation()`.
  - `PublicGroup::from_external` has no skip option, so the server can't
    rebuild a group from GroupInfo + tree. It must persist the
    `PublicGroup` itself; `PublicGroup::load` doesn't re-check lifetimes.
  - Ordinary commits still work.

Cost at 512 leaves:

| Operation | Time |
|---|---|
| `from_external` (GroupInfo + tree, every leaf verified) | 113 ms |
| Server check + merge: add 1 device | 36 ms |
| Server check + merge: empty commit | 42 ms |
| Server check + merge: remove 4 leaves | 37 ms |
| Server check + merge: external rejoin | 40 ms |
| Server check + merge: add 410 devices in one commit | 206 ms |
| Member applies a commit | 39–44 ms |
| Member joins from Welcome | 105 ms |
| Joiner builds an external commit | 170 ms |
| `PublicGroup::load` from SQLite (JSON codec) | 43 ms |

### 4. External commits and out-of-band trees: works

- `ExternalCommitBuilder::with_ratchet_tree()` and
  `JoinBuilder::with_ratchet_tree()` / `StagedWelcome::new_from_welcome(.., Some(tree))`
  take the tree out of band. No `ratchet_tree` extension was used anywhere.
- **Rejoin with the same key.** OpenMLS adds a Remove for any leaf with
  the joiner's signature key by itself. The commit's proposals were
  `["ExternalInit", "Remove"]`. Leaf count is unchanged, and the stale
  old state sees itself removed. This settles PLAN 19's open point.
- A new device of an identity that has a leaf joined by external commit.
- The other participant of a direct conversation joined by external
  commit with no earlier leaf.
- An identity with no leaf in a room is refused.
- The external `CommitBuilder` can only add PSK proposals, so OpenMLS
  can't build an external commit that removes someone else. OpenMLS
  receivers would accept one, though (`validate_external_commit` leaves
  the Remove check to the application), so the 12.5 / 12.6 rules are needed.
- The joiner must set `LeafNodeParameters` capabilities to include
  `0xF2A1`. The default capabilities fail the group's required capabilities.

### 5. History keys and ENC: works as written

`src/history.rs` implements 12.8 to 12.10 from the text:

- `MLS-Exporter("risala history", "", 48)` is
  `export_secret(crypto, "risala history", b"", 48)`. It agrees on every
  device, and the context matters.
- Bob decrypts and verifies Alice's message.
- Wrong epoch in the AAD, wrong `from` key, a flipped bit and a wrong
  `frank` tag all fail.
- A RisalaMessage with a short TEXT is 2581 bytes (2816 padded to 256).
  The payload is about 3.8 KB of base64. The signature dominates.
- A backup blob is 84 bytes, and opens only for its conversation id and epoch.

OpenMLS exports only for the current epoch. A device must derive each
epoch's history key before it merges the next commit.
`StagedCommit::export_secret` gives the next epoch's key before the merge.

Ambiguities are listed under spec changes I to O.

### 6. Server-originated removals: not applicable

Section 12 has no external senders. Members' devices commit every removal
(12.6), and the server only refuses ENC with `ERR stale` while a leaf it
knows must go is still in the group. That needs nothing more from
OpenMLS. If it's ever wanted, OpenMLS 0.9 has `ExternalSendersExtension`
and `ExternalProposal::new_remove`, but I didn't test them.

### 7. Sizes (base64 characters on the line; 8 MiB = 8388608)

| Item | Size |
|---|---|
| KeyPackage | 11536 |
| GroupInfo (any size of group) | 5092–5156 |
| Commit adding 1 device (adds need no path) | 14976 |
| Welcome for 1 device | 5208 |
| Tree, 2 leaves | 13364 |
| Tree, 100 leaves | 674764 |
| Tree, 512 leaves (parents blank) | 3420940 |
| Tree, 512 leaves, every parent filled (estimate: +511 × ~1270 bytes) | ~4.29 M (51%) |
| Empty commit at 512 leaves, blank parents, so encrypted to ~511 leaves | 834240 (10%) |
| Remove 4 leaves at 512 | 424012 |
| External rejoin at 508 | 803952 |
| Add 410 devices: commit / Welcome | 4735532 / 681424 |
| **Add 511 devices in one commit: whole COMMIT line** | **6752627 (80.5%)** |

All lines fit in 8 MiB. Two cases come close:

- A commit adding about 511 devices. If it also carried a path to ~511
  leaves, it would be ~7.6 M (estimate, 90%).
- A WELCOME line: Welcome plus a full tree is ~4.3 M.

Groups of 512 devices are workable. Per-commit cost is tens of ms on the
server, and a WELCOME or GROUPINFO line is about 3.4 to 4.3 MB.

### 8. Storage: works, with caveats

`openmls_sqlite_storage` 0.3.0 works on a file shared by two connections:

- Each MLS operation runs in `BEGIN IMMEDIATE`. The provider is built on
  `&*tx`, which works because the crate takes `Borrow<Connection>`.
- Rollback undoes a merged commit, so the merge is atomic.
- The other connection gets `database is locked` while the write is in progress.
- A process's in-memory `MlsGroup` goes stale when the other process
  commits. Load it inside every transaction, and never keep it across one.

But it **can't be used in the risala workspace as is**. It pins
rusqlite 0.37 (libsqlite3-sys 0.35), and the workspace uses rusqlite 0.41
(libsqlite3-sys 0.39). Both crates declare `links = "sqlite3"`:

```
package `libsqlite3-sys` links to the native library `sqlite3`, but it conflicts with a previous package which links to `sqlite3` as well:
package `libsqlite3-sys v0.35.0`
    ... which satisfies dependency `libsqlite3-sys = "^0.35.0"` of package `rusqlite v0.37.0`
    ... which satisfies dependency `rusqlite = "^0.37"` of package `openmls_sqlite_storage v0.3.0`
Only one package in the dependency graph may specify the same links value.
```

(From a scratch crate depending on `rusqlite = "0.41"` and `openmls_sqlite_storage = "0.3"`.)

Other notes:

- Its migrations also create virtual-client tables (`vc_*`) whatever the
  features. All tables are prefixed, so they don't collide with
  librisala's.
- With a JSON codec, the 512-leaf group's data is about 9.3 MB, and
  `MlsGroup::load` takes 43 ms. A binary serde codec should be much
  smaller; I didn't measure it.
- **The KeyPackage is lost if a Welcome fails.** OpenMLS deletes an
  ordinary KeyPackage's private keys before it validates the Welcome
  (`keys_for_welcome`). Retrying the same Welcome then gives
  `NoMatchingKeyPackage`. Processing Welcomes inside a transaction that
  is rolled back on failure avoids this.

## Spec changes Section 12 needs

A. **12.2, after the algorithm table.** Pin the HPKE parameters, so an
   independent implementation can match `suite_id`:

   > Within HPKE, the suite uses the KEM `0x647a` (X-Wing as in [XWING]),
   > the KDF HKDF-SHA384 (`0x0002`) and the AEAD ChaCha20-Poly1305
   > (`0x0003`). ExpandWithLabel, SignWithLabel and the MLS exporter use
   > SHA-384. OpenMLS 0.9 names this suite
   > `MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44`.

   **Section 15:** mention the HPKE KEM value next to `0x0052`.

B. **12.2, the capabilities sentence.** Add `last_resort`:

   > Leaves list this type, and `last_resort` (`0x000A`) [MLS-EXT], in
   > their capabilities…

   Otherwise last-resort KeyPackages fail validation, as the spike
   showed. **12.4 `KEYPKG ADD`:** add "that its leaf supports the
   conversation extension" to the list of checks.

C. **12.2 Credentials, new bullet; plus 12.5 rule 4 and 12.6.**

   > A leaf's credential and signature key never change. A commit's path
   > MUST keep the committer's credential and signature key (an external
   > commit's: the joiner's). A device that needs a new key joins as a
   > new device.

   **12.5 rule 4:** add "**The path**, if any, keeps the committer's
   credential and signature key." **12.6 Commits:** add a bullet,
   "changes the credential or signature key of the committer's leaf".
   OpenMLS accepts such a commit, as the spike showed.

D. **12.5 rule 4, Remove.** Allow removal of a key that is being re-added:

   > **Remove** removes a leaf of the committer's own identity, a leaf
   > whose signature key the same commit adds again (see Add), a leaf
   > whose key is no longer in its identity's key file, or, in a room, a
   > leaf of an identity that is neither a member nor invited.

E. **12.5 rule 4, ExternalInit.** Define "own earlier leaf":

   > An external commit may hold at most one Remove, and only of the leaf
   > whose signature key is the joiner's.

   **12.6 Commits:** add "is an external commit that removes a leaf
   other than one with the joiner's signature key". The device rule now
   only requires "the committer's own identity", which is looser than
   the server's.

F. **12.5 rule 2.** Say what "the GroupInfo must match" means, and what
   the server can't check:

   > …and the GroupInfo: its group context is the one the commit
   > produces, its confirmation tag is the commit's, its signer is the
   > committer's leaf in the new epoch, its signature verifies, and it
   > has the `external_pub` extension and no `ratchet_tree` extension.
   > The server cannot check the confirmation tag itself, or that the
   > path's secrets decrypt, so a member can send a commit that the
   > server accepts and other devices reject (12.6).

   **12.5 rule 4, GroupContextExtensions:** "its extension list is the
   group's current one with only the `history` field of the conversation
   extension changed". A GCE replaces the whole list.

G. **12.4 or 12.6: leaf lifetimes.** A new paragraph:

   > A KeyPackage's lifetime is checked when it is uploaded and when it
   > is added. A leaf keeps that lifetime until its device commits, and
   > it may end while the leaf is still in the group. So devices joining
   > by Welcome or external commit, and the server, do not check the
   > lifetimes of leaves already in the tree. A device SHOULD commit a
   > fresh leaf (12.6, Refreshing keys) well before its lifetime ends.

   This departs from the RFC 9420 7.3 SHOULD, so say so. Also consider
   fixing a lifetime, for example at most 12 weeks.

H. **12.6, after "A device that rejects a commit can no longer follow the group".**
   Optionally add:

   > If it rejected the commit only because MLS could not process it,
   > and not for one of the reasons above, it MAY join again by external
   > commit, with the checks for joining.

I. **12.8 step 5: padding.** "Sets `padding` to zero bytes" can mean
   empty or zero-valued. Suggested:

   > Sets `padding` to an empty vector. It SHOULD then fill `padding`
   > with zero-valued bytes so that the encoded RisalaMessage is a
   > multiple of 256 bytes. Receivers ignore the contents of `padding`.

   The varint length prefix grows at 64 bytes, so senders have to search
   for the right length. That's fine, but worth a note or a test vector.

J. **12.8 steps 4, 6 and 7.** Spell out the labels and KDF:

   - Step 4: "SignWithLabel… (the bytes signed are SignContent with the
     label `MLS 1.0 risala message`)".
   - Step 6: "ExpandWithLabel with HKDF-SHA384, using `history_key` as
     the PRK (the full label is `MLS 1.0 risala message key`)".
   - Step 7: "the ciphertext, with its 16-byte tag".
   - Step 8: "HMAC-SHA-384(frank_key, content), over the content bytes
     without their length prefix".

   A test vector in Appendix B (history key, salt, message → payload)
   would settle all of these.

K. **12.8 decrypt step 4.** "If the device was in the group in that
   epoch… the leaf of `from`" means devices must keep each epoch's leaf
   keys. Say so:

   > Devices keep, with each epoch's history key, the signature keys of
   > that epoch's leaves.

L. **12.8 decrypt step 1.** After retention removes COMMIT events (7.5,
   12.11), "the epoch of the latest COMMIT event before it" can't be read
   from history. Add:

   > …or, if those events have expired, from the epochs the device
   > recorded.

M. **12.8 content.** There's no limit on content size, and it's unclear
   whether 2.3's line limits apply to content lines. One 8 MiB ENC line
   holds about 70,000 KEY lines. Suggested:

   > Content lines are not subject to the limits of 2.3. The content is
   > at most 4 MiB. A device sends at most 10000 KEY lines per message.

N. **12.8, ENC.** "decode to at least 48 bytes" is fine as a server check,
   but a real message is never under about 2.5 KB. Optional: say it's a
   sanity bound.

O. **12.9.** Add an implementation note:

   > A device derives an epoch's history key before it applies the next
   > commit, since the exporter is gone afterwards.

P. **12.7 `<tree>`.** "The ratchet tree of the epoch the commit started"
   means the server has to keep a copy of that tree for each commit
   with pending Welcomes, up to about 4.3 MB at 512 leaves. Add:

   > The server keeps that tree while any of the commit's Welcomes is
   > pending.

   Also advise:

   > A device deletes the Welcome only after it has joined.

   OpenMLS consumes the KeyPackage on the first attempt.

Q. **12.5, sizes (optional).**

   > A client that adds many devices SHOULD split them over commits of
   > at most 256 devices.

   This keeps COMMIT lines under about 4 MiB. The 8 MiB limit and the
   512-leaf limit can both stay as they are.

## Crates and features for the real implementation

- `openmls = "0.9.2"`, `openmls_traits = "0.6"`, both with
  `draft-ietf-mls-pq-ciphersuites`. No `test-utils`: use
  `MlsMessageIn::extract()`, since `into_welcome()` and friends are
  test-only.
- Crypto: `openmls_rust_crypto = "0.6"` with
  `draft-ietf-mls-pq-ciphersuites`. It pulls in `ml-dsa` 0.1.2,
  `hpke-rs-rust-crypto` 0.7, `ml-kem` 0.3.4 and `x25519-dalek`. The
  alternative is `openmls_libcrux_crypto = "0.4"` plus
  `libcrux-ml-dsa = "0.0.11"` behind the wrapper in
  `src/libcrux_mldsa.rs`, until upstream adds ML-DSA. Messages are the
  same either way. Run `cargo audit` on whichever is picked; it wasn't
  installed here.
- Device key: the 32-byte ML-DSA seed in the platform keystore. Use our
  own `Signer` impl, deterministic, as in `src/common.rs`. Don't use
  `openmls_basic_credential::SignatureKeyPair`, which would put the
  private key into OpenMLS storage. `BasicCredential` comes from
  `openmls` itself.
- `tls_codec = "0.5"` (the version OpenMLS uses) with `derive` and
  `mls`, for RisalaConversation and RisalaMessage.
- **risalad:** keep each group as a `PublicGroup` in its own SQLite (rusqlite
  0.41) through a small custom `PublicStorageProvider`. It needs about 15
  methods: tree, context, interim transcript hash, confirmation tag and
  proposal queue, with a binary serde codec. Run each COMMIT as
  load → `process_message` → checks → `merge_commit` in one transaction.
  Never rebuild from GroupInfo + tree (lifetimes, see 3).
- **librisala:** `openmls_sqlite_storage` 0.3 can't sit next to rusqlite
  0.41. The options:
  1. Port the crate (2381 lines, MIT) to rusqlite 0.41. Recommended:
     it already takes `Borrow<Connection>`, so it works inside
     librisala's own transactions.
  2. Write a full `StorageProvider`.
  3. Move the workspace to rusqlite 0.37.

  Whichever is chosen, use a binary codec, and wrap each MLS operation
  in `BEGIN IMMEDIATE` with a fresh `MlsGroup::load`. Welcome processing
  goes in a transaction that is rolled back on failure.
- Joining: always call `skip_lifetime_validation()` on `JoinBuilder` and
  `ExternalCommitBuilder`. Set `LeafNodeParameters` capabilities on
  external commits. Use `PURE_PLAINTEXT_WIRE_FORMAT_POLICY` and
  `use_ratchet_tree_extension(false)`.
