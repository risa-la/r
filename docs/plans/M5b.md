# M5b: the zero-trust redesign

The working plan for milestone M5b in [PLAN.md](../../PLAN.md): draft-03
of the spec, reviewed until nothing above Low remains, and the code
rewritten to follow it. The spec (`spec/`, draft-03) is the source of
truth. If this file and the spec disagree, the spec wins: report it
rather than work around it.

The decisions are PLAN.md section 5, items 51-61: item 59 has the order
of the work, and item 60 the choices made while writing draft-03 and
the user's answers to its questions.

## Goal

At the end of M5b:

- A fresh review of the spec, against `../soatok-review.md` and for
  consistency, finds nothing above Low.
- `risala-proto`, `risala-mls`, `risalad`, librisala and `risala-cli`
  follow draft-03, and Appendix B's test vectors match the new formats.
- Two CLI devices talk in an encrypted direct conversation, a private
  room and a public room, over anonymous connections; a third device is
  paired by QR text and gets the history by transfer; an identity is
  recovered from its recovery key; and every key file record a device
  accepts has a witnessed inclusion proof.

**Not in M5b:** light clients (draft-ietf-mls-partial, item 60), which
OpenMLS does not support and whose draft just expired; measuring
ML-DSA and X-Wing on phones (item 59, step 3); the outside review of
epochal signatures; proof of work (M6a, item 42); the apps (M7).

## Decided before starting

On 2026-11-08, with the user:

- **The protocol layers are rewritten** (item 59's open question).
  Keep the crypto, OpenMLS's storage (`openmls-sqlite-storage`), the
  TLS and network code, `risala-keyfetch`, `risala-pow` and general
  utilities. Rewrite the line types in `risala-proto`, the server's
  core and store, and librisala's sync engine, store and client API to
  draft-03, rather than bending M5a's code. Code that still fits may be
  moved over, but nothing is kept only because it exists.
- **No migrations from M5a.** Nothing has been released, so the
  server's and librisala's SQLite schemas start again at version 1.
- **Epochal signatures are built as specified**, since public rooms
  depend on them. The construction still needs its outside review
  (item 53); the code says so where it starts.
- Work happens on branch `m5b`. Nothing is merged into `main` or pushed
  during M5b's run; the user reviews `m5b` first.

## Conventions

[M2-M5.md](M2-M5.md)'s conventions still apply (typed values from
`risala-proto`, `Timestamp::now()` behind a replaceable clock,
`getrandom`, `tracing` without secrets, SQLite in WAL mode with
`user_version`, blocking calls off the async workers). In addition:

- **Builds.** Run cargo only through
  `/home/humaid/repos/risala-m5b/cargo.sh <args>`. It allows two cargo
  runs at a time across all agents, niced and memory-capped, each
  checkout with its own target directory, and waits for a free slot. Never run cargo
  directly, never `nix flake check`, Kani, TLC or fuzzers. Prefer
  `-p <crate>` and targeted tests while working; run the whole
  workspace's tests once before reporting.
- **Git.** Commit on your own branch, in small commits named like the
  existing history (`proto: ...`, `server: ...`, `librisala: ...`,
  `mls: ...`, `Spec: ...`, `Plan: ...`), citing spec sections in
  parentheses. Stage explicit paths only, never `git add -A` or
  `git add .`, and check `git diff --cached --stat` before committing.
  No `Co-Authored-By` lines and no mention of Claude or any AI tool in
  commits. Never merge; never push; never touch `main`.
- **Your files.** Each task lists what it owns. Change other files only
  where your task cannot compile without it, keep such changes minimal,
  and list them in your report.
- **Decisions.** Nobody can be asked during the run. Where the spec is
  silent, ambiguous or impossible to build as written, choose the option
  that trusts the server least and is simplest to change later, mark it
  in the code with a comment citing the section, and list it under
  "Choices to confirm" in your report. Do not edit `spec/` unless your
  task says so.
- **Reviews and audit notes** go in `/home/humaid/repos/risala-m5b/`,
  never in the repo.
- **Tests.** Every behaviour the spec states with MUST gets a test.
  Integration tests use the real server, as before.
- **Report.** End with: branch name and head SHA; what is done and what
  is not; tests run and their results; files outside your task that
  you changed; and "Choices to confirm".

## Tasks

`[ ]` to do, `[~]` started, `[x]` merged into `m5b`. Each task names
the tasks it needs. Tasks with no unmet needs run in parallel, up to
four writing code at once.

### S. Spec review (item 59, steps 2 and 3)

- [x] **S1. Review draft-03, round 1.** Four reviewers at once, each on
  one area, against `../soatok-review.md`'s checklist (section 8), the
  decisions in items 51-61, and the spec's own consistency (every
  command in 13 defined where it points, every format specified to the
  byte, every MUST testable). Findings rated C/H/M/L/I go to
  `/home/humaid/repos/risala-m5b/review-1-<area>.md`.
  - a. Identity: 4.3-4.9, 10.5, 12.14 (key files, the key log, pairing,
    recovery, safety numbers).
  - b. MLS: 12.1-12.10 (credentials, extensions, KeyPackages, commits,
    membership, Welcomes, messages, confirming leaves, epochal).
  - c. Metadata: 2, 4.1-4.2, 5.2, 7, 8, 9 (connections, mailboxes, send
    tokens, pseudonyms, delivery, presence, push).
  - d. Content and operators: 5 (except 5.2), 6, 10, 12.11-12.13, 14,
    Appendix D (files, blobs, transfer, backups, reports, moderation,
    the threat model).
- [x] **S2. Fix round 1.** Fixes go into `spec/`, and new choices into
  PLAN.md item 62. Needs S1.
- [x] **S3. Review again** with two fresh reviewers over the whole spec,
  then fix. At most three rounds in all; what remains above Low after
  that is listed for the user.

### P. `risala-proto`

- [x] **P1. Lines for draft-03.** Rewrite `Command`, `ServerLine` and
  their parameter types to the tables in section 13: add ANON, CREATE,
  POST, FOLLOW, UNFOLLOW, FETCH, KEYS PUT, PAIR, MUTE, GROUPINFO,
  WATCH, BLOB, BACKUP, PRESENCE ON/OFF, GONE, DROP, RECORD and the new
  forms of REGISTER, UPLOAD, REPORT, PUSH, KEYPKG and WELCOME; remove
  the commands and lines draft-03 drops (JOIN, PART, MSG, HISTORY,
  SYNC, RELATED, SET, ROLE, ROLES, INVITE, KICK, BAN, KEY lines, ENC,
  REPORTENC, NAME, TYPING, READ, BLOCK and the rest); connection kinds
  (new, anonymous, guest, signed in) and which commands each may send;
  1 MiB long lines and 64 KiB REGISTER (2.3); error codes (3.7). The
  spec tests (`tests/spec_*.rs`) pass over every example in `spec/`.
  Owns `crates/risala-proto/src/` except the files P2 and P4 own, its
  tests and fuzz targets.
- [x] **P2. Key files and identity formats** (4.3, 4.4, 4.8, 12.14):
  `risala-keys/1` key files, the Record kinds (`master`, `signing`,
  `device`) with `previous` chaining, RisalaSign and its labels, the
  master key's derivation from the recovery key (`risala/1 identity `),
  seed-only import, device ids, PairingCode and its QR text, safety
  numbers (`risala-fp-1`, 40 digits, `RISALA-FP:`), chain checks
  (extends, forks). Owns `crates/risala-proto/src/keyfile.rs`,
  `fingerprint.rs`, `auth.rs` and new modules for records and pairing.
- [x] **P3. The key log crate, `crates/risala-keylog`** (4.5): C2SP
  tlog-checkpoint, signed-note with ML-DSA-44 cosignatures (type
  `0x06`) for the log and its witnesses, tlog-tiles (tile paths,
  hashing, building and reading tiles), inclusion and consistency
  proofs computed from tiles, the witness policy (k of n), and fork
  evidence. Pure library, no I/O beyond traits for fetching tiles.
  Owns the new crate.
- [x] **P4. Content lines** (12.9, 5.3-5.8, 8): the lines inside
  encrypted messages (TEXT with its tags, DELETE, TYPING, READ, REPORT,
  CHALLENGE/ANSWER, ATTEST/REVEAL, BLOCK/UNBLOCK, RECORD/ALERT,
  SIGNINGKEY/BACKUPKEY), as a separate `Content` type with its own
  parser and serialiser. Owns `crates/risala-proto/src/content.rs`.
  Needs P1 (the shared parser).

### M. `risala-mls`

- [x] **M1. Groups** (12.1-12.8): RisalaIdentity credentials, per-group
  leaf keys, the device binding (`0xF2A2`), profile (`0xF2A3`) and
  conversation (12.4) extensions, KeyPackages (with `last_resort` as
  the component `0x0004`: patch OpenMLS as `crates/openmls-traits` was
  if that is small, otherwise keep the extension and report it), groups
  for each kind of conversation, commits with a path, PrivateMessage
  commits outside public rooms, SelfRemove as a PrivateMessage,
  external commits for public rooms, the weekly fresh-leaf commit,
  RisalaAAD, send tokens and their hashes from the exporter, and
  reading group id, epoch, content type and AAD from a message without
  its keys (for the server). Owns `crates/risala-mls/src/` except what
  M2-M4 own.
- [x] **M2. Messages** (12.9): RisalaMessage, counters and `previous`
  for gaps, franking (frank key, the frank in the AAD, constant-time
  checks), MLS padding to 256 bytes, times, past epochs kept for a few
  epochs, deletes. Owns `crates/risala-mls/src/message.rs`. Needs M1,
  P4.
- [x] **M3. Confirming leaves** (12.10): pairwise CHALLENGE/ANSWER with
  X-Wing and HMAC-SHA-384 under `risala/1 confirm`, confirming senders
  only, the 256-member threshold; PeriodCert, per-period leaf keys, ATTEST and REVEAL. Owns
  `crates/risala-mls/src/confirm.rs` and `epochal.rs`. Needs M1.
- [x] **M4. Files, blobs, transfer and backups** (12.11-12.13, 4.8):
  the 64 KiB chunked ChaCha20-Poly1305 format with Padmé and
  `file-hash`, blob refs, HistoryArchive, TransferRef, IdentityBundle
  and its encryption under the pairing secret, backups wrapped under
  the backup key of generation g. Owns `crates/risala-mls/src/file.rs`,
  `archive.rs`, `backup.rs` and `pairing.rs`. Needs nothing.

### SV. `risalad`

- [x] **SV0. Scaffold.** A new store (schema version 1 for draft-03)
  and core: connection kinds, the greeting, ANON and GUEST, command
  routing to one module per area below, each replying `not-supported`;
  M5a's core, store and tests removed where draft-03 replaces them.
  Owns `crates/risala-server/src/core/`, `src/store/`. Needs P1, M1's
  framing reader.
- [x] **SV1. Identity** (4.6-4.9, 10.5): AUTH, REGISTER with a key
  file, KEYS PUT (chain checks, RECORD lines), hosted key files (410
  after UNREGISTER), PAIR PUT/GET (10 minutes), UNREGISTER, ADMIN
  UNREGISTER. Needs SV0, P2.
- [x] **SV2. The key log on the server** (4.5): appending hosted and
  outside records, tiles and checkpoints over HTTPS, the log's ML-DSA
  key, asking witnesses to cosign (C2SP tlog-witness), a checkpoint
  within an hour of a new record and at least daily, and a test
  witness in `risala-dev`. Needs SV0, P3.
- [x] **SV3. Mailboxes and delivery** (5.2, 6.1, 7): CREATE (both
  forms), POST (framing checks, send-token sets for the newest 16
  epochs, pseudonyms, `live`, `groupinfo`, `cid` for 24 hours),
  FOLLOW/UNFOLLOW/FETCH, GROUPINFO and a public room's current tree,
  MUTE/UNMUTE, GONE, DROP, retention (7.5). Needs SV0, M1.
- [x] **SV4. Keys, Welcomes, blobs and backups** (12.5, 12.8, 12.12,
  12.13, 5.6): KEYPKG, WELCOME PUT/GET/LIST/DEL, BLOB and the HTTPS
  blob store, BACKUP, UPLOAD with `del` URLs, bearer secrets stored as
  hashes and compared in constant time. Needs SV0.
- [x] **SV5. Everything else** (6.1, 8, 9, 5.8, 10): LIST, INFO,
  PRESENCE/WATCH/WHOIS/MEMBERS, PUSH (RFC 8291 bodies, mailbox and
  account subscriptions), REPORT and the operators' review, the ADMIN
  commands. Needs SV0.

### C. librisala and `risala-cli`

- [x] **C0. Scaffold.** New store (schema version 1), the signed-in
  connection plus anonymous connections for posting and fetching, the
  client API's shape, module stubs per area below. Needs P1.
- [~] **C1. Identity** (4.3-4.9, 12.14): creating an identity with its
  recovery key, the key file chain, verifying records against the key
  log (witness policy, proofs from tiles, consistency, forks, daily
  watching, RECORD/ALERT), pairing by QR text, recovery, removing a
  device, safety numbers, pins on master keys and logs. Needs C0, P2,
  P3.
- [~] **C2. Conversations** (5, 6, 7, 12.6-12.9): the group engine on
  mailboxes, posting with tokens and pseudonyms, first valid commit
  wins, Welcomes, membership and roles in the group, PART, deletes,
  gaps, profiles, topics, typing and read markers, blocks, guests in
  public rooms. Needs C0, M1, M2.
- [~] **C3. Confirming leaves** in the engine (12.10). Needs C2, M3.
- [~] **C4. Transfer, backups, files, push and reports** (4.8,
  12.11-12.13, 9, 5.8). Needs C2, M4.
- [ ] **C5. `risala-cli` and `risala-dev`** follow the new API, and the
  end-to-end tests in the goal pass. Needs C1-C4.

### V. Test vectors

- [x] **V1. Appendix B** gains vectors for the key file records,
  RisalaSign, safety numbers, the chunked file format, the confirm MAC
  and the backup key wrap, generated by the code and checked by tests.
  Needs P2, M2, M3, M4.

### R. Code review

- [ ] **R1. Review** of M5b's code, one reviewer per crate, with the same
  rules as M5a's review; findings to `/home/humaid/repos/risala-m5b/`.
- [ ] **R2. Fixes.**
