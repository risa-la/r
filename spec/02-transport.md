## 2. Transport

### 2.1. Connections

A client opens a TCP connection to the server and starts TLS straight
away. The default port is 7472. There is no unencrypted mode and no
upgrade step.

- Both sides MUST use TLS 1.3 [RFC8446].
- Both sides MUST use the hybrid post-quantum key exchange
  X25519MLKEM768 [ECDHE-MLKEM]. Clients MUST offer it, and servers MUST
  NOT complete a handshake that uses any other key exchange. A server
  SHOULD refuse such a client with the `handshake_failure` alert, so
  that clients can tell the user why. This keeps recorded connections
  secret against a future quantum computer.
  `openssl s_client` offers it by default from OpenSSL 3.5 on.
- The client MUST send the server's hostname using Server Name Indication
  (SNI) [RFC6066]. The server uses this name to choose its certificate.
  The name is also what authentication is bound to, and a server
  accepts sign-ins only on connections whose SNI names it (Section 4.6).
  A client that connects to a bare IP address cannot send SNI, and so
  cannot sign in as an identity.
- Clients SHOULD offer the ALPN [RFC7301] protocol identifier
  `risala/1`. Servers MUST accept connections that offer no ALPN, so that
  tools such as `openssl s_client` work without extra flags. A server
  MUST refuse a client that offers ALPN identifiers but not `risala/1`,
  with the `no_application_protocol` alert, so that a web browser or
  other client sent to the wrong port fails clearly.
- Clients MUST NOT resume TLS sessions or use pre-shared keys, on
  risala connections or on the HTTPS requests they make for risala
  (uploads, blobs and key files: 4.4, 5.6, 12.12). A session ticket
  offered on one connection would tell the server that it comes from the
  same client as the connection that got the ticket, whatever address it
  comes from, and so link anonymous connections to signed-in ones (4.1).
  For the same reason, a client SHOULD NOT send HTTPS requests that
  belong to different risala connections over one HTTPS connection.
  Servers SHOULD NOT issue session tickets.

A server address is a hostname with an optional port, for example
`chat.example.org` or `chat.example.org:7000`. Clients lower-case the
hostname and drop one trailing `.` before using it anywhere: in SNI, as
the key of the trust record (2.2) and in the signed bytes (4.6). So
`Chat.Example.org.` and `chat.example.org` are the same server.

### 2.2. Verifying the Server

Operators SHOULD use a certificate from a public certificate authority,
for example a free one from Let's Encrypt. Nothing special is needed: the
certificate that serves `chat.example.org` on the web also works for
risala on port 7472. Servers SHOULD load renewed certificates without
dropping connections.

For each server address, a client keeps a record of how that server was
verified. The record is one of:

- nothing yet;
- `CA`;
- `pin <fingerprint>`, a pin from trust on first use;
- `strict <fingerprint>`, a strict pin (below), whether the server's
  certificate is CA-valid or not.

It checks the server's certificate as follows:

0. **A strict pin is recorded.** The client accepts a certificate whose
   key has the pinned fingerprint, CA-valid or not. It MUST refuse any
   other certificate, CA-valid or not, and show its fingerprint, until
   the user accepts the new key, which then becomes the strict pin.
1. **The certificate is CA-valid.** The chain validates against the
   client's trusted certificate authorities and matches the hostname
   [RFC9525]. The client accepts it and records `CA`. Without a strict
   pin, the client MUST NOT compare a CA-valid certificate against a
   pin, because ACME clients such as those used
   with Let's Encrypt usually generate a new key at every renewal.
2. **Any other certificate** (self-signed, expired, wrong name or unknown
   authority) is handled by trust on first use:
   - The fingerprint is the SHA-256 hash of the certificate's DER-encoded
     SubjectPublicKeyInfo. It is written as `sha256:` followed by 64
     lower-case hex digits.
   - If nothing is recorded for the server yet, the client MUST show the
     fingerprint and ask the user whether to accept it. If the user
     accepts, the client records `pin <fingerprint>`.
   - If a pin is recorded and matches, the client accepts.
   - If a pin is recorded and does not match, or `CA` is recorded, the
     client MUST refuse the connection and show the fingerprint. The
     user SHOULD have to delete the record explicitly before trying
     again.

A client records `CA` or a pin only after the TLS handshake has
completed, which proves that the server holds the certificate's private
key. Otherwise anyone could replay a server's public certificate to
change the record.

Recording `CA` means an attacker cannot downgrade a server that has a CA
certificate to a trust-on-first-use prompt. A server that moves from a
self-signed certificate to a CA-valid one is accepted under rule 1, and
the client replaces its pin with `CA`. When it replaces a pin this way,
the client SHOULD tell the user once, showing the old fingerprint and
the new certificate's, since whoever can get a certificate for the name,
for example by taking over its DNS, could be behind the change.

Clients SHOULD let users set a **strict pin** for a server, on the key
of the certificate it has just accepted. The client then compares every
certificate, CA-valid or not, against the pinned key (rule 0). An
operator whose users do this keeps the same key across renewals.

Pinning the public key rather than the whole certificate lets an
operator renew a self-signed certificate by keeping its key. Appendix A
shows how to compute a fingerprint for comparison through another
channel.

### 2.3. Lines

After the TLS handshake, both sides exchange lines.

- **Line endings.** A line is a sequence of bytes ending with LF (%x0A).
  A CR (%x0D) directly before the LF is removed. Senders SHOULD end
  lines with LF alone. `openssl s_client` does this by default.
- **Characters.** Lines MUST be valid UTF-8 [RFC3629]. They MUST NOT
  contain control characters (%x00-08, %x0A-1F, %x7F and U+0080 to
  U+009F) apart from TAB (%x09) and the line ending itself.
- **Length.** A line from a client MUST NOT be longer than 8192 bytes
  including the LF. A line from a server MUST NOT be longer than 16384
  bytes. The difference leaves room for the tags a server adds when it
  relays a client's text.
- **Long lines.** Lines that carry MLS data, key files or reports
  (Sections 4, 5.8 and 12) may be longer:
  - From a client, a line whose verb is CREATE, KEYPKG, KEYS, PAIR,
    POST, REPORT or WELCOME may be up to 1 MiB (1048576 bytes)
    including the LF.
  - From a server, a line whose verb is GROUPINFO, KEYPKG, PAIR, POST,
    REPORT or WELCOME may be up to 1 MiB plus 16384 bytes.
  - Anything larger travels as a blob over HTTPS, and the line carries
    its hash instead (12.12).
  - The data that makes these lines long always comes after the verb.
    So the start of every line, up to the end of its verb, MUST fit the
    normal limit, tags included. A receiver can then tell from the first
    8192 or 16384 bytes whether a line may be long. A line whose verb
    does not end within the normal limit is too long.
  - Before a connection has signed in, or become anonymous or a guest
    (4.1), the server applies the normal limits to every line, except
    that REGISTER, KEYS and PAIR may be up to 65536 bytes, for their
    records (4.7) and pairing messages (4.8).
  - The lines inside an encrypted message have their own limits (12.9).
- **Bad lines.** A server that receives a line that is too long MUST
  discard everything up to the next LF and reply `ERR too-long`. It MAY
  reply as soon as it knows the line is too long, before the LF arrives. A server
  that receives a line it cannot parse MUST discard it and reply
  `ERR bad-syntax`. A client SHOULD ignore server lines it cannot parse,
  except that an `OK` or `ERR` line it cannot parse still counts as the
  final response to its command (3.6), as a general failure.
- **Empty lines** are ignored and get no response.

### 2.4. Versions

The protocol has one version number. This document describes version 1,
whose ALPN identifier is `risala/1` (2.1).

- Implementations support at most two versions at once: the current one
  and the one before it.
- A new version is rolled out in order: implementations first learn to
  read it, then write it, then re-encrypt what they store in the old
  one, and only then stop accepting the old one.
- An implementation rejects any message, key, signature or MLS object
  that names a version it does not support. It never falls back to an
  older version that its peer did not ask for.
- Every label that this document puts in front of signed, MACed or
  derived bytes starts with `risala/1 `, such as `risala/1 send` (7.2).
  The two older labels, `risala-auth-1` (4.6) and `risala-fp-1`
  (12.14), carry their version too.
- Every binary structure that this document defines to be sent or
  stored on its own starts with a one-byte `version`, which is 1 here.
  Structures that are only signed, MACed or hashed carry the version in
  their label instead. Text formats, such as key files (4.4), start with
  a line that names their version.
