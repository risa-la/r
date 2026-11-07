# risala

```
risala                                                        draft-01
A Line-Based Chat Protocol                                  2026-11-06
Status: Draft. Anything in this document may change.
Copyright (c) 2026 Risala developers. Licensed under CC BY 4.0.
```

## Abstract

risala is a protocol for real-time chat on independent servers. It runs
over TLS and is made of UTF-8 text lines, so a person can use it directly
from a terminal with `openssl s_client`. It provides:

- guest access
- portable identities built on domain names and Ed25519 keys
- stored history that clients can catch up on without gaps
- replies, edits and reactions
- optional file uploads over HTTPS
- push notifications that carry no message content
- a standard set of commands for server operators

Servers do not federate: every conversation lives on exactly one server.

## Contents

1. Introduction
2. Transport
3. Message Format
4. Identity and Authentication
5. Conversations
6. Rooms
7. History and Sync
8. Other Lines
9. Push Notifications
10. Server Administration
11. Keepalive and Closing
12. Command Summary
13. Security Considerations
14. Assigned Values
15. References
- Appendix A. Using risala by Hand
- Appendix B. Test Vectors
- Appendix C. Push Gateways
- Appendix D. Differences from IRC

---

## 1. Introduction

risala follows the shape of IRC: a client connects to one server, picks a
name, joins rooms and exchanges lines of text. It leaves out what makes
IRC hard to use and implement today:

- numeric replies
- capability negotiation
- 512-byte lines
- `nick!user@host` prefixes
- mode letters
- service bots
- server-to-server links
- having no history

It adds what people now expect from chat: identities that work on any
server, stored history, replies, edits, reactions, file sharing and push
notifications.

### 1.1. Goals

- **Usable by hand.** Every feature can be used by typing lines into
  `openssl s_client`. Uploading a file also needs an HTTP tool such as
  `curl`.
- **Small.** A complete client or server is realistic to write in Go,
  Rust or C. A client needs TLS and Ed25519. A server also needs an HTTPS
  client. File uploads are optional and need HTTPS on both sides.
- **Independent servers.** Anyone can run a server. No server is special,
  and nothing depends on central infrastructure.
- **Portable identity.** A person can prove the same identity, such as
  `alice@example.org`, to any server. No server has to trust any other
  server for this.
- **History.** Servers store conversations. A client that reconnects
  fetches exactly what it missed.

### 1.2. Non-goals

This version does not provide:

- **Federation.** Messages never move between servers.
- **End-to-end encryption.** The server can read every message, including
  direct messages.
- **Browser clients.** There is no WebSocket or HTTP transport. Clients
  are native applications.
- **Binary data on the chat connection.** Files, where a server supports
  them, travel over HTTPS (Section 5.6).
- **Group direct conversations.** A conversation is either a direct
  conversation between two people or a room. A group talks in a room,
  which can be private.

### 1.3. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC2119] [RFC8174] when, and only when, they appear in all capitals, as
shown here.

Grammar is written in ABNF [RFC5234]. In examples, `C:` marks a line sent
by the client and `S:` a line sent by the server. These prefixes are not
part of the protocol. Examples use the domain names reserved by
[RFC2606].

### 1.4. Overview

```
$ openssl s_client -connect chat.example.org:7472 -quiet
S: RISALA 1 chat.example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e Welcome!
C: guest sam
S: OK uid=~sam
C: join #general
S: @seq=8812;t=2026-11-06T15:40:58.120Z;from=~sam;id=k3f9q2 JOIN #general
S: SET #general topic General chat. Be kind.
S: SET #general public yes
S: SET #general guests write
S: SET #general retention server
S: OK id=k3f9q2 head=8812
C: history #general before=8812 limit=2
S: @seq=8810;t=2026-11-06T15:30:11.004Z;from=alice@example.org MSG #general anyone around?
S: @seq=8811;t=2026-11-06T15:31:40.950Z;from=bob@example.net MSG #general yep
S: OK id=k3f9q2 more=1
C: @reply=8810 msg #general hi alice, I'm new here
S: @seq=8813;t=2026-11-06T15:41:02.377Z;from=~sam;reply=8810 MSG #general hi alice, I'm new here
S: OK seq=8813
S: @seq=8814;t=2026-11-06T15:41:09.512Z;from=alice@example.org;react=8813 MSG #general 👋
```

In this session:

1. The server greets the client.
2. The client becomes the guest `~sam` and joins `#general`. The server
   answers with the room's settings.
3. The client reads the two messages sent before it joined.
4. It replies to one of them.
5. It receives a reaction to its reply.

Every stored event carries a sequence number (`seq`), a time (`t`) and an
author (`from`).

---

## 2. Transport

### 2.1. Connections

A client opens a TCP connection to the server and starts TLS straight
away. The default port is 7472. There is no unencrypted mode and no
upgrade step.

- Both sides MUST use TLS 1.3 [RFC8446].
- The client MUST send the server's hostname using Server Name Indication
  (SNI) [RFC6066]. The server uses this name to choose its certificate.
  The name is also what authentication is bound to (Section 4.5). A
  client that connects to a bare IP address cannot send SNI, and so
  cannot sign in as an identity.
- Clients SHOULD offer the ALPN [RFC7301] protocol identifier
  `risala/1`. Servers MUST accept connections that offer no ALPN, so that
  tools such as `openssl s_client` work without extra flags. A server
  MUST refuse a client that offers ALPN identifiers but not `risala/1`,
  with the `no_application_protocol` alert, so that a web browser or
  other client sent to the wrong port fails clearly.

A server address is a hostname with an optional port, for example
`chat.example.org` or `chat.example.org:7000`.

### 2.2. Verifying the Server

Operators SHOULD use a certificate from a public certificate authority,
for example a free one from Let's Encrypt. Nothing special is needed: the
certificate that serves `chat.example.org` on the web also works for
risala on port 7472. Servers SHOULD load renewed certificates without
dropping connections.

For each server address, a client keeps a record of how that server was
verified: nothing yet, "CA", or a pinned fingerprint. It checks the
server's certificate as follows:

1. **The certificate is CA-valid.** The chain validates against the
   client's trusted certificate authorities and matches the hostname
   [RFC9525]. The client accepts it and records "CA". The client MUST NOT
   compare a CA-valid certificate against a pin, because ACME clients
   such as those used with Let's Encrypt usually generate a new key at
   every renewal.
2. **Any other certificate** (self-signed, expired, wrong name or unknown
   authority) is handled by trust on first use:
   - The fingerprint is the SHA-256 hash of the certificate's DER-encoded
     SubjectPublicKeyInfo. It is written as `sha256:` followed by 64
     lower-case hex digits.
   - If nothing is recorded for the server yet, the client MUST show the
     fingerprint and ask the user whether to accept it. If the user
     accepts, the client records the fingerprint as the server's pin.
   - If a pin is recorded and matches, the client accepts.
   - If a pin is recorded and does not match, or "CA" is recorded, the
     client MUST refuse the connection and show the fingerprint. The
     user SHOULD have to delete the record explicitly before trying
     again.

A client records "CA" or a pin only after the TLS handshake has
completed, which proves that the server holds the certificate's private
key. Otherwise anyone could replay a server's public certificate to
change the record.

Recording "CA" means an attacker cannot downgrade a server that has a CA
certificate to a trust-on-first-use prompt. A server that moves from a
self-signed certificate to a CA-valid one is accepted under rule 1, and
the client replaces its pin with "CA".

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
- **Bad lines.** A server that receives a line that is too long MUST
  discard everything up to the next LF and reply `ERR too-long`. A server
  that receives a line it cannot parse MUST discard it and reply
  `ERR bad-syntax`. A client SHOULD ignore server lines it cannot parse,
  except that an `OK` or `ERR` line it cannot parse still counts as the
  final response to its command (3.6), as a general failure.
- **Empty lines** are ignored and get no response.

---

## 3. Message Format

### 3.1. Grammar

```abnf
line       = [ tags SP ] verb [ SP params ] [ CR ] LF
tags       = "@" [ tag *( ";" tag ) ]
tag        = tag-key [ "=" tag-value ]
tag-key    = 1*( %x61-7A / DIGIT / "-" )        ; a-z 0-9 -
tag-value  = 1*( %x21-3A / %x3C-7E / UTF8-nonascii )
                                                ; no space, no ";"
verb       = 1*ALPHA                            ; case-insensitive
params     = *( HTAB / %x20-7E / UTF8-nonascii )
                                                ; split as in 3.3
UTF8-nonascii = UTF8-2 / UTF8-3 / UTF8-4        ; from RFC 3629, but
                                                ; not U+0080-009F (2.3)
```

Verbs are case-insensitive, so `msg` and `MSG` mean the same. Servers
send verbs in upper case. This document writes client commands in upper
case too. Receivers SHOULD accept runs of spaces between the tags and the
verb, as between tokens (3.3).

Tag keys are always lower case. Elsewhere, where the ABNF in this
document lists only `a-z` for something case-insensitive, such as option
keys, names and keywords, it describes the form after folding:
receivers fold ASCII upper case to lower case first.

### 3.2. Tags

Tags carry metadata: the sequence number, time and author of an event,
the target of a reply or reaction, and the id that matches a response to
its command.

- The order of tags does not matter. A line MUST NOT repeat a tag key.
- A lone `@` carries no tags. Receivers MUST accept it, and senders
  SHOULD leave it out.
- Receivers MUST ignore tags they do not understand.
- From a client command, a server copies only `reply`, `edit`, `react`
  and `file` onto the event the command causes.
- Tag keys that begin with `x-` are reserved for experiments.

| Tag | Set by | Value | Meaning |
|---|---|---|---|
| `ref` | client | tag value, at most 64 bytes | Matches a response to its command (3.6) |
| `seq` | server | sequence number | The event's position in its conversation (5.2) |
| `t` | server | timestamp | When the server accepted the event or report |
| `from` | server | uid | Who caused the event, or who made the report |
| `reply` | client | sequence number | The message being replied to (5.3) |
| `edit` | client | sequence number | The message being edited (5.3) |
| `react` | client | sequence number | The message being reacted to (5.3) |
| `file` | client | URL | A file attached to the message (5.6) |
| `file-type` | server | media type | The attached file's media type (5.6) |
| `file-size` | server | bytes | The attached file's size (5.6) |
| `cid` | client | tag value, at most 64 bytes | Client message id for safe resending (7.6) |
| `deleted` | server | none | The event's content was removed (5.4) |
| `retry` | server | seconds | With `ERR rate-limited`: when to try again |
| `report` | server | id | The report that a line belongs to (5.8) |
| `id` | server | id | On a JOIN event: the room's id (6.1) |

### 3.3. Parameters

Each verb defines its own parameters. There are three kinds:

- A **token** is one or more characters other than space and TAB.
- An **option** is a token of the form `key=value`. Options come after a
  verb's tokens, in any order, and are optional unless stated otherwise.
  A command MUST NOT repeat an option.
- **Text** is the rest of the line after the space that follows the last
  token. It may contain spaces and may be empty. When it is empty, that
  space may be left out.

A verb either ends with text or takes options, never both. Text is
always last, so no quoting is needed.

Senders MUST separate tokens with exactly one space. Receivers SHOULD
accept runs of spaces between tokens. Once all tokens are read, text
starts after exactly one space, so any further leading spaces belong to
the text. For a verb that takes no text, receivers ignore spaces after
the last token, so `LIST ` means `LIST`.

```abnf
option     = option-key "=" option-value
option-key = 1*( %x61-7A / DIGIT / "-" )        ; a-z 0-9 -
option-value = 1*( %x21-7E / UTF8-nonascii )    ; any token, "=" allowed
```

Option keys are case-insensitive, like verbs. An option's value ends at
the next space, so values such as URLs may contain `=`.

Numbers, such as counts, sizes, limits and numbers of days, are written
in decimal, without a sign or leading zeros:

```abnf
number     = "0" / %x31-39 *18DIGIT             ; 0 to 2^63-1
```

A server MUST reply `ERR bad-syntax` to a command that has too few or
too many tokens, or that has an option the server does not know.

In the syntax lines of this document:

- `<name>` is a token and `[<name>]` an optional token.
- `key=` is an option.
- `<name...>` is text, and `[<name...>]` text that may be empty.

### 3.4. Text Escaping

Text cannot contain a line break, so three rules apply:

- `\n` stands for a line break.
- `\\` stands for one backslash.
- Any other backslash stands for itself.

Escapes are read left to right. So `one\ntwo` is two lines, `C:\Users`
stays as it is, and `\\n` is a backslash followed by the letter "n".

Servers store and relay text exactly as received. Length limits apply to
the escaped form. Clients unescape text only to display it. Clients MUST
NOT interpret text as HTML. They MAY render common plain-text
conventions such as `code` and *emphasis*.

### 3.5. Names

```abnf
name       = alnum [ *30( alnum / "." / "_" / "-" ) ( alnum / "_" / "-" ) ]
alnum      = %x61-7A / DIGIT                    ; a-z 0-9
guest      = "~" name
identity   = name "@" domain
domain     = label 1*( "." label )              ; A-labels [RFC5890]
label      = alnum [ *61( alnum / "-" ) alnum ]
uid        = guest / identity
room       = "#" alnum [ *62( alnum / "." / "_" / "-" ) ( alnum / "_" / "-" ) ]
conv       = room / uid
seq        = %x31-39 *18DIGIT                   ; 1 to 2^63-1
id         = 1*64( alnum / "-" / "_" )          ; conversation or report id
timestamp  = full-date "T" time-hour ":" time-minute ":"
             time-second "." 3DIGIT "Z"         ; RFC 3339, UTC
```

- Timestamps are always UTC, with milliseconds. Senders write `T` and
  `Z` in upper case, and receivers MAY accept lower case. Seconds run
  from 00 to 59: leap seconds are not used.
- A **uid** identifies a user. It is either a guest such as `~sam`
  (Section 4.2) or an identity such as `alice@example.org` (4.3).
- A **conv** names a conversation. It is either a room, or the other
  person in a direct conversation (5.1).
- Names and rooms never end with `.`, so a full stop after one in a
  sentence is never part of it.
- A domain is at most 253 characters long, and its last label MUST NOT
  be all digits. So an IP address is never a domain.
- Names are case-insensitive. Servers fold ASCII upper-case letters in
  commands to lower case, and always send names in lower case.
- Display names (8.2) are separate free text. They are not names in the
  sense of this section.

### 3.6. Responses

Every command gets exactly one final response: `OK` or `ERR`. The one
exception is PONG, which gets no response.

```
OK [<key>=<value> ...]
ERR <code> [<message...>]
```

- **Order.** A server handles each connection's commands in the order
  they arrive, and sends their final responses in that order.
- **Matching.** A client matches each final response to its oldest
  command that has none yet. If a final response carries a `ref` that
  does not belong to that command, the client can no longer tell which
  response belongs to which command. It SHOULD close the connection and
  reconnect.
- **Results.** An `OK` may carry result values as options, for example
  `OK seq=8813`. Clients MUST ignore result values they do not know.
- **Error messages.** The `<message...>` of an ERR is for people to read.
- **Response lines and `ref`.** Some commands return lines before their
  final response, such as the events HISTORY returns or the lines LIST
  returns. If the command had a `ref` tag, the server copies it onto
  these lines and onto the final response. This includes the `ERR` for a
  command it cannot parse, as long as it can still read a valid `ref`
  from the line's tags.
- **Live events.** Events that a command causes, such as the event a MSG
  creates, are not part of its response. They go to every connection in
  the conversation without `ref`. The connection that sent the command
  receives them before its final response.

```
C: @ref=7 history #general after=8811 limit=2
S: @ref=7;seq=8812;t=2026-11-06T15:40:58.120Z;from=~sam;id=k3f9q2 JOIN #general
S: @ref=7;seq=8813;t=2026-11-06T15:41:02.377Z;from=~sam;reply=8810 MSG #general hi alice, I'm new here
S: @ref=7 OK id=k3f9q2 more=1
```

### 3.7. Error Codes

| Code | Meaning |
|---|---|
| `bad-syntax` | The line could not be parsed, or has the wrong parameters |
| `unknown-command` | The verb is not known |
| `too-long` | The line or one of its parameters is too long, or a file is too large |
| `not-authenticated` | The command needs GUEST, AUTH or REGISTER first |
| `already-authenticated` | This connection is already a guest or signed in |
| `auth-failed` | The signature did not verify, or the key file could not be fetched |
| `name-taken` | The guest name or identity name is already in use |
| `not-found` | The room, user or message does not exist, or is not visible to you |
| `forbidden` | Not allowed because of permissions, a ban or server policy |
| `last-owner` | The only owner of a room cannot give up the role |
| `not-supported` | The server does not offer this feature |
| `rate-limited` | Too many requests. The `retry` tag says when to try again |
| `internal` | Something went wrong on the server |

A name, room, id, text, URL or tag value that follows its grammar except
for being too long gets `too-long`, not `bad-syntax`. A number, key or
signature with the wrong number of digits or characters gets
`bad-syntax`.

Clients MUST treat an unknown code as a general failure.

### 3.8. Extending the Protocol

- **New verbs** may be added. Servers reply `ERR unknown-command` to
  verbs they do not know, and clients ignore lines with verbs they do not
  know. An unknown subcommand of a known verb, such as `KEY FOO`, also
  gets `ERR unknown-command`, so a client can tell it apart from a
  mistake in a known one.
- **New information on an existing verb** goes in tags. The tokens and
  text of the verbs defined here never change.
- **New options and result values** may be added. Servers reject unknown
  options (3.3), so a client can tell whether a server supports an
  option.
- **Versions.** The greeting carries a protocol version (4.1). Any change
  that breaks the rules of this document requires a new version. A
  client that does not support the server's version MUST close the
  connection.

---

## 4. Identity and Authentication

### 4.1. The Greeting

As soon as TLS is set up, the server sends:

```
RISALA <version> <host> <nonce> [<message...>]
```

- `<version>` is `1` for this document.
- `<host>` is the hostname from SNI, in lower case. If the client sent
  no SNI, it is the server's own main hostname.
- `<nonce>` is 16 to 64 bytes from a cryptographically secure random
  source, written in lower-case hex. It is unique to this connection.
- `<message...>` is an optional welcome text, at most 512 bytes.

A new connection is not yet a guest or an identity. Until it becomes
one, the server accepts only INFO, GUEST, AUTH, REGISTER, PING, PONG and
QUIT. It replies `ERR not-authenticated` to anything else.

A connection signs in once. To become someone else, reconnect. Servers
SHOULD allow at least 120 seconds to sign in, which leaves time to sign
a challenge by hand (Appendix A).

### 4.2. Guests

```
GUEST <name>
```

→ `OK uid=~<name>`

A guest's uid lasts only as long as its connection. Once that connection
closes, another guest may take the same name, so a guest uid says
nothing about who someone is over time. For this reason guests:

- cannot take part in direct conversations
- cannot create rooms, hold roles, be invited, set read markers, block
  anyone, upload files or register for push
- stay members of the rooms they join only until they disconnect. At
  that point the server records a PART for each of those rooms.

The server replies `ERR name-taken` if a connected guest already has the
name. A guest that reconnects can get this for its own name, if the
server has not yet noticed that its old connection is gone (Section 11).
Clients SHOULD then try another name, for example by adding a number. It MAY also reserve names, for example the names of identities it
hosts. It MAY refuse guests entirely with `ERR forbidden`.

### 4.3. Identities

An identity looks like an email address, for example
`alice@example.org`. Whoever controls the key file at this URL controls
the identity:

```
https://example.org/.well-known/risala/alice
```

A server accepts `alice@example.org` when the client proves it holds one
of the private keys listed in that file. Nothing else is involved. No
server is in charge of any identity, and a server never asks another
chat server about a user.

An identity's domain and the chat server are independent of each other.
`alice@example.org` can use `chat.example.org`, `chat.example.net` or
any other server.

### 4.4. Key Files

A key file is UTF-8 text. Each line lists one key:

```
ed25519 <key> [<label...>]
```

- `<key>` is the 32-byte Ed25519 public key [RFC8032], in base64 with
  padding [RFC4648]. It is 44 characters long.
- `<label...>` is an optional note for people, usually the name of the
  device.
- Blank lines and lines starting with `#` are ignored.
- Lines with a key type other than `ed25519` are ignored, so that new key
  types can be added later.

Each device SHOULD have its own key. Revoking a lost device's key means
deleting its line.

```
# alice@example.org
ed25519 J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY= laptop
ed25519 xOANpWbIg5OCt//dfeEit/1AngQtJJdLe4ks1mxhd5M= phone
```

When a server fetches a key file:

- It MUST use HTTPS and validate the certificate against public
  certificate authorities.
- It MUST NOT follow redirects. Only a 200 response counts. Any other
  response means the identity has no keys.
- It MUST stop after 10 seconds or 64 KiB. A file that is larger, or
  that does not arrive in time, means the identity has no keys.
- It MUST use at most 64 keys: the first 64 different, valid `ed25519`
  keys in the file. Repeated keys, malformed lines and ignored lines do
  not count toward the 64.
- It MUST NOT connect to loopback, private, link-local or other
  special-purpose addresses [RFC6890] unless its operator has configured
  it to. Users choose the domain, so without this rule they could make
  the server probe its own internal network.
- It MAY cache the file for up to one hour. If a signature does not
  verify against a cached file, the server SHOULD fetch the file again
  once before failing, so that a newly added device works straight away.

A server that notices a key has been removed SHOULD close the
connections that signed in with it.

### 4.5. Signing In

```
AUTH <identity> <signature>
```

→ `OK uid=<identity>`

Guests do not sign in, so a guest uid gets `ERR bad-syntax`.

The client signs these bytes with its device's private key:

```
"risala-auth-1" LF host LF nonce LF uid LF
```

- `host` is the hostname the client connected to, exactly as it sent it
  in SNI, in lower case. The client MUST use its own value, not the one
  in the greeting.
- `nonce` is the nonce from the greeting.
- `uid` is the identity, in lower case.

`<signature>` is the 64-byte Ed25519 signature, in base64 with padding.
It is plain Ed25519, with no prehash and no context. Appendix B has a
worked example.

The server checks the signature as follows:

1. It builds the same bytes, using this connection's SNI hostname and
   nonce.
2. It gets the identity's keys. If it hosts the identity itself (4.6), it
   uses its own records. Otherwise it fetches the key file (4.4).
3. It accepts if the signature verifies under any of those keys.

On success the server replies `OK uid=<uid>`, and adds `op=yes` if the
identity is a server operator (Section 10). The key that verified becomes
the connection's **device key**, which push notifications use (Section
9). On failure the server replies `ERR auth-failed`.

Each part of the signed bytes has a job:

- **The first line** keeps the signature from meaning anything in
  another protocol.
- **The host** stops a server from using a signature it received to sign
  in somewhere else. Without it, a malicious server could pass another
  server's nonce to the client, then use the client's answer to sign in
  there as that user.
- **The nonce** stops replay.
- **The uid** ties the signature to one identity.

Any AUTH or REGISTER command that parses uses up the connection's nonce,
whether it succeeds or not. To try again, reconnect.

### 4.6. Registration

A server MAY host identities under a domain it controls, called its
**identity domain**. For example, `chat.example.org` might host
`<name>@example.org`. A server that does this MUST publish each
identity's key file at the URL given in Section 4.3. It can serve the
files itself or place them on a web server. To every other server, these
are ordinary identities.

INFO reports a server's identity domain (8.5).

```
REGISTER <name> <key> <signature>
```

→ `OK uid=<name>@<identity domain>`

This creates the identity `<name>@<identity domain>`, with `<key>` as its
first key. The client learns the identity domain from INFO (8.5) first.
It computes `<signature>` as in Section 4.5 using that uid, and the server verifies it with `<key>`. This proves the client
holds the private key. If it succeeds, the identity exists and the
connection is signed in as it.

Errors:

- `not-supported`: this server does not offer registration.
- `name-taken`: the name is already registered.
- `auth-failed`: the signature did not verify.
- `forbidden`: for example, registration is closed.

If someone loses all the keys of an identity the server hosts, an
operator can add a new key for them with `ADMIN ADDKEY` (10.5). How the
operator checks who is asking is outside the scope of this document.

### 4.7. Managing Keys

These commands work only for identities that the server itself hosts.
Other people edit their key file directly.

```
KEY LIST
KEY ADD <key> [<label...>]
KEY DEL <key>
```

- `KEY LIST` sends one `KEY <key> [<label...>]` line per key, then OK.
- `KEY ADD` adds a key. To set up a new device, the new device shows its
  public key, and the user adds it from a device that is already signed
  in.
- `KEY DEL` removes a key. The server MUST refuse to remove the last key
  (`ERR forbidden`). It SHOULD close the connections that use the
  removed key.

### 4.8. Deleting an Identity

```
UNREGISTER <uid> [purge=yes]
```

→ `OK`, then the server closes all of the identity's connections

Deletes everything the server keeps about the identity the connection
is signed in as. `<uid>` MUST be that identity (`ERR forbidden`
otherwise). Having to type it out guards against sending UNREGISTER by
mistake. Any identity may do this on any server.

The server removes the identity from all its rooms, and deletes its
roles, read markers, blocks, display name, cids and push registrations.
Then:

- **With `purge=yes`,** the server also deletes every message the
  identity has sent, in every conversation, as if by DELETE (5.4). The
  DELETE events have the identity as `from`.
- **Without it,** messages it has sent stay. The other participant in a
  direct conversation keeps that conversation.
- **Rooms:** if the identity was a room's only owner, the room is left
  without one. An operator can give it a new owner (Section 10).
- **Hosted identities (4.6):** the server also deletes the identity's
  keys and key file. It SHOULD NOT let anyone register the name again,
  for the reason given in Section 10.5.
- **Other identities** are only forgotten by this server. If the same
  identity signs in again later, the server treats it as new.

Guests have nothing to delete. What a guest has sent can be removed only
by DELETE, or by an operator (10.4).

---

## 5. Conversations

### 5.1. Kinds of Conversation

- A **room**, such as `#general`, has any number of members (Section 6).
- A **direct conversation** is between two identities. Each side names it
  by the other person's uid: Alice talks to `bob@example.net`, and Bob
  talks to `alice@example.org`. It starts with the first message. A
  conversation with yourself, for example for notes, is named by your
  own uid.

There are no other kinds. There are no group direct conversations: a
group of people talks in a room, which can be private (6.2).

Every conversation has an **id**, an opaque token chosen by the server
when the conversation starts. The server MUST NOT give the same id to
two conversations, even after one of them is gone. A name can outlive a
conversation: when an operator drops a room (10.4) and someone creates a
room with the same name, the new room gets a new id. Clients use the id
to tell the two apart (7.1). SYNC, JOIN and INFO report it.

Direct conversations are only for identities (4.2), and only with
identities the server knows, meaning they have signed in to it at least
once. Otherwise the server replies `ERR not-found`. To limit spam, a
server MAY restrict who can start one, for example to people who share
a room (`ERR forbidden`).

### 5.2. Events

Every change to a conversation is an **event**. The server numbers each
conversation's events 1, 2, 3 and so on. There are no gaps, and numbers
are never reused. This number is the event's sequence number, sent in
the `seq` tag. The server stores events and returns them through HISTORY
(Section 7).

An event line looks like this:

```
@seq=<seq>;t=<timestamp>;from=<uid>[;<tag>...] <VERB> <conv> [<parameters>]
```

- `seq`, `t` and `from` MUST be present on every event.
- An event has the same parameters as the command that caused it. A
  guest's automatic PART has no reason text.
- In a room, `<conv>` is the room.
- In a direct conversation, `<conv>` is the other participant, as seen
  by whoever receives the line. It is therefore always the uid to send
  to in order to reply. When Alice sends `MSG bob@example.net hi`:
  - her own devices receive `from=alice@example.org MSG bob@example.net hi`
  - Bob's devices receive `from=alice@example.org MSG alice@example.org hi`

  In a conversation with yourself, `<conv>` is your own uid. The rule
  holds whoever `from` is, including an operator who deletes a message
  (10.4). The server writes each line of a direct conversation for the
  person receiving it, in live events and in HISTORY alike.

The event verbs are MSG and DELETE (this section), and JOIN, PART,
INVITE, KICK, BAN, UNBAN, SET and ROLE (Section 6).

The server sends each new event straight away to every connection in
the conversation. For a room, that means the connections of all its
members, including guests who joined it on that connection. For a direct
conversation, it means the connections of both participants. Either way,
it includes the author's own connections. Within one conversation,
events arrive in sequence order. There is no ordering across
conversations.

A **snapshot line** has the same form as an event but no `seq`, `t` or
`from`. It describes current state rather than a change, like the SET
lines after JOIN in Section 1.4. Snapshots use only the verbs SET, BAN
and ROLE. A client can apply snapshots and events with the same code.

### 5.3. Messages

```
MSG <conv> <text...>
```

→ `OK seq=<seq>`

Sends a message. The text MUST NOT be empty. Text made only of spaces,
TABs and line breaks, once unescaped, counts as empty. The sender's connection
receives the message's event before the OK, so a client can match the
two by seq.

A message may carry at most one of these tags. The server copies it onto
the event. A `reply` may also carry a `file` (5.6).

- `reply=<seq>` replies to message `<seq>`.
- `edit=<seq>` replaces the text of message `<seq>`. Only the author of
  `<seq>` may edit it. An edit is a message in its own right, with its
  own seq. Clients show the text of the newest edit in the original's
  place. They MAY also show every earlier version. All versions stay in
  history, and anyone who can read the conversation can see them.
- `react=<seq>` reacts to message `<seq>`. The text is the reaction,
  usually a single emoji, and MUST be at most 64 bytes. To take a
  reaction back, delete it (5.4). If a user sends the same reaction to
  the same message twice, the server SHOULD reply OK with the existing
  reaction's seq and not create a new event.

The target `<seq>` MUST be a message in the same conversation. It MUST
NOT be deleted, and MUST NOT itself be an edit or a reaction. Otherwise
the server replies `ERR not-found`. A reply may target another reply.

A client that does not understand these tags still shows the text, so
older clients degrade gracefully: an edit appears as a new message and a
reaction as a short message.

Members of a room who are allowed to post (6.3) may send messages to it.
Both participants of a direct conversation may send messages in it.
Anyone else gets `ERR forbidden`.

### 5.4. Deleting Messages

```
DELETE <conv> <seq>
```

→ `OK seq=<seq of the DELETE event>`

Deletes message `<seq>`. The author may delete their own messages. In
rooms, moderators and owners may delete any message (6.3). Only MSG
events can be deleted.

The server records a `DELETE <conv> <seq>` event and MUST erase the
stored text of the target. The one exception is the copy kept for an
open report (5.8). What else happens depends on the target:

- Deleting a message also deletes its edits, its reactions and its
  attached file (5.6). Replies to it stay.
- Deleting an edit makes the previous version current again.
- Deleting a reaction removes it.

Deleting a message that is already deleted gets `ERR not-found`.

A deleted event keeps its place in history, so there are no gaps.
HISTORY returns it with the `deleted` tag and empty text. It keeps its
`seq`, `t` and `from`, and any `reply`, `edit` or `react` tag. It loses
its `file`, `file-type` and `file-size` tags, since the file is gone:

```
S: @seq=8813;t=2026-11-06T15:41:02.377Z;from=~sam;reply=8810;deleted MSG #general
```

Clients SHOULD discard deleted text they have stored. Deletion cannot
reach copies that people have already made.

### 5.5. Mentions

A mention is `@` followed by a uid, for example `@alice@example.org` or
`@~sam`. The `@` must be at the start of the text or follow whitespace,
after unescaping. The mention is the longest uid that follows the `@`.
Uids never end with `.` (3.5), so in `thanks @~sam.` the mention is
`~sam`.

Servers use mentions to decide when to send push notifications (Section
9). Clients SHOULD highlight mentions of the user. They SHOULD also let
users type a display name and insert the matching uid.

### 5.6. Files

Servers MAY support file uploads. INFO reports the largest file allowed
as `upload=<bytes>`, or `upload=no` (8.5). Files never travel over the
chat connection. They go over HTTPS, so a client that uploads or
downloads files also needs an HTTPS client.

```
UPLOAD <size> <type> <name...>
```

→ `OK put=<url> get=<url>`

Asks to upload a file of `<size>` bytes, with the media type `<type>`
(for example `image/png`) and the file name `<name...>`. `<type>` is
`type/subtype` as in [RFC6838], without parameters such as
`;charset=utf-8`, since it is copied into the `file-type` tag. Media
types are case-insensitive. Only identities
can upload. Sharing a file takes three steps:

1. The client sends UPLOAD. The server replies with two URLs: `put` to
   upload the file to, and `get` to download it from.
2. The client sends the file in an HTTP PUT request to the `put` URL, with
   a matching `Content-Length` and `Content-Type`. A 2xx response means
   the server has stored it.
3. The client sends a message with the tag `file=<get URL>`. The text is
   a caption, or the file name if there is no caption.

```
C: upload 48213 image/png cat.png
S: OK put=https://files.example.org/u/7Qm2xV9pLk4sT8wBn5RyHu get=https://files.example.org/f/k3JxR8vN2qYd6hWaP0tZcE/cat.png
   (the client PUTs the 48213 bytes to the put URL)
C: @file=https://files.example.org/f/k3JxR8vN2qYd6hWaP0tZcE/cat.png msg #general look at this
S: @seq=8815;t=2026-11-06T15:42:30.001Z;from=alice@example.org;file=https://files.example.org/f/k3JxR8vN2qYd6hWaP0tZcE/cat.png;file-type=image/png;file-size=48213 MSG #general look at this
S: OK seq=8815
```

Rules for uploads:

- **The `put` URL** works for one upload within 10 minutes. The server
  MUST reject a body whose length differs from `<size>`.
- **Size and type.** A file larger than the server allows gets
  `ERR too-long`. A media type the server refuses gets `ERR forbidden`.
- **Storage.** Both URLs may point anywhere. A server can keep files on
  its own disk or hand out presigned URLs for object storage.

Rules for messages with files:

- **Which URL.** `file` MUST be a `get` URL from this server's UPLOAD,
  uploaded by the same identity. Each upload can be attached to only one
  message. Otherwise the server replies `ERR not-found`.
- **Metadata.** The server adds `file-type` and `file-size` to the event,
  from what it stored.
- **One file per message.** `file` can be combined with `reply`, but not
  with `edit` or `react`. An edit can change a file message's text, but
  not its file.
- **Older clients** that do not support files show only the text.

Rules for `get` URLs:

- They MUST use `https`, MUST NOT contain `;`, and MUST be at most 512
  bytes, so that they fit in a tag.
- They are capabilities: anyone who has one can download the file. They
  MUST therefore contain at least 128 bits of randomness. A file in a
  private room is only as private as its URL.

When files are removed:

- Deleting a message deletes its file (5.4).
- Files expire together with their messages (7.5).
- A server MAY delete a file that was never attached to a message after
  24 hours.

### 5.7. Blocking

```
BLOCK <target>
UNBLOCK <target>
BLOCKS
```

- `<target>` is an identity, such as `spam@example.net`, or a whole
  domain, written `*@example.net`. A domain block also covers the
  domain's subdomains, as in Section 10.2.
- BLOCK and UNBLOCK reply `OK`. BLOCKS sends one `BLOCK <target>` line
  per block, then `OK`.
- A block belongs to the account and applies to all its devices. Nobody
  else can see it. Only identities can block.

A block applies to direct conversations only. While U has blocked
someone:

- Neither of them can send messages or typing notifications in their
  direct conversation, and the blocked person cannot start one with U.
  The server replies `ERR forbidden`, the same reply as when server
  policy does not allow a direct conversation (5.1).
- Their existing direct conversation stays, and both can still read it.
- Rooms are not affected on the server, since everyone in a room sees
  the same history. However, the blocked person's mentions of U and
  replies to U's messages do not count as notable for push (9.2).
- Clients SHOULD offer to hide a blocked person's messages in rooms as
  well. They do this themselves, without involving the server.

### 5.8. Reporting

```
REPORT <conv> <seq> [<reason...>]
```

→ `OK id=<id>`

Reports message `<seq>` as abusive to the people who can act on it, its
**reviewers**:

- for a room: the room's owners and moderators, and the server's
  operators
- for a direct conversation: the server's operators

Rules for REPORT:

- Anyone who can read the message may report it, guests included.
- The target MUST be a message (a MSG event, which includes edits and
  reactions) that is not deleted (`ERR not-found`). It MUST NOT be your
  own (`ERR forbidden`).
- `<reason...>` is free text of up to 512 bytes.
- If the same uid reports the same message again, the server replies
  with the existing report's id.
- Servers SHOULD rate-limit reports.

When a report is made, the server keeps a copy of the reported event
until the report is resolved, even if the message is deleted or expires
in the meantime. This is an exception to Sections 5.4 and 7.5. Without
it, someone could remove what they sent as soon as it is reported. The
server SHOULD discard the copy when the report is resolved. It MAY
close reports on its own after a time it chooses.

Reviewers receive each report as two lines: a REPORT line with the same
parameters as the command, and the reported event as it was when it
was reported. Both carry the `report` tag with the report's id:

```
S: @report=p4x8n2;t=2026-11-06T15:44:10.230Z;from=bob@example.net REPORT #general 8816 spam
S: @report=p4x8n2;seq=8816;t=2026-11-06T15:43:58.019Z;from=~spammer MSG #general cheap pills at …
```

- On the REPORT line, `t` is when the report was made, and `from` is
  the reporter.
- Only operators see `from` on REPORT lines. Room owners and moderators
  get the line without it, so that reporters cannot be singled out.
- Both lines name a direct conversation as the reporter sees it, so
  `<conv>` is the author on both. The two participants are the reporter
  (`from` on the REPORT line) and the author (`from` on the event).
- The server sends the two lines to every reviewer's connections when
  the report is made.
- The event line is a copy for review. Clients MUST NOT treat it as a
  new event in the conversation.

```
REPORTS <room>
ADMIN REPORTS
RESOLVE <id>
```

- **`REPORTS <room>`** sends the two lines of each open report in the
  room, then `OK`. It is for the room's owners and moderators, and for
  operators.
- **`ADMIN REPORTS`** sends the lines of every open report on the
  server, in rooms and direct conversations, then `OK`. It is for
  operators only.
- **`RESOLVE <id>`** closes a report, and replies `OK`. Any of the
  report's reviewers may resolve it. The server sends `RESOLVED <id>` to
  the other reviewers' connections, so that their lists stay current.

Resolving a report does nothing else. Reviewers act on a report with
the ordinary commands, such as DELETE, KICK, BAN or ADMIN BAN, and then
resolve it.

---

## 6. Rooms

### 6.1. Joining and Leaving

```
LIST [after=<room>] [limit=<n>]
```

→ one `ROOM <room> <members> [<topic...>]` line per public room (6.2),
then `OK more=<0 or 1>`

- `<members>` is the number of members.
- A guest's LIST leaves out rooms whose `guests` setting is `none`.
- Rooms come in order of name, compared byte by byte.
- **`after`** returns only rooms whose names sort after `<room>`, which
  need not exist. To fetch the next page, send LIST again with `after`
  set to the last room returned.
- **`limit`** is at least 1 and defaults to 100. A server MAY return
  fewer rooms than asked for. `more=1` means there are more rooms after
  the last one returned.

```
JOIN <room>
```

→ JOIN event, then snapshot SET lines, then `OK id=<id> head=<seq>`

Every JOIN event carries the room's id (5.1) in the `id` tag, live and in
HISTORY. An identity's other devices also receive its JOIN, and one of
them may still have history from an older room of the same name, for
example one that was dropped while that device was kicked. A device that
receives a JOIN whose `id` differs from the id it has stored for the room
discards what it has stored, as in 7.1, before storing the event.

- **The room exists and you may join it.** The server records a JOIN
  event, sends the room's settings as snapshot SET lines, and replies
  `OK id=<id> head=<seq>`, where `<id>` is the room's id (5.1) and
  `<seq>` its newest seq.
- **You are already a member.** The server sends the settings and the OK,
  but records no event.
- **The room does not exist.** The server MAY create it, if the user is
  an identity and server policy allows. The creator becomes the room's
  owner, and their JOIN is event 1. Otherwise the server replies
  `ERR not-found`.

Who may join:

- Anyone not banned may join a public room.
- Joining a private room takes an invitation (6.4), unless you hold the
  role owner or mod in it (6.3).
- Guests may join only rooms whose `guests` setting is not `none`.

A room you cannot see, meaning a private room you are not a member of
and hold no role or invitation in, gets `ERR not-found`, as if it did
not exist. A room you can see but may not join, for example because you
are banned or are a guest and its `guests` setting is `none`, gets
`ERR forbidden`. INFO, HISTORY and RELATED follow the same rule for
rooms you may not read.

An identity stays a member across connections until it leaves. After
signing in, it receives live events for all its rooms without joining
them again.

```
PART <room> [<reason...>]
```

→ PART event, then `OK`

Leaves the room. Owners and moderators keep their role when they leave
(6.3). Guests leave all their rooms automatically when they disconnect.

A room goes on existing when its last member leaves. Nothing about it
changes: its history, settings, roles, invitations and bans all stay.
Its owners and moderators can join it again at any time, and so can
server operators (Section 10). Only ADMIN DROP (10.4) deletes a room.

### 6.2. Settings

```
SET <room> <key> [<value...>]
```

→ SET event, then `OK seq=<seq>`

| Key | Values | Default | Who may change it |
|---|---|---|---|
| `topic` | any text up to 512 bytes, may be empty | empty | mods, owners |
| `public` | `yes` or `no` | `yes` | owners |
| `guests` | `none`, `read` or `write` | `write` | owners |
| `retention` | a number of days, or `server` | `server` | owners |

- `public yes`: LIST shows the room, and anyone may join.
- `public no`: LIST does not show the room, and joining takes an
  invitation.
- `guests none`: guests cannot join or read.
- `guests read`: guests may join and read, but not send.
- `guests write`: guests may also send messages. This is the default, so
  anyone can connect and talk straight away. If guests start sending
  spam, an owner can switch the room to `read`.
- `retention <days>`: events older than this many days are deleted
  (7.5). The value MUST be at least 1, and MUST NOT be longer than the
  server's own retention period (`ERR forbidden`). Shortening it also
  applies to events already stored.
- `retention server`: the room follows the server's retention period.

Keyword and number values ignore trailing spaces, so `SET #r public yes `
works. A topic keeps its spaces. An unknown key gets
`ERR not-supported`.

```
INFO <room>
```

→ snapshot SET lines, then
`OK id=<id> members=<n> head=<head> role=<role> joined=<yes or no>`

- `<id>` is the room's id (5.1).
- `<head>` is the room's newest seq, or `0` if it has no events yet. A
  room that the server creates itself, for example from its
  configuration, has none until someone joins it.
- `<role>` is your role in the room (6.3): `owner` or `mod` if you hold
  one of those roles, `member` if you are a member without one, and
  `none` otherwise.
- `joined` says whether you are a member right now. An owner or
  moderator who has left has `joined=no`.

### 6.3. Roles

Each identity in a room has one of three roles: `owner`, `mod` or
`member`. Guests are always `member`. Whoever creates a room is its
first owner.

The roles `owner` and `mod` belong to the identity, not to its current
membership:

- Someone who leaves with PART keeps the role. They can join again
  without an invitation, even in a private room, and have the role back.
- KICK and BAN take the role away.
- A room therefore never loses its owners because they left.

| Action | member | mod | owner |
|---|---|---|---|
| Send messages; edit, react to and delete your own | ✓ | ✓ | ✓ |
| Delete anyone's messages | | ✓ | ✓ |
| Set `topic` | | ✓ | ✓ |
| INVITE, KICK, BAN, UNBAN, BANS | | ✓ | ✓ |
| Set `public`, `guests` and `retention` | | | ✓ |
| ROLE | | | ✓ |

- Moderators may kick and ban only plain members. Owners may act on
  anyone, including other owners.
- Guests in a room with `guests read` cannot send messages, reactions or
  typing notifications.
- Server operators (Section 10) have owner rights in every room, and may
  join any room without an invitation.

```
ROLE <room> <uid> <role>
```

→ ROLE event, then `OK seq=<seq>`

The target must be an identity that is a member of the room, or that
holds the role `owner` or `mod` in it. Setting the role of someone who
has left to `member` takes their role away. If an owner is the room's
only owner, they cannot change their own role (`ERR last-owner`).

```
ROLES <room>
```

→ one snapshot `ROLE <room> <uid> <role>` line per owner and moderator,
whether or not they are members right now, then `OK`

ROLES requires permission to read the room (7.2).

### 6.4. Moderation

```
INVITE <room> <uid>
KICK <room> <uid> [<reason...>]
BAN <room> <uid> [<reason...>]
UNBAN <room> <uid>
BANS <room>
```

- `INVITE` records an INVITE event, which lets an identity join a private
  room. The event also goes to the invitee's connections, so their
  client can offer to join. The invitation lasts until it is used or the
  invitee is banned. Guests cannot be invited.
- `KICK` removes a member. They may join again.
- `BAN` removes a member, if they are one, and stops them from joining.
  Banning a guest uid has little effect, because guest names get reused.
  A server MAY ban the guest's network address instead.
- `UNBAN` lifts a ban.
- `BANS` lists the current bans as snapshot `BAN <room> <uid>
  [<reason...>]` lines, then OK.

INVITE, KICK, BAN and UNBAN reply `OK seq=<seq>`. The KICK or BAN event
also goes to its target, before the target stops receiving the room.
An INVITE event that reaches an invitee who is not a member, and a KICK
or BAN event that reaches its target, are notifications. They do not
make the receiver a member, and a client that is not a member does not
store them as the room's history.
For moderation across a whole server, see Section 10.

---

## 7. History and Sync

### 7.1. SYNC

```
SYNC
```

→ one `CONV <conv> <id> <head> <read>` line per conversation, then `OK`

SYNC lists every conversation the connection is in, both rooms and direct
conversations:

- `<id>` is the conversation's id (5.1).
- `<head>` is the conversation's newest seq.
- `<read>` is the account's read marker (7.4), or `0` if there is none.
  It is always `0` for guests.

A connection receives live events for its conversations from the moment
it signs in. So every event newer than the head that SYNC reports is
delivered live, and nothing falls in between.

For each conversation, a client keeps the id it has stored (5.1) and a
**sync point**: the seq up to which it has every event the server still
keeps. Events it has stored beyond the sync point, such as live events
that arrived while it was catching up, do not move it. This matters when
a connection drops in the middle of catching up: the newest seq stored
can then lie past a gap, while the sync point stays before it.

A client catches up like this:

1. Sign in, then send SYNC.
2. For each conversation whose `<id>` differs from the id the client has
   stored for it, the client discards what it has stored for that
   conversation and sets its sync point to 0 (see below).
3. For each conversation, let L be its sync point. If L is less than
   `<head>`, send `HISTORY <conv> after=L`, and repeat while the response
   says `more=1`. After each page, the sync point moves to the last seq
   in it, and on over any stored events that directly follow.
4. If the gap is large, the client MAY instead fetch only the newest page,
   and load older pages when the user scrolls back (7.3). The sync point
   then stays where it was until the gap is filled.
5. Live events may arrive in the meantime. A duplicate has the same seq
   as the event already received, so it can be dropped. A live event
   moves the sync point only if it directly follows it.
6. A client MUST NOT store a live event for a conversation until it has
   learned that conversation's id on this connection, from SYNC, JOIN or
   INFO. Before then it cannot tell which room the event belongs to.
   HISTORY returns such events later.

A client MAY download the whole history of its conversations for reading
offline. Sequence numbers make the download easy to resume.

If a conversation the client knows about is missing from SYNC, the
account is no longer in it. It may have left, been kicked or banned, or
an operator may have dropped the room (10.4).

A room that was dropped can later be created again under the same name.
The new room has a new id, and its sequence numbers start again at 1. A
client that missed the DROP notices the new id and starts the room
afresh, instead of mixing the two rooms' histories. The client also
discards what it has stored when the head a server reports is lower than
the newest seq it has stored for that id. This cannot happen with a
correct server, but it keeps the client consistent.

### 7.2. HISTORY

```
HISTORY <conv> [after=<seq>] [before=<seq>] [limit=<n>]
```

→ events in ascending seq order, then `OK id=<id> more=<0 or 1>`

`<id>` is the conversation's id (5.1). A room can be dropped and created
again while a HISTORY request is on its way (10.4), and then the events
come from the new room. A client that gets an `id` other than the one it
has stored for the conversation discards the page, and starts the
conversation afresh as in 7.1.

- **With `after`:** the earliest `limit` events whose seq is greater than
  `after` (and less than `before`, if it is given). `more=1` means there
  are more events after the last one returned, and below `before` if it
  is given.
- **Without `after`:** the latest `limit` events whose seq is less than
  `before`, or the latest of all events if `before` is not given.
  `more=1` means there are older events before the first one returned.
- **`limit`** defaults to 50. A server MAY return fewer events than
  asked for. `more` says whether there are more.
- `after` may be `0`, which a client with nothing stored uses to read
  from the start (7.1). `before` and `limit` are at least 1.

You may read the history of:

- rooms you are a member of
- public rooms you are allowed to join, so you can look before joining
- your direct conversations

Guests may read rooms whose `guests` setting is `read` or `write`.

Deleted events come back as placeholders (5.4). Events that the server
has removed under its retention policy (7.5) do not come back at all. If
the first event returned is later than `after` + 1, the events in
between have expired.

### 7.3. Edits and Reactions of Older Messages

```
RELATED <conv> <first> <last> [after=<seq>] [limit=<n>]
```

→ events in ascending seq order, then `OK id=<id> more=<0 or 1>`, where
`<id>` is checked as for HISTORY (7.2)

An edit or reaction (5.3) has a later seq than the message it targets,
often a much later one. A client that loads older history one page at a
time therefore has the messages of a page, but not necessarily their
edits and reactions. RELATED returns them:

- It returns every edit and every reaction whose target seq is between
  `<first>` and `<last>`, inclusive. If `<first>` is greater than
  `<last>`, it returns none.
- Deleted edits and reactions come back as placeholders (5.4), so a
  client can remove ones it has stored.
- **`after`** returns only events whose seq is greater than `after`,
  which may be `0`. `more=1` means there are more. To fetch the rest, send RELATED again
  with `after` set to the last seq returned.
- **`limit`** defaults to 50, as in HISTORY.
- The same rules about who may read apply as for HISTORY (7.2).

```
C: history #general before=4001 limit=2
S: @seq=3999;t=2026-10-02T09:12:40.118Z;from=alice@example.org MSG #general lunch?
S: @seq=4000;t=2026-10-02T09:13:02.551Z;from=bob@example.net MSG #general sure, at 12
S: OK id=k3f9q2 more=1
C: related #general 3999 4000
S: @seq=4003;t=2026-10-02T09:14:10.902Z;from=bob@example.net;edit=4000 MSG #general sure, at 12:30
S: @seq=8790;t=2026-11-06T15:20:31.004Z;from=~sam;react=3999 MSG #general 🍕
S: OK id=k3f9q2 more=0
```

A client needs RELATED only for ranges whose later events it has not all
stored. A client that has every event up to the head already has every
edit and reaction.

A reply's target (`reply=<seq>`) may also be outside what the client has
loaded. The client fetches it with
`HISTORY <conv> before=<seq + 1> limit=1`. If the event that comes back
has a lower seq, the target has expired.

### 7.4. Read Markers

```
READ <conv> <seq>
```

→ `OK`

Sets the account's read marker for the conversation to `<seq>`.

- The marker only moves forward. A lower value is ignored. A value
  beyond the conversation's head sets the marker to the head.
- The server sends `READ <conv> <seq>` to the account's other connections,
  so they can update their unread counts. This line is not an event.
- Read markers are private to the account. Nobody else sees them.
- Only identities can set read markers.

### 7.5. Retention

A server MAY delete events older than a retention period, which INFO
reports (8.5). A room may set a shorter period of its own (6.2).
Whichever period is shorter applies. So if a server later shortens its
period below a room's, the server's period applies to that room.

The sequence numbers of expired events are never reused. Files expire
together with the messages they are attached to (5.6). Copies kept for
open reports do not expire (5.8).

### 7.6. Resending Safely

A connection might drop after a client sends MSG but before the OK
arrives. The client then cannot know whether the message went through.
To make resending safe:

- A client MAY tag MSG with `cid=<token>`. The token is a random value
  of at least 16 characters, chosen anew for each message.
- If the same identity has already sent a message with that cid in the
  last 24 hours, to the same conversation, the server MUST NOT create a
  new event. It replies `OK seq=<seq>` with the existing message's seq.
  It checks the cid before anything else about the message, so this
  holds even if the sender has since left the room or the reply target
  has been deleted.
- "The same conversation" means the same id (5.1). After a room is
  dropped and created again (10.4), a cid from the old room does not
  match, so a resent message is sent to the new room. Otherwise the
  client would be given the seq of someone else's event.
- For guests, the server checks cids only within one connection.
- The cid is not part of the event.

---

## 8. Other Lines

### 8.1. Typing

```
TYPING <conv>
```

→ `OK`

Tells the other people in a conversation that you are typing. The server
sends `@from=<uid> TYPING <conv>` to their connections. It is not stored
and has no seq. In a direct conversation, `<conv>` follows the same rule
as for events (5.2).

A typing notification lasts 6 seconds, so clients repeat it about every 4
seconds while the user types. A message from the same user ends it.

### 8.2. Display Names

```
NAME [<name...>]
```

→ `OK`

Sets your display name on this server. With no text, it clears your
display name. A display name is any text up to 128 bytes, for example
"Alice Martin" or "عائشة". The server sends `@from=<uid> NAME
[<name...>]` to the connections that share a conversation with you. A
guest's display name lasts as long as its connection.

Display names are not unique and prove nothing, since anyone can call
themselves anything. Clients SHOULD show the uid whenever two people in
a conversation share a display name, and whenever the user asks.

### 8.3. Members and Users

```
MEMBERS <room>
```

→ one `MEMBER <room> <uid> <role> <presence> [<name...>]` line per
member, then `OK`

```
WHOIS <uid>
```

→ `USER <uid> <presence> [<name...>]`, then `OK`

- `<presence>` is `online` if the user has at least one open connection,
  and `offline` otherwise.
- `<name...>` is the user's display name.
- MEMBERS requires permission to read the room (7.2).
- WHOIS replies `not-found` for a user the server does not know, and for
  a guest who has left.

When identities come online or go offline, the server tells the people
who share a conversation with them:

```
PRESENCE <presence> <uids>
```

```
S: PRESENCE online alice@example.org,bob@example.net
S: PRESENCE offline carol@example.com
```

- `<presence>` is `online` or `offline`, as above.
- `<uids>` is one or more uids, separated by commas with no spaces.
  Uids cannot contain commas.
- PRESENCE is not stored and has no seq.
- The server sends it to the connections of everyone who shares a room
  or a direct conversation with each of the listed users. A connection
  receives only the uids it shares a conversation with.
- The server SHOULD collect changes for a short time, up to a few
  seconds, and send them together, so that one line covers many users.
  It splits a list that does not fit within the line length limit (2.3)
  over several lines.
- The server SHOULD wait about 30 seconds after a user's last
  connection closes before reporting them `offline`, so that a client
  reconnecting does not make them blink off and on.
- PRESENCE covers identities only. A guest is online for as long as it
  is a member, and its PART (4.2) says when it leaves.

A client learns the current presence of members from MEMBERS and of
others from WHOIS, then keeps it current with PRESENCE. Future versions
may add presence values. A client SHOULD show an unknown value as
`online`.

### 8.4. Notices

```
NOTICE <message...>
```

The server may send a notice at any time with information for people,
such as planned downtime. Notices are not stored. Clients show them to
the user.

### 8.5. Server Information

```
INFO
```

→ `OK <values>`

INFO is allowed before signing in. It returns these values:

| Value | Meaning |
|---|---|
| `version=1` | The protocol version |
| `guests=yes` or `guests=no` | Whether guests are allowed |
| `register=<domain>` or `register=no` | The identity domain for REGISTER, or `no` if the server offers no registration |
| `retention=<days>` or `retention=forever` | How long events are kept |
| `push=yes` or `push=no` | Whether PUSH is supported |
| `upload=<bytes>` or `upload=no` | The largest file UPLOAD accepts, or `no` if the server offers no uploads (5.6) |

`INFO <room>` is described in Section 6.2.

---

## 9. Push Notifications

Phones do not let apps keep connections open in the background. Push
lets a server wake an app when something needs attention. In risala, a
push says only that something happened. The app then connects and
fetches the rest itself, over TLS. A push carries no message text,
sender, conversation or server name.

### 9.1. Registering

```
PUSH ADD <url> <tag>
PUSH DEL <url>
PUSH LIST
```

- **`PUSH ADD`** asks the server to send pushes for this account to
  `<url>`, an `https` URL of at most 512 bytes, while this device is not
  connected.
  - `<tag>` is an opaque token of at most 64 bytes, chosen by the client.
    The server includes it in every push, so the app knows which server
    and account the push is about.
  - Clients SHOULD choose a random tag for each registration, so that the
    tag tells the push service nothing.
  - Adding a URL that is already registered replaces its tag.
- **`PUSH DEL`** removes a registration.
- **`PUSH LIST`** sends one `PUSH <url> <tag>` line for each of this
  device's registrations, then OK.

A registration belongs to the device key of the connection that made it
(4.5). Removing the key removes its registrations. Only identities can
register for push. A server MAY limit the number of registrations per
key.

### 9.2. When to Push

For an identity U, a **notable event** is a message from someone else,
whom U has not blocked (5.7), that:

- is in a direct conversation with U (reason `dm`)
- mentions U in a room U is a member of (reason `mention`)
- replies to one of U's messages (reason `reply`)

Edits and reactions are never notable.

U's **unread count** is the number of notable events, across all U's
conversations, that are newer than U's read marker in their
conversation.

When a notable event happens, the server pushes to each of U's
registrations whose device key has no open connection.

A connection can still look open after its device has lost the
network, until the idle timeout closes it (Section 11). That could hold
back pushes for minutes. So when a registration's device key does have
open connections, the server checks that they are alive:

1. On each of those connections that it has received nothing on in the
   last 10 seconds, the server sends `PING`.
2. If 10 seconds later none of the device's connections has sent a line
   since the check began, the server pushes as if the device had no
   open connection.

The server leaves those connections open, and the idle timeout closes
them. A mobile client SHOULD send QUIT when the app goes to the
background and stops reading from its connection, so that pushes start
straight away.

The server SHOULD send at most one push per registration every 10
seconds. Events that happen in between go into the next push.

When U's unread count goes down because of a READ from any device, the
server MAY push with the reason `read`, so that apps can clear
notifications they have already shown.

### 9.3. The Push Request

```
POST <url> HTTP/1.1
Content-Type: text/plain; charset=utf-8

NOTIFY <tag> <reason> <unread>
```

The body is one line in the format of Section 3, ending with LF.
`<reason>` is `dm`, `mention`, `reply` or `read`, and `<unread>` is the
unread count. A reason is 1 to 32 characters of `a-z`, `0-9` and `-`.
Later versions may add reasons. A gateway forwards a
NOTIFY with a reason it does not know unchanged, and an app treats it as
new activity: it connects and syncs as for any other push.

When sending a push, the server:

- MUST use HTTPS and validate the certificate
- MUST NOT follow redirects
- MUST apply the address restrictions of Section 4.4
- SHOULD give up on a request after 10 seconds

How the server handles the response:

- **2xx:** the push was accepted.
- **404 or 410:** the server MUST delete the registration.
- **Any other failure:** the server SHOULD retry with increasing delays,
  and MAY delete the registration after a day of failures.

When an app receives a push, it does the following:

1. It uses the tag to find which server and account the push is about.
2. It connects to that server, signs in and sends SYNC.
3. It fetches what is new and shows its own notification.

If the app cannot finish in time, it shows a generic notification such
as "New activity". Appendix C explains how this works with Apple's and
Google's push services.

---

## 10. Server Administration

Every server has one or more **operators**: identities that may use the
ADMIN commands in this section. Standard commands mean any client can
offer administration tools for any server.

- Anyone who is not an operator gets `ERR forbidden` for every ADMIN
  command.
- A server MAY leave out commands that do not apply to it and reply
  `ERR not-supported`. For example, a server that hosts no identities has
  no use for the commands in Section 10.5.
- Operators also have owner rights in every room through the ordinary
  commands of Section 6. They may join any room without an invitation.
  Their actions in rooms are recorded as events like anyone else's.
- The ADMIN commands themselves create no events, except PURGE (10.4).

### 10.1. Operators

```
ADMIN OPS
ADMIN OP <uid>
ADMIN DEOP <uid>
```

- **`ADMIN OPS`** sends one `OP <uid>` line per operator, then OK.
- **`ADMIN OP`** makes an identity an operator. Guests cannot be
  operators.
- **`ADMIN DEOP`** removes an operator. Operators named in the server's
  configuration cannot be removed this way (`ERR forbidden`).

A server's first operators come from its configuration. An identity
learns it is an operator from the `op=yes` value when it signs in (4.5).

### 10.2. Bans

```
ADMIN BAN <target> [<reason...>]
ADMIN UNBAN <target>
ADMIN BANS
```

A server-wide ban applies on top of room bans (6.4). `<target>` is one
of these:

| Target | Example | Effect |
|---|---|---|
| An identity | `spam@example.net` | That identity cannot sign in |
| A domain | `*@example.net` | No identity at that domain, or at any of its subdomains, can sign in |
| A connected guest | `~sam` | Bans the network address the guest is connected from |
| A network address or prefix | `203.0.113.7`, `2001:db8::/32` | No guest can connect from it |

- **Identity and domain bans.** AUTH and REGISTER reply `ERR forbidden`
  for a banned identity. A banned identity's open connections are closed
  with BYE. A domain ban is useful because one domain can mint any
  number of identities.
- **Address bans** apply only to guests. People with identities who
  happen to share an address with a spammer, such as at a university or
  on a mobile network, are not affected. Ban identities one at a time or
  by domain instead.
- **Banning a guest** also closes the guest's connection. BANS lists the
  ban under the address it applies to.
- **Banning deletes nothing.** Use ADMIN PURGE (10.4) to remove what a
  user has sent.
- **`ADMIN BANS`** sends one `SERVERBAN <target> [<reason...>]` line per
  ban, then OK.

### 10.3. Connections

```
ADMIN WHO
ADMIN DISCONNECT <uid> [<reason...>]
ADMIN NOTICE <message...>
```

- **`ADMIN WHO`** sends one `CONNECTION <uid> <address> <since>` line per
  open connection, then OK. `<address>` is the client's IP address,
  optionally with its port, written `203.0.113.7:51000` or
  `[2001:db8::1]:51000`. `<since>` is a timestamp. A connection that has not signed in yet is
  shown with the uid `-`.
- **`ADMIN DISCONNECT`** closes every connection of `<uid>`, sending
  `BYE` with the reason. The user can reconnect; ban them to stop that.
- **`ADMIN NOTICE`** sends `NOTICE <message...>` to every open connection.

### 10.4. Rooms and Content

```
ADMIN ROOMS [after=<room>] [limit=<n>]
ADMIN DROP <room> [<reason...>]
ADMIN PURGE <uid> [hours=<n>]
ADMIN REPORTS
```

- **`ADMIN ROOMS`** lists every room, private ones included, as
  `ROOM <room> <members> [<topic...>]` lines, then `OK more=<0 or 1>`.
  It pages like LIST (6.1).
- **`ADMIN DROP`** deletes a room together with all of its events and
  files. This cannot be undone.
  - Every member is removed from the room, as if kicked. The room's
    roles, invitations and bans are deleted too.
  - The server sends `DROP <room> [<reason...>]` to every connection in
    the room. No event is recorded, since the room's events are gone.
  - The room stops appearing in SYNC.
  - Clients SHOULD remove the room and the history they have stored for
    it.
  - The name becomes free. If anyone creates a room with it later
    (6.1), that is a new room with a new id, whose sequence numbers
    start again at 1. Clients that missed the DROP notice the new id
    (7.1). Links that name a seq in the old room (Section 14) do not
    carry over, and may point to a different message in the new room.
- **`ADMIN PURGE`** deletes the messages `<uid>` has sent, in every
  conversation.
  - Each message is deleted as if by DELETE (5.4), with the operator as
    the DELETE event's `from`.
  - With `hours=<n>`, only messages from the last `<n>` hours are
    deleted. For a guest uid, the purge covers messages sent under that
    name, which is why `hours` is useful there.
  - The server replies `OK deleted=<count>`.
- **`ADMIN REPORTS`** lists every open report (5.8).

### 10.5. Hosted Identities

These commands act on identities the server hosts (4.6). They let an
operator help someone who has lost all their keys, or remove an account.

```
ADMIN KEYS <uid>
ADMIN ADDKEY <uid> <key> [<label...>]
ADMIN DELKEY <uid> <key>
ADMIN UNREGISTER <uid>
```

- **`ADMIN KEYS`** lists an identity's keys as `KEY <key> [<label...>]`
  lines (4.7), then OK.
- **`ADMIN ADDKEY`** and **`ADMIN DELKEY`** work like KEY ADD and KEY DEL
  (4.7), but for any hosted identity. DELKEY may remove the last key,
  which locks the identity.
- **`ADMIN UNREGISTER`** deletes a hosted identity, as UNREGISTER (4.8)
  without `purge=yes` does. The server removes its key file and closes
  its connections. Messages it has sent stay unless they are purged.
  - The server SHOULD NOT let anyone register the same name again. Other
    servers would take the new owner for the old one.

### 10.6. Server Settings

```
ADMIN SET <key> [<value...>]
```

| Key | Values | Meaning |
|---|---|---|
| `guests` | `yes` or `no` | Whether guests may connect |
| `registration` | `open` or `closed` | Whether REGISTER is accepted |
| `retention` | a number of days, or `forever` | The server's retention period (7.5) |
| `welcome` | any text up to 512 bytes | The message in the greeting (4.1) |

As in 6.2, keyword and number values ignore trailing spaces, and the
welcome text keeps them.

- Changes take effect immediately and show in INFO (8.5).
- Shortening `retention` also applies to events already stored.
- Settings not listed here are left to the server's configuration.

---

## 11. Keepalive and Closing

```
PING [<token>]
```

→ `OK`

A client can send PING to check that the connection works.

When a server has received no line from a client for 120 seconds, it
sends `PING <token>`. The client MUST answer `PONG <token>` right away,
which gets no response. The server also sends PING to check a
connection before a push (9.2). If another 60 seconds pass with no line
received, the server closes the connection. Any complete line resets the
timer, including an empty one or one the server cannot parse, so someone
typing by hand can simply press Enter. Part of a line does not reset
it. This lets the
server notice dead connections, which matters for deciding when to push.

```
QUIT [<message...>]
```

→ `OK`, then the server closes the connection

QUIT is the last command a connection runs. The server ignores any
lines that arrive after it.

```
BYE [<message...>]
```

The server sends BYE just before it closes a connection for its own
reasons, such as shutting down, an idle timeout or a removed key.

---

## 12. Command Summary

Commands a client can send. "Before sign-in" means the command is
allowed before GUEST, AUTH or REGISTER. A guest that sends a command
marked "no" under "Guests" gets `ERR forbidden`.

| Command | Section | Before sign-in | Guests |
|---|---|---|---|
| `INFO [<room>]` | 8.5, 6.2 | without a room | yes |
| `GUEST <name>` | 4.2 | yes | – |
| `AUTH <identity> <signature>` | 4.5 | yes | – |
| `REGISTER <name> <key> <signature>` | 4.6 | yes | – |
| `KEY LIST` / `KEY ADD <key> [<label...>]` / `KEY DEL <key>` | 4.7 | | no |
| `UNREGISTER <uid> [purge=]` | 4.8 | | no |
| `MSG <conv> <text...>` | 5.3 | | rooms only |
| `DELETE <conv> <seq>` | 5.4 | | yes |
| `LIST [after=] [limit=]` | 6.1 | | yes |
| `JOIN <room>` | 6.1 | | yes |
| `PART <room> [<reason...>]` | 6.1 | | yes |
| `SET <room> <key> [<value...>]` | 6.2 | | no |
| `ROLE <room> <uid> <role>` | 6.3 | | no |
| `ROLES <room>` | 6.3 | | yes |
| `INVITE` / `KICK` / `BAN` / `UNBAN` / `BANS` | 6.4 | | no |
| `SYNC` | 7.1 | | yes |
| `HISTORY <conv> [after=] [before=] [limit=]` | 7.2 | | yes |
| `RELATED <conv> <first> <last> [after=] [limit=]` | 7.3 | | yes |
| `READ <conv> <seq>` | 7.4 | | no |
| `TYPING <conv>` | 8.1 | | yes |
| `NAME [<name...>]` | 8.2 | | yes |
| `MEMBERS <room>` | 8.3 | | yes |
| `WHOIS <uid>` | 8.3 | | yes |
| `UPLOAD <size> <type> <name...>` | 5.6 | | no |
| `BLOCK <target>` / `UNBLOCK <target>` / `BLOCKS` | 5.7 | | no |
| `REPORT <conv> <seq> [<reason...>]` | 5.8 | | yes |
| `REPORTS <room>` / `RESOLVE <id>` | 5.8 | | no |
| `PUSH ADD <url> <tag>` / `PUSH DEL <url>` / `PUSH LIST` | 9.1 | | no |
| `ADMIN OPS` / `OP <uid>` / `DEOP <uid>` | 10.1 | | no |
| `ADMIN BAN <target> [<reason...>]` / `UNBAN <target>` / `BANS` | 10.2 | | no |
| `ADMIN WHO` / `DISCONNECT <uid> [<reason...>]` / `NOTICE <message...>` | 10.3 | | no |
| `ADMIN ROOMS [after=] [limit=]` / `DROP <room> [<reason...>]` / `PURGE <uid> [hours=]` / `REPORTS` | 10.4, 5.8 | | no |
| `ADMIN KEYS <uid>` / `ADDKEY <uid> <key> [<label...>]` / `DELKEY <uid> <key>` / `UNREGISTER <uid>` | 10.5 | | no |
| `ADMIN SET <key> [<value...>]` | 10.6 | | no |
| `PING [<token>]` / `PONG <token>` | 11 | yes | yes |
| `QUIT [<message...>]` | 11 | yes | yes |

Lines a server can send:

| Line | Kind | Section |
|---|---|---|
| `RISALA <version> <host> <nonce> [<message...>]` | greeting | 4.1 |
| `OK [<key>=<value> ...]` / `ERR <code> [<message...>]` | final response | 3.6 |
| `MSG` `DELETE` `JOIN` `PART` `INVITE` `KICK` `BAN` `UNBAN` `SET` `ROLE` | events; `SET`, `BAN` and `ROLE` also as snapshots | 5.2, 6 |
| `ROOM <room> <members> [<topic...>]` | response to LIST and ADMIN ROOMS | 6.1, 10.4 |
| `CONV <conv> <id> <head> <read>` | response to SYNC | 7.1 |
| `MEMBER <room> <uid> <role> <presence> [<name...>]` | response to MEMBERS | 8.3 |
| `USER <uid> <presence> [<name...>]` | response to WHOIS | 8.3 |
| `PRESENCE <presence> <uids>` | users came online or went offline | 8.3 |
| `BLOCK <target>` | response to BLOCKS | 5.7 |
| `REPORT <conv> <seq> [<reason...>]`, then the reported event | a report, live or in response to REPORTS | 5.8 |
| `RESOLVED <id>` | a report was resolved | 5.8 |
| `KEY <key> [<label...>]` | response to KEY LIST and ADMIN KEYS | 4.7, 10.5 |
| `PUSH <url> <tag>` | response to PUSH LIST | 9.1 |
| `READ <conv> <seq>` | read marker from your other devices | 7.4 |
| `TYPING <conv>` / `NAME [<name...>]` | not stored | 8.1, 8.2 |
| `NOTICE <message...>` | information | 8.4 |
| `DROP <room> [<reason...>]` | an operator deleted the room | 10.4 |
| `OP <uid>` | response to ADMIN OPS | 10.1 |
| `SERVERBAN <target> [<reason...>]` | response to ADMIN BANS | 10.2 |
| `CONNECTION <uid> <address> <since>` | response to ADMIN WHO | 10.3 |
| `PING <token>` / `BYE [<message...>]` | connection | 11 |

---

## 13. Security Considerations

- **No end-to-end encryption.** TLS protects messages in transit, but
  server operators can read everything, including direct messages.
  Clients SHOULD tell users this where they will see it, for example
  when starting a direct conversation.
- **Trust on first use.** Someone can intercept the first connection to
  a server that has a self-signed certificate. Users can compare the
  fingerprint through another channel (Appendix A). Servers with CA
  certificates do not have this weakness.
- **Identity follows the domain.** Whoever controls
  `https://<domain>/.well-known/risala/` controls every identity under
  that domain, including after the domain changes hands. Private keys
  should be protected like SSH keys.
- **Signatures.** The signed bytes (4.5) bind a signature to one server,
  one connection and one identity. A signature therefore cannot be
  replayed, or used on another server.
- **Requests from the server.** Fetching key files and sending pushes
  both mean connecting to hosts that users choose. The rules in Sections
  4.4 and 9.3 stop these requests from reaching the server's internal
  network.
- **Hosted identities trust their host.** A server that hosts
  identities (4.6) publishes their key files. Its operator can therefore
  add a key and sign in as any of them on any server, and ADMIN ADDKEY
  (10.5) does exactly this to recover lost accounts. People who do not
  want to depend on a host can publish their own key file. While a host
  is unreachable, its users cannot sign in to servers that have no
  cached copy of their key file (4.4).
- **Open registration.** Each REGISTER creates an identity that works on
  every server. A server with open registration SHOULD rate-limit it,
  for example per network address, and close it if it is abused. Other
  servers can answer abuse from such a server only by banning single
  identities or its whole domain (10.2), and a domain ban also shuts out
  that server's legitimate users.
- **Abuse.** Guests are anonymous. Servers SHOULD rate-limit commands and
  connections per network address, and limit how often they fetch any
  one key file. The `guests` setting restricts guests per room.
- **Display names** can be used to imitate other people (8.2).
- **Reports and blocks.** Room owners and moderators do not learn who
  reported a message, but operators do (5.8). The server keeps reported
  messages until reports are resolved, even after their authors delete
  them. Blocks stop direct messages only (5.7). In rooms, people who
  have been blocked can still be seen by others and can still mention
  the person who blocked them.
- **Metadata.** The server sees who talks to whom, and when. Because
  identities work everywhere, different servers can tell that the same
  person uses all of them. Someone who does not want this can use a
  guest name or a separate identity.
- **Push.** Pushes carry no content (Section 9). The push service, and
  any gateway in between, still see when pushes happen and the unread
  count.
- **Deletion** removes text from the server, but not from copies that
  people have already made.
- **Files.** `get` URLs are capabilities (5.6). Anyone a URL is passed to
  can download the file, including people outside the room. People will
  open these URLs in web browsers, so servers SHOULD serve files from a
  domain that is used for nothing else, and with the header
  `X-Content-Type-Options: nosniff`.
- **Operators** can read and remove anything on their server, and ADMIN
  WHO shows them users' network addresses (10.3).

---

## 14. Assigned Values

- **Port:** 7472/tcp. The digits spell RISA on a phone keypad. The port
  is not yet registered with IANA.
- **ALPN identifier:** `risala/1`.
- **Well-known URI suffix:** `risala` [RFC8615].
- **URI scheme:** `risala://<host>[:<port>][/<room>[/<seq>]]`, where
  `<room>` is written without its `#`. For example,
  `risala://chat.example.org/general` points to `#general`, and
  `risala://chat.example.org/general/8813` to one message in it.

---

## 15. References

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC2606] Eastlake 3rd, D. and A. Panitz, "Reserved Top Level DNS
  Names", BCP 32, RFC 2606, June 1999.
- [RFC3339] Klyne, G. and C. Newman, "Date and Time on the Internet:
  Timestamps", RFC 3339, July 2002.
- [RFC3629] Yergeau, F., "UTF-8, a transformation format of ISO 10646",
  STD 63, RFC 3629, November 2003.
- [RFC4648] Josefsson, S., "The Base16, Base32, and Base64 Data
  Encodings", RFC 4648, October 2006.
- [RFC5234] Crocker, D. and P. Overell, "Augmented BNF for Syntax
  Specifications: ABNF", STD 68, RFC 5234, January 2008.
- [RFC5890] Klensin, J., "Internationalized Domain Names for
  Applications (IDNA): Definitions and Document Framework", RFC 5890,
  August 2010.
- [RFC6066] Eastlake 3rd, D., "Transport Layer Security (TLS)
  Extensions: Extension Definitions", RFC 6066, January 2011.
- [RFC6838] Freed, N., Klensin, J., and T. Hansen, "Media Type
  Specifications and Registration Procedures", BCP 13, RFC 6838,
  January 2013.
- [RFC6890] Cotton, M., Vegoda, L., Bonica, R., and B. Haberman,
  "Special-Purpose IP Address Registries", BCP 153, RFC 6890, April 2013.
- [RFC7301] Friedl, S., Popov, A., Langley, A., and E. Stephan,
  "Transport Layer Security (TLS) Application-Layer Protocol Negotiation
  Extension", RFC 7301, July 2014.
- [RFC8032] Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital
  Signature Algorithm (EdDSA)", RFC 8032, January 2017.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119
  Key Words", BCP 14, RFC 8174, May 2017.
- [RFC8446] Rescorla, E., "The Transport Layer Security (TLS) Protocol
  Version 1.3", RFC 8446, August 2018.
- [RFC8615] Nottingham, M., "Well-Known Uniform Resource Identifiers
  (URIs)", RFC 8615, May 2019.
- [RFC9525] Saint-Andre, P. and R. Salz, "Service Identity in TLS",
  RFC 9525, November 2023.

---

## Appendix A. Using risala by Hand

**Connect:**

```
openssl s_client -connect chat.example.org:7472 -quiet
```

Keep `-quiet`, or use `-nocommands`. Without either, `s_client` treats
lines that start with `Q`, `R`, `k` or `K` as its own commands. It would
then swallow `quit`, `read`, `kick` and others instead of sending them.

**Check a server's fingerprint** (Section 2.2):

```
openssl s_client -connect chat.example.org:7472 </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256
```

**Make a key, and print the line for your key file:**

```
openssl genpkey -algorithm ed25519 -out alice.pem
printf 'ed25519 %s laptop\n' \
  "$(openssl pkey -in alice.pem -pubout -outform der | tail -c 32 | openssl base64 -A)"
```

**Sign in.** Copy the nonce from the server's greeting. In a second
terminal, run:

```
printf 'risala-auth-1\n%s\n%s\n%s\n' chat.example.org <nonce> alice@example.org > chal
openssl pkeyutl -sign -rawin -inkey alice.pem -in chal | openssl base64 -A
```

Then type `auth alice@example.org <signature>` in the first terminal.
Servers allow at least 120 seconds for this (4.1).

**Upload a file** (Section 5.6). Send `upload <size> <type> <name>`, then
PUT the file to the `put` URL from the response:

```
curl -T cat.png -H 'Content-Type: image/png' '<put URL>'
```

Then send `@file=<get URL> msg #general look at this`.

**Stay connected.** If the server sends `PING`, type anything, even an
empty line.

## Appendix B. Test Vectors

These keys are for testing only. Ed25519 signatures are deterministic, so
every correct implementation produces exactly this signature.

Private key (seed, hex):

```
c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8
```

The same private key as PEM:

```
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMEfrlxZLhO+Z9yW9uhQBNMukoYV968f06bF2eoKtsuo
-----END PRIVATE KEY-----
```

Public key (hex):

```
27f2a6ba9b9461c45dd82db235978acfad4921b20a6dd469fdd2fc95faae0d86
```

Key file line:

```
ed25519 J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY= laptop
```

Signing in to `chat.example.org` as `alice@example.org` with the nonce
`6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e`. These are the signed bytes, 82 in
total, with each line ending in LF:

```
risala-auth-1
chat.example.org
6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e
alice@example.org
```

Signature (base64):

```
Hk+S5Vd7ciW57dRNS3AhcvZkYNLmj+kkgJUxOYvCrbEQSBk0UDdH+cSBXF6YvCSU85FRVPaURwsQdbV/SAK0CQ==
```

The command:

```
AUTH alice@example.org Hk+S5Vd7ciW57dRNS3AhcvZkYNLmj+kkgJUxOYvCrbEQSBk0UDdH+cSBXF6YvCSU85FRVPaURwsQdbV/SAK0CQ==
```

## Appendix C. Push Gateways (Informative)

Apple's push service (APNs) and Google's (FCM) accept pushes for an app
only from that app's developer, who holds the credentials. An
independent chat server cannot have those credentials. So whoever
publishes an app runs a small **push gateway**: an HTTPS service that
accepts NOTIFY requests from any risala server and forwards them.

A typical setup:

1. The app gets a device token from APNs or FCM and registers it with the
   developer's gateway. The gateway returns a URL containing an opaque
   id, such as `https://push.app.example/n/3f9c...`. The chat server
   never sees the device token.
2. The app sends `PUSH ADD https://push.app.example/n/3f9c... <random
   tag>` to each server it uses. It remembers which tag belongs to which
   server and account.
3. The server POSTs `NOTIFY <tag> <reason> <unread>` to that URL, and the
   gateway forwards it to the device.

How each platform handles a push:

- **iOS.** The gateway sends a visible notification with generic text
  ("New activity"). It sets `mutable-content` and puts the NOTIFY line in
  the notification's data. The app's Notification Service Extension then
  connects to the server, fetches the new messages and replaces the
  generic text with the sender and message. If it cannot finish in time,
  the generic text stays. For the reason `read`, the gateway sends a
  background push instead, so the app can clear notifications.
- **Android with FCM.** The gateway sends a high-priority data message.
  The app fetches the new messages and shows its own notification.
- **Android with UnifiedPush.** The app registers the endpoint URL from
  the user's UnifiedPush distributor directly. No gateway is needed.

A gateway sees only the tag, reason, unread count and timing of each
push, and so do Apple and Google. Anyone who knows a gateway URL can
send to it, so gateways SHOULD rate-limit each URL.

## Appendix D. Differences from IRC (Informative)

| IRC | risala |
|---|---|
| Plaintext by default, TLS optional | TLS only |
| Numeric replies such as `433` | `OK` or `ERR` with a word, exactly one per command |
| `CAP` negotiation | One version, extensions in tags, unknown verbs ignored |
| 512-byte lines | 8 KiB from clients, 16 KiB from servers |
| `PRIVMSG #chan :text` | `MSG #chan text` |
| `nick!user@host` | `~guest` or `name@domain` |
| NickServ and ChanServ | Keys and domains; roles and settings built in |
| Mode letters such as `+o` and `+i` | Named roles and settings |
| No history without a bouncer | Stored history with sequence numbers |
| Networks of linked servers, netsplits | Independent servers, no federation |
| Special case-mapping rules | Lower-case ASCII names |
| `OPER`, with commands that differ between servers | Standard `ADMIN` commands |
| DCC file transfer | Optional uploads over HTTPS |
| CTCP | Not included |
