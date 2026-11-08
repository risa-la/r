# risala

```
risala                                                        draft-02
A Line-Based Chat Protocol                                  2026-11-07
Status: Draft. Anything in this document may change.
Copyright (c) 2026 Risala developers. Licensed under CC BY 4.0.
```

## Abstract

risala is a protocol for real-time chat on independent servers. It runs
over TLS and is made of UTF-8 text lines, so a person can use most of it
directly from a terminal with `openssl s_client`. It provides:

- guest access
- portable identities built on domain names and ML-DSA keys
- end-to-end encryption for direct conversations and private rooms,
  using MLS with post-quantum algorithms
- stored history that clients can catch up on without gaps, including
  encrypted history
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
12. End-to-End Encryption
13. Command Summary
14. Security Considerations
15. Assigned Values
16. References
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
server, stored history, replies, edits, reactions, file sharing, push
notifications and end-to-end encryption.

### 1.1. Goals

- **Usable by hand.** Every feature outside encrypted conversations can
  be used by typing lines into `openssl s_client`. Uploading a file also
  needs an HTTP tool such as `curl`. Encrypted conversations need a real
  client (Section 12).
- **Small where it can be.** A client for public rooms needs only TLS and
  ML-DSA. Encrypted conversations need an MLS implementation in clients,
  and in servers to check commits. A server also needs an HTTPS client.
  File uploads are optional and need HTTPS on both sides.
- **Private.** Direct conversations, and private rooms that choose it,
  are end-to-end encrypted. The server stores them but cannot read them.
- **Post-quantum.** Connections and encrypted conversations use hybrid
  post-quantum key exchange, so recorded traffic stays secret against a
  future quantum computer. Signatures use ML-DSA.
- **Independent servers.** Anyone can run a server. No server is special,
  and nothing depends on central infrastructure.
- **Portable identity.** A person can prove the same identity, such as
  `alice@example.org`, to any server. No server has to trust any other
  server for this.
- **History.** Servers store conversations. A client that reconnects
  fetches exactly what it missed. Devices keep the keys of encrypted
  conversations, so encrypted history can be fetched and read offline
  too.

### 1.2. Non-goals

This version does not provide:

- **Federation.** Messages never move between servers.
- **Hiding metadata.** Even in encrypted conversations, the server sees
  who talks to whom and when (Section 14).
- **Encrypting public rooms.** Anyone may join a public room, so
  encrypting it would protect nothing.
- **Browser clients.** There is no WebSocket or HTTP transport. Clients
  are native applications.
- **Binary data on the chat connection.** Files, where a server supports
  them, travel over HTTPS (Section 5.6). MLS data travels in base64.
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
S: OK uid=~sam token=q7m2x9k4b8n1v5c3z6l0w2e4r7t9y1u3
C: join #general
S: @seq=8812;t=2026-11-06T15:40:58.120Z;from=~sam;id=k3f9q2 JOIN #general
S: SET #general topic General chat. Be kind.
S: SET #general public yes
S: SET #general guests write
S: SET #general retention server
S: SET #general e2ee no
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
  accepts sign-ins only on connections whose SNI names it (Section 4.5).
  A client that connects to a bare IP address cannot send SNI, and so
  cannot sign in as an identity.
- Clients SHOULD offer the ALPN [RFC7301] protocol identifier
  `risala/1`. Servers MUST accept connections that offer no ALPN, so that
  tools such as `openssl s_client` work without extra flags. A server
  MUST refuse a client that offers ALPN identifiers but not `risala/1`,
  with the `no_application_protocol` alert, so that a web browser or
  other client sent to the wrong port fails clearly.

A server address is a hostname with an optional port, for example
`chat.example.org` or `chat.example.org:7000`. Clients lower-case the
hostname and drop one trailing `.` before using it anywhere: in SNI, as
the key of the trust record (2.2) and in the signed bytes (4.5). So
`Chat.Example.org.` and `chat.example.org` are the same server.

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
- **Long lines.** Lines that carry MLS data or encrypted content
  (Section 12) may be longer:
  - From a client, a line whose verb is COMMIT, ENC, INIT, KEYPKG or
    REPORTENC may be up to 8 MiB (8388608 bytes) including the LF.
  - From a server, a line whose verb is COMMIT, ENC, GROUPINFO, KEYPKG,
    REPORTENC or WELCOME may be up to 8 MiB plus 16384 bytes.
  - The data that makes these lines long always comes after the verb.
    So the start of every line, up to the end of its verb, MUST fit the
    normal limit, tags included. A receiver can then tell from the first
    8192 or 16384 bytes whether a line may be long. A line whose verb
    does not end within the normal limit is too long.
  - Before a connection has signed in, the server applies the normal
    limits to every line.
  - The lines inside an encrypted message have their own limits (12.8).
- **Bad lines.** A server that receives a line that is too long MUST
  discard everything up to the next LF and reply `ERR too-long`. It MAY
  reply as soon as it knows the line is too long, before the LF arrives. A server
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
- From a client command, a server copies only `reply`, `edit`, `react`,
  `file` and `frank` onto the event the command causes.
- Tag keys that begin with `x-` are reserved for experiments.
- The content of an encrypted message has tags of its own, which never
  appear on the connection (12.8).

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
| `retry` | server | seconds | With `ERR rate-limited` or `ERR unavailable`: when to try again |
| `report` | server | id | The report that a line belongs to (5.8) |
| `id` | server, client | id | On a JOIN event, a DROP line or a report's lines: the conversation's id (5.8, 6.1, 10.4). On DELETE: the conversation's id the client expects (5.4) |
| `frank` | client | base64 | On ENC: the franking commitment (12.8) |

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
- **Flow control.** A server MAY stop reading a connection's commands
  while that client is not reading its responses. A client may send
  several commands without waiting for their responses, but then it
  MUST keep reading while it writes, or both sides can wait on each
  other forever.
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
- **Consistent with live events.** A line that reports the state of a
  conversation, meaning a CONV line from SYNC, the `OK` of JOIN or
  `INFO <room>`, or the snapshot lines of ROLES and BANS, agrees with
  the live events the connection receives.
  Every event of that conversation sent to the connection before the
  line is covered by it, and every event sent after it is newer. The
  same holds for read markers: the `<read>` on a CONV line covers every
  READ line (7.4) for that conversation sent to the connection before
  it. A server does this by queuing the line while no event or READ
  line of that conversation can be queued.
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
| `auth-failed` | The signature did not verify against the identity's keys, or the connection's SNI does not name this server (4.5) |
| `name-taken` | The guest name or identity name is already in use |
| `not-found` | The room, user or message does not exist, or is not visible to you |
| `forbidden` | Not allowed because of permissions, a ban or server policy |
| `last-owner` | The only owner of a room cannot give up the role |
| `not-supported` | The server does not offer this feature |
| `encrypted` | The conversation is encrypted, so this command cannot be used in it (Section 12) |
| `stale` | The conversation's group is not in the state the command needs. Apply the newer commits, or commit pending removals, and try again (12.5, 12.6) |
| `invalid` | MLS data or a franking commitment did not verify, or a required franking commitment or key is missing (5.8, Section 12) |
| `rate-limited` | Too many requests. The `retry` tag says when to try again |
| `unavailable` | The server could not get the identity's key file, so it could not check the signature. Try again later (4.5) |
| `internal` | Something went wrong on the server |

A name, room, id, text, URL or tag value that follows its grammar except
for being too long gets `too-long`, not `bad-syntax`. A number, key,
signature, franking commitment or franking key with the wrong number of
digits or characters gets `bad-syntax`, and so does base64 that is not
valid. A franking commitment or key that is required but missing gets
`invalid` (5.8, 12.8).

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
one, the server accepts only INFO without a room, GUEST, AUTH, REGISTER,
PING, PONG and QUIT. It replies `ERR not-authenticated` to anything else.

A connection signs in once. To become someone else, reconnect. Servers
SHOULD allow at least 120 seconds to sign in, which leaves time to sign
a challenge by hand (Appendix A).

### 4.2. Guests

```
GUEST <name> [token=<token>]
```

→ `OK uid=~<name> token=<token> [resumed=yes]`

A guest has a name for as long as its **session** lasts. The session
starts with GUEST and ends a while after its connection closes, unless
the guest resumes it (see below). Once it ends, another guest may take
the same name, so a guest uid says nothing about who someone is over
time. For this reason guests:

- cannot take part in direct conversations
- cannot create rooms, hold roles, be invited, set read markers, block
  anyone, upload files or register for push
- stay members of the rooms they join only until their session ends. At
  that point the server records a PART for each of those rooms. If the
  server stops without recording them, for example because it crashed,
  it MUST record them when it starts again, with the time it records
  them as `t`. Sessions do not survive a restart.

Since guests have no direct conversations, a conversation named by a uid
does not exist for a guest. Any command from a guest that names a uid as
its `<conv>`, such as MSG, HISTORY or TYPING, gets `ERR not-found`.
Commands that guests may not use at all still get `ERR forbidden`
(Section 13).

**Resuming.** The token in GUEST's `OK` lets a guest come back after its
connection closes, for example after a network drop, or after a phone
app sends QUIT as it goes to the background (9.2):

- The token is an id (3.5) with at least 128 bits of randomness. It is a
  secret: anyone who has it can take over the guest's name and rooms.
- When a guest's connection closes for any reason, QUIT included, the
  server keeps its session, name and rooms for a resume period of its
  choosing, at least 2 minutes. Only then does the session end and the
  server record the PARTs.
- `GUEST <name> token=<token>` with the session's current token resumes
  it. The connection becomes that guest again, still a member of its
  rooms, and no JOIN or PART is recorded. If another connection still
  has the session, the server closes that one with BYE and reads no
  more commands from it. The `OK` carries `resumed=yes` and a new token,
  and the old token stops working. Without `resumed=yes`, a new session
  has started.
- A token that matches no current session for that name is ignored, and
  GUEST works as it does without one.
- The client catches up on what happened in the meantime with SYNC and
  HISTORY, as in Section 7.1.
- ADMIN DISCONNECT (10.3) and server bans (10.2) end a guest's session
  at once.

The server replies `ERR name-taken` while a session holds the name,
whether its connection is open or it is waiting to be resumed. A client
that cannot resume SHOULD then try another name, for example by adding a
number. The server MAY reserve names, for example the names of
identities it hosts. It MAY refuse guests entirely with `ERR forbidden`.

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
mldsa44 <key> [<label...>]
```

- `<key>` is the 1312-byte ML-DSA-44 public key [FIPS204], in base64
  with padding [RFC4648]. It is 1752 characters long.
- `<label...>` is an optional note for people, usually the name of the
  device. It is at most 64 bytes. A line whose label is longer counts as
  malformed, and is ignored.
- Blank lines and lines starting with `#` are ignored. A line that is
  not valid UTF-8 counts as malformed, and is ignored too.
- Lines with a key type other than `mldsa44` are ignored, so that new key
  types can be added later.

A key line is therefore at most 1827 bytes, CRLF included: 7 for
`mldsa44`, a space, 1752 for the key, a space, 64 for the label and 2
for the line ending. So 64 keys take at most 116,928 bytes, less than
half of the 256 KiB a fetch reads (below), which leaves room for
comments.

Each device SHOULD have its own key. A device's key is also its key in
encrypted conversations (12.2). Revoking a lost device's key means
deleting its line, which also removes the device from those
conversations (12.6).

Keys are shortened here. Appendix B has a full one.

```
# alice@example.org
mldsa44 xjgGNXnY2mHZ3KDuXsHq19lnJd7U5fdp… laptop
mldsa44 0Kc2Ffq9WbL7xNHe1sTr5VgmPa3Ziu4D… phone
```

Servers fetch key files to check sign-ins, and devices fetch them to
check the members of encrypted conversations (12.12). When a server or
device fetches a key file:

- It MUST use HTTPS with TLS 1.3, and validate the certificate against
  public certificate authorities.
- It MUST NOT follow redirects.
- It MUST stop after 10 seconds or 256 KiB.
- It MUST use at most 64 keys: the first 64 different, valid `mldsa44`
  keys in the file. Repeated keys, malformed lines and ignored lines do
  not count toward the 64.
- A server MUST NOT connect to loopback, private, link-local or other
  special-purpose addresses [RFC6890] unless its operator has configured
  it to. Users choose the domain, so without this rule they could make
  the server probe its own internal network.
- It MAY cache the file for up to one hour. If a signature does not
  verify against a cached file, it SHOULD fetch the file again once
  before failing, so that a newly added device works straight away.

A fetch has one of three outcomes:

- **A key file.** A 200 response whose body arrives within the limits.
  The identity's keys are the ones the file lists, which may be none. A
  200 response whose body is larger than 256 KiB counts as a key file
  that lists no keys.
- **Gone.** A 404 or 410 response. The identity has no keys.
- **Failed.** Anything else: no response, a DNS or TLS error, a timeout,
  a 5xx response, or any other status, including a redirect. This is an
  outage, and says nothing about the identity's keys.

A key file or a gone answer replaces a cached copy. A failed fetch does
not, and a cached copy stays valid until its hour is up.

A key has been **removed** when a fetch returns a key file that no
longer lists it, or a gone answer. A server that notices a key has been
removed SHOULD close the connections that signed in with it. A failed
fetch is not a reason to close anything, however long it lasts.

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

`<signature>` is the 2420-byte ML-DSA-44 signature [FIPS204], in base64
with padding, which is 3228 characters long. It is plain ML-DSA.Sign,
with an empty context string and no prehash. The signer may use the
hedged (randomised) or the deterministic variant, and verifiers cannot
tell them apart. Appendix B has a worked example.

The server checks the signature as follows:

1. It checks that the connection's SNI hostname is a name it serves:
   its configured hostname, or a name on one of its certificates. If it
   is not, or the client sent no SNI, the server MUST refuse AUTH and
   REGISTER with `ERR auth-failed`. Its message SHOULD say that the host
   name is wrong, so that a client does not tell the user their key was
   removed.
2. It builds the same bytes, using this connection's SNI hostname and
   nonce.
3. It gets the identity's keys. If it hosts the identity itself (4.6), it
   uses its own records. Otherwise it fetches the key file (4.4), or
   uses a cached copy.
4. It accepts if the signature verifies under any of those keys.

On success the server replies `OK uid=<uid>`, and adds `op=yes` if the
identity is a server operator (Section 10). The key that verified becomes
the connection's **device key**, which push notifications use (Section
9). On failure the server replies:

- `ERR auth-failed` if step 1 fails, or if the signature does not verify
  under the keys the server got. A key file that does not list the key,
  and a gone answer (4.4), count as keys the server got: the identity
  has none that verify.
- `ERR unavailable` if the fetch failed (4.4) and the server has no
  cached copy, so it could not check the signature at all. This
  includes the case where a cached copy did not verify and fetching
  again failed. It MAY add a `retry` tag.

A client that gets `unavailable` SHOULD reconnect and try again later,
waiting longer after each failure, and at least as long as `retry`
says. A client that gets `auth-failed` SHOULD NOT try again on its own,
since the same key will fail the same way. It tells the user instead.

Each part of the signed bytes has a job:

- **The first line** keeps the signature from meaning anything in
  another protocol.
- **The host** stops a server from using a signature it received to sign
  in somewhere else. Without it, a malicious server could pass another
  server's nonce to the client, then use the client's answer to sign in
  there as that user. The host alone is not enough, since the malicious
  server could connect to the other server with its own name in SNI.
  Step 1 closes that gap: the other server refuses a name it does not
  serve.
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
- `name-taken`: the name is already registered, or was once and has been
  retired (4.8).
- `auth-failed`: the signature did not verify, or the connection's SNI
  is not a name the server serves (4.5).
- `forbidden`: for example, registration is closed.
- `rate-limited`: too many registrations from the client's network
  address (Section 14). The `retry` tag says when to try again. The
  limit counts registrations that have succeeded or are still in
  progress, so that sending REGISTER on several connections at once
  does not get around it.

A client whose REGISTER got no answer, because the connection dropped,
cannot tell whether the identity was created. It SHOULD reconnect and
try AUTH as the new identity with the same key before it treats the
registration as failed. It MUST NOT throw the key away before then: if
the registration went through, that key is the identity's only key.

If someone loses all the keys of an identity the server hosts, an
operator can add a new key for them with `ADMIN ADDKEY` (10.5). How the
operator checks who is asking is outside the scope of this document.

### 4.7. Managing Keys

These commands work only for identities that the server itself hosts.
Other people edit their key file directly, and get `ERR not-supported`.
So a client can tell from KEY LIST whether a server hosts the identity
it is signed in as: `ERR not-supported` means it does not. INFO's
`register=` (8.5) is not a reliable sign, since it says `no` while
registration is closed.

```
KEY LIST
KEY ADD <key> [<label...>]
KEY DEL <key>
```

- `KEY LIST` sends one `KEY <key> [<label...>]` line per key, then OK.
- `KEY ADD` adds a key. To set up a new device, the new device shows its
  public key, and the user adds it from a device that is already signed
  in. The new device then joins the identity's encrypted conversations
  (12.6).
- `KEY ADD` of a key the identity already has replaces its label. A
  label longer than the 64 bytes of 4.4 gets `ERR too-long`. Like all
  text, it is measured escaped (3.4). A label that holds a line break
  once unescaped gets `ERR bad-syntax`, since it cannot go in a key
  file. A key beyond the 64 of 4.4 gets `ERR forbidden`.
- `KEY DEL` removes a key. The server MUST refuse to remove the last key
  (`ERR forbidden`). It SHOULD close the connections that use the
  removed key. It deletes the key's KeyPackages and pending Welcomes
  (Section 12), and devices remove its leaves from their groups (12.6).

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
roles, invitations, read markers, blocks, display name, cids, push
registrations, KeyPackages, pending Welcomes and backups (Section 12).
Room bans against it stay, since they belong to the rooms: otherwise
someone banned could come back clean by unregistering. Members' devices
remove its leaves from encrypted rooms (12.6). Then:

- **With `purge=yes`,** the server also deletes every message the
  identity has sent, in every conversation, as if by DELETE (5.4). The
  DELETE events have the identity as `from`.
- **Without it,** messages it has sent stay. The other participant in a
  direct conversation keeps that conversation.
- **Rooms:** if the identity was a room's only owner, the room is left
  without one. An operator can give it a new owner (Section 10).
- **Hosted identities (4.6):** the server also deletes the identity's
  keys and key file. It SHOULD NOT let anyone register the name again,
  for the reason given in Section 10.5. A client can tell beforehand
  whether the server hosts the identity with KEY LIST (4.7).
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
  talks to `alice@example.org`. It starts when one of them creates its
  encryption group with INIT (12.5). A conversation with yourself, for
  example for notes, is named by your own uid. Direct conversations are
  always end-to-end encrypted (Section 12).

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
- An event has the same parameters as the command that caused it,
  except COMMIT (12.5). A guest's automatic PART has no reason text.
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

The event verbs are MSG and DELETE (this section), JOIN, PART, INVITE,
KICK, BAN, UNBAN, SET and ROLE (Section 6), and ENC and COMMIT
(Section 12).

The server sends each new event straight away to every connection in
the conversation. For a room, that means the connections of all its
members, including each guest member's connection while it has one. For a direct
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
  `<seq>` may edit it (`ERR forbidden`). An edit is a message in its own right, with its
  own seq. Clients show the text of the newest edit in the original's
  place. They MAY also show every earlier version. All versions stay in
  history, and anyone who can read the conversation can see them.
- `react=<seq>` reacts to message `<seq>`. The text is the reaction,
  usually a single emoji, and MUST be at most 64 bytes. To take a
  reaction back, delete it (5.4). If a user sends the same reaction to
  the same message twice, the server SHOULD reply OK with the existing
  reaction's seq and not create a new event. Reactions are the same if
  their escaped text (3.4) is the same, byte for byte.

A guest is the author only of the messages it sent in its current guest
session (4.2), since guest names get reused. Someone who takes a name
later may not edit or delete what an earlier guest sent under it, except
as a moderator.

The target `<seq>` MUST be a message in the same conversation. It MUST
NOT be deleted, and MUST NOT itself be an edit or a reaction. Otherwise
the server replies `ERR not-found`. A reply may target another reply.

A client that does not understand these tags still shows the text, so
older clients degrade gracefully: an edit appears as a new message and a
reaction as a short message.

Members of a room who are allowed to post (6.3) may send messages to it.
Both participants of a direct conversation may send messages in it.
Anyone else gets `ERR forbidden`, or `ERR not-found` for a room they
cannot see (6.1).

In an encrypted conversation, messages are sent with ENC instead
(12.8), and MSG gets `ERR encrypted`. The tags of this section then
travel inside the encryption, and devices apply their rules themselves
(12.11).

### 5.4. Deleting Messages

```
DELETE <conv> <seq>
```

→ `OK seq=<seq of the DELETE event>`

Deletes message `<seq>`. The author may delete their own messages. In
rooms, moderators and owners may delete any message (6.3). Only MSG
and ENC events can be deleted: DELETE of any other event gets
`ERR not-found`.

The author may delete their own messages in a room even after they can
no longer read it, for example after leaving a private room or being
kicked or banned from it. So the server checks whether the sender wrote
the target before it applies the reading rules of 6.1. A DELETE that
fails those rules, and does not target a message of the sender's, gets
`ERR not-found` as usual.

The server records a `DELETE <conv> <seq>` event and MUST erase the
stored text of the target. The one exception is the copy kept for an
open report (5.8). What else happens depends on the target:

- Deleting a message also deletes its edits, its reactions and its
  attached file (5.6). Replies to it stay.
- Deleting an edit makes the previous version current again.
- Deleting a reaction removes it.

Deleting a message that is already deleted, by DELETE or along with
the message it belongs to, gets `OK seq=<seq>` with the seq of the
DELETE event that deleted it, and records nothing. So a client can
resend a DELETE safely after a dropped connection (7.6). The rules on
who may delete still apply first.

A DELETE MAY carry an `id` tag with the conversation's id (5.1). If the
conversation's id is different, the server replies `ERR not-found` and
deletes nothing. A room can be dropped and created again (10.4) while a
client cannot read it, for example after leaving, and the tag stops a
seq from the old room naming a message in the new one. Clients SHOULD
send it when they delete in a room they can no longer read.

A deleted event keeps its place in history, so there are no gaps.
HISTORY returns it with the `deleted` tag and empty text. It keeps its
`seq`, `t` and `from`, and any `reply`, `edit` or `react` tag. It loses
its `file`, `file-type` and `file-size` tags, since the file is gone:

```
S: @seq=8813;t=2026-11-06T15:41:02.377Z;from=~sam;reply=8810;deleted MSG #general
```

Clients SHOULD discard deleted text they have stored. Deletion cannot
reach copies that people have already made.

ENC events are deleted the same way. The placeholder has an empty
payload, and loses the `frank` tag as well as the file tags, since the
content it commits to is gone. The copy kept for an open report (5.8)
keeps its `frank` tag. The server cannot see the edits and reactions of
an ENC event, so it does not delete those with it (12.11).

### 5.5. Mentions

A mention is `@` followed by a uid, for example `@alice@example.org` or
`@~sam`. The `@` must be at the start of the text or follow whitespace,
after unescaping. The mention is the longest uid that follows the `@`.
Uids never end with `.` (3.5), so in `thanks @~sam.` the mention is
`~sam`.

Servers use mentions to decide when to send push notifications (Section
9). Clients SHOULD highlight mentions of the user. They SHOULD also let
users type a display name and insert the matching uid. In encrypted
conversations, mentions are inside the encryption, and the server cannot
see them (12.11).

### 5.6. Files

Servers MAY support file uploads. INFO reports the largest file allowed
as `upload=<bytes>`, or `upload=no` (8.5). Files never travel over the
chat connection. They go over HTTPS, so a client that uploads or
downloads files also needs an HTTPS client. In encrypted conversations,
devices encrypt files before uploading them (12.11).

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
- After a BLOCK or UNBLOCK that changes the account's blocks, the server
  sends `BLOCK <target>` or `UNBLOCK <target>` to the account's other
  connections, as it does a READ that moves the marker (7.4), so that
  their lists stay current. Blocking someone already blocked, or
  unblocking someone who is not, gets `OK` and sends nothing. These lines are not
  events. A client applies each one to its list, adding or removing that
  one target, rather than replacing its whole list. The lines BLOCKS
  returns agree with them as a CONV line agrees with READ lines (3.6):
  they cover every BLOCK and UNBLOCK line sent to the connection before
  them.
- A server MAY limit how many blocks an account has, and replies
  `ERR forbidden` beyond the limit. Domain blocks keep the need for many
  entries low.

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
REPORTENC <conv> <seq> <frank-key> <content> [<reason...>]
```

→ `OK id=<id>`

Reports message `<seq>` as abusive to the people who can act on it, its
**reviewers**:

- for a room: the room's owners and moderators, and the server's
  operators
- for a direct conversation: the server's operators

The author of the reported message is never one of its reviewers, so
nobody reviews or resolves a report about their own message. They do
not receive its lines, REPORTS and ADMIN REPORTS leave it out for them,
and their RESOLVE of it gets `ERR not-found`.

REPORT reports a MSG event. REPORTENC reports an ENC event, and reveals
its content to the reviewers (below). Rules for both:

- Anyone who can read the message may report it. That includes guests,
  but only with REPORT, since guests cannot take part in encrypted
  conversations (12.2).
- The target MUST be a message (a MSG or ENC event, which includes edits
  and reactions) that is not deleted (`ERR not-found`). It MUST NOT be
  your own (`ERR forbidden`).
- REPORT of an ENC event, and REPORTENC of a MSG event, get
  `ERR invalid`.
- `<reason...>` is free text of up to 512 bytes.
- If the same uid reports the same message again, the server replies
  with the existing report's id. It checks this before every other rule
  except that the conversation exists, so the reply is the same even if
  the message has been deleted since or the reporter can no longer read
  the conversation, and a client can resend a report safely.
- Servers SHOULD rate-limit reports.

When a report is made, the server keeps a copy of the reported event
until the report is resolved, even if the message is deleted or expires
in the meantime. This is an exception to Sections 5.4 and 7.5. Without
it, someone could remove what they sent as soon as it is reported. The
server SHOULD discard the copy when the report is resolved. It MAY
close reports on its own after a time it chooses.

Reviewers receive each report as two lines: a REPORT or REPORTENC line
with the same parameters as the command, and the reported event as it
was when it was reported. Both carry the `report` tag with the report's
id, and the `id` tag with the conversation's id (5.1), so that a report
from a room that was dropped and created again (10.4) is not taken for
one about the new room:

```
S: @report=p4x8n2;id=k3f9q2;t=2026-11-06T15:44:10.230Z;from=bob@example.net REPORT #general 8816 spam
S: @report=p4x8n2;id=k3f9q2;seq=8816;t=2026-11-06T15:43:58.019Z;from=~spammer MSG #general cheap pills at …
```

- On the REPORT or REPORTENC line, `t` is when the report was made, and
  `from` is the reporter.
- Only operators see `from` on these lines. Room owners and moderators
  get them without it, so that reporters cannot be singled out.
- Both lines name a direct conversation as the reporter sees it, so
  `<conv>` is the author on both. The two participants are the reporter
  (`from` on the REPORT or REPORTENC line) and the author (`from` on the
  event).
- The server sends the two lines to every reviewer's connections when
  the report is made.
- The event line is a copy for review. Clients MUST NOT treat it as a
  new event in the conversation.

The server cannot read an ENC event (12.8), so a report of one reveals
its content to the reviewers. The `frank` tag on the event makes this
checkable:

- `<frank-key>` is the message's franking key, the 32-byte `frank_key`
  of 12.8, in base64 with padding. It is 44 characters long.
- `<content>` is the message's decrypted content, the bytes of
  `content` in 12.8, in base64 with padding.
- The server decodes both, and checks that HMAC-SHA-384 [RFC2104] of the
  content bytes under the franking key equals the event's `frank` tag.
  If it does not, it replies `ERR invalid`. Devices make the same check
  before they show a message (12.8), so the content can only be what
  its author sent.
- Reviewers receive the REPORTENC line, which carries the franking key
  and the content, and the ENC event with an empty payload, since they
  cannot decrypt it. The event keeps its `frank` tag. Reviewers decode
  `<content>` to read the message, and MAY check the commitment
  themselves.
- The content can be long, so REPORTENC is one of the verbs that may
  begin a long line (2.3).

```
C: reportenc alice@example.org 2 g6310tyvzbFYtF+zfJzNGwhM3CbuWJ83hbt4OL35Zb4= VEVYVCBz… harassment
S: OK id=w7c1m5
```

The server's operators then receive:

```
S: @report=w7c1m5;id=d8m4x1;t=2026-11-07T10:20:41.118Z;from=bob@example.net REPORTENC alice@example.org 2 g6310tyvzbFYtF+zfJzNGwhM3CbuWJ83hbt4OL35Zb4= VEVYVCBz… harassment
S: @report=w7c1m5;id=d8m4x1;seq=2;t=2026-11-07T10:02:12.003Z;from=alice@example.org;frank=hT3m… ENC alice@example.org 1
```

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
  every reviewer's connections except the one that sent RESOLVE,
  including the resolver's other devices, so that their lists stay
  current. RESOLVE by someone who is not one of the report's reviewers
  gets `ERR not-found`, as for an id that does not exist.

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
  `ERR not-found`. Anyone who controls a domain can make any number of
  identities, so servers SHOULD limit how often one identity creates
  rooms, and reply `ERR rate-limited` with a `retry` tag beyond the
  limit (Section 14). The limit need not apply to operators.

Who may join:

- Anyone not banned may join a public room.
- Joining a private room takes an invitation (6.4), unless you hold the
  role owner or mod in it (6.3).
- Guests may join only rooms whose `guests` setting is not `none`.
- Joining an encrypted room always takes an invitation, made by adding
  your devices to the room's group (12.6). This holds for owners,
  moderators and server operators too.

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
(6.3). Guests leave all their rooms automatically when their session
ends (4.2).
PART for a room you are not a member of gets `ERR not-found`. The one
exception is an invitee of an encrypted room, for whom PART declines the
invitation (12.6). The server records a PART event for it.

A room goes on existing when its last member leaves. Nothing about it
changes: its history, settings, roles, invitations and bans all stay.
Its owners and moderators can join it again at any time, and so can
server operators (Section 10), except that an encrypted room takes a new
invitation (12.6). Only ADMIN DROP (10.4) deletes a room.

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
| `e2ee` | `yes` or `no` | `no` | nobody: only INIT sets it (12.5) |
| `history` | `shared` or `joined` | `shared` | owners, in encrypted rooms |

- `public yes`: LIST shows the room, and anyone may join.
- `public no`: LIST does not show the room, and joining takes an
  invitation.
- `guests none`: guests cannot join or read.
- `guests read`: guests may join and read, but not send.
- `guests write`: guests may also send messages. This is the default, so
  anyone can connect and talk straight away. If guests start sending
  spam, an owner can switch the room to `read`.
- Changing `guests` applies at once to the guests already in the room.
  Under `read` they stay but can no longer send. Under `none` the
  server removes them from the room, recording a PART for each. Their
  sessions and their other rooms are not affected (4.2).
- `retention <days>`: events older than this many days are deleted
  (7.5). The value MUST be at least 1 (`ERR bad-syntax`), and MUST NOT
  be longer than the server's own retention period (`ERR forbidden`). Shortening it also
  applies to events already stored.
- `retention server`: the room follows the server's retention period.
- `e2ee yes`: the room is end-to-end encrypted (Section 12). INIT turns
  this on (12.5), and nothing turns it off. SET of `e2ee` gets
  `ERR forbidden`, and so does SET of `public` or `guests` in an
  encrypted room.
- `history shared`: devices that add a new member to an encrypted room
  also give it the keys to read the room's earlier messages (12.9).
- `history joined`: new members can read only what is sent after they
  are added.
- `history` exists only in encrypted rooms, and its snapshot SET lines
  leave it out elsewhere. Its value lives in the room's group, where
  devices read and enforce it (12.9). An owner changes it with a COMMIT
  (12.5), and the server then records the SET event. SET of `history`
  gets `ERR encrypted` in an encrypted room, and `ERR forbidden` in any
  other.

Keyword and number values ignore trailing spaces, so `SET #r public yes `
works. A topic keeps its spaces. An unknown key gets
`ERR not-supported`. Setting a key to the value it already has records
nothing, and gets a plain `OK`.

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
- INFO follows the reading rules of 7.2, except that someone invited to a
  private room may see its INFO before joining, so their client can show
  what they are invited to. HISTORY stays closed to them until they join.

### 6.3. Roles

Each identity in a room has one of three roles: `owner`, `mod` or
`member`. Guests are always `member`. Whoever creates a room is its
first owner.

The roles `owner` and `mod` belong to the identity, not to its current
membership:

- Someone who leaves with PART keeps the role. They can join again
  without an invitation, even in a private room, and have the role back.
  An encrypted room is the exception: there, coming back always takes a
  new invitation (12.6).
- They keep the role's rights while they are away, for example to read
  the room, change its settings or moderate it.
- KICK and BAN take the role away.
- A room therefore never loses its owners because they left.

| Action | member | mod | owner |
|---|---|---|---|
| Send messages; edit, react to and delete your own | ✓ | ✓ | ✓ |
| Delete anyone's messages | | ✓ | ✓ |
| Set `topic` | | ✓ | ✓ |
| INVITE, KICK, BAN, UNBAN, BANS | | ✓ | ✓ |
| Set `public`, `guests`, `retention` and `history` | | | ✓ |
| ROLE | | | ✓ |

- Moderators may kick and ban only plain members. Owners may act on
  anyone, including other owners. Server operators count as owners here,
  so moderators cannot kick or ban them.
- A room's only owner cannot KICK or BAN themselves
  (`ERR last-owner`), since the room would be left without one.
- Guests in a room with `guests read` cannot send messages, reactions or
  typing notifications.
- Server operators (Section 10) have owner rights in every room, and may
  join any room without an invitation, except an encrypted one (6.1),
  even one they are banned from.

```
ROLE <room> <uid> <role>
```

→ ROLE event, then `OK seq=<seq>`

The target must be an identity that is a member of the room, or that
holds the role `owner` or `mod` in it (`ERR not-found`). Guests cannot
hold roles (`ERR forbidden`). Setting the role of someone who
has left to `member` takes their role away. If an owner is the room's
only owner, they cannot change their own role (`ERR last-owner`).
Setting the role someone already has records nothing, and gets a plain
`OK`.

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
  invitee is banned, and someone who is banned cannot be invited
  (`ERR forbidden`): unban them first. Guests cannot be invited.
  Inviting someone who is
  already a member, or already invited, records nothing, and gets a
  plain `OK`. So a client
  that receives an INVITE for its own account knows the server does not
  count it as a member, and SHOULD send SYNC if it thought it was one.
- `KICK` removes a member. They may join again. KICK of someone who is
  not a member gets `ERR not-found`, even if they hold a role. To take
  the role of someone who has left, use ROLE (6.3) or BAN.
- `BAN` removes a member, if they are one, and stops them from joining.
  Banning a guest uid has little effect, because guest names get reused.
  A server MAY ban the guest's network address instead. BAN of someone
  who is already banned, and not a member, records nothing: it replaces
  the ban's reason, and gets a plain `OK`.
- `UNBAN` lifts a ban. UNBAN of someone who is not banned gets
  `ERR not-found`.
- `BANS` lists the current bans as snapshot `BAN <room> <uid>
  [<reason...>]` lines, then OK.

INVITE, KICK, BAN and UNBAN reply `OK seq=<seq>`. The KICK or BAN event
also goes to its target, before the target stops receiving the room. A
BAN event reaches a target who is not a member only if they could see
the room before the ban (6.1), so that a ban made in advance does not
reveal a private room.
An INVITE event that reaches an invitee who is not a member, and a KICK
or BAN event that reaches its target, are notifications. They do not
make the receiver a member, and a client that is not a member does not
store them as the room's history.

In an encrypted room, INVITE gets `ERR encrypted`. An invitation there
is a COMMIT that adds the invitee's devices, and the server records the
INVITE event for it (12.6). After KICK or BAN, members' devices remove
the person's devices from the group, so someone who was kicked needs a
new invitation to come back.

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
  It is always `0` for guests. It covers every READ line for the
  conversation sent to the connection before the CONV line (3.6).

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
   in it, and on over any stored events that directly follow. If the
   response holds no events and says `more=0`, every event after L up to
   the head the client knew when it sent the command has expired (7.5),
   and the sync point moves to that head. A head learned while the
   command was on its way is not covered by the response: if it is
   higher, send HISTORY again.
4. If the gap is large, the client MAY instead fetch only the newest page,
   and load older pages when the user scrolls back (7.3). The sync point
   then stays where it was until the gap is filled.
5. Live events may arrive in the meantime. A duplicate has the same seq
   as the event already received, so it can be dropped. A live event
   moves the sync point only if it directly follows it.
6. A client MUST NOT store a live event for a conversation until it has
   learned that conversation's id on this connection, from SYNC, JOIN or
   INFO. Before then it cannot tell which room the event belongs to.
   HISTORY returns such events later. A live event for a conversation
   the client has not heard of on this connection, such as the first
   message of a new direct conversation, means it should send SYNC
   again to learn the id, then catch up as above. So does a live event
   whose seq is above the head that SYNC just reported for that
   conversation, since the head was computed before the event.

A client MAY download the whole history of its conversations for reading
offline. Sequence numbers make the download easy to resume. In encrypted
conversations, the client decrypts the events with the history keys it
keeps (12.9).

If a conversation the client knows about is missing from SYNC, the
account is no longer in it. It may have left, been kicked or banned, or
an operator may have dropped the room (10.4).

A room that was dropped can later be created again under the same name.
The new room has a new id, and its sequence numbers start again at 1. A
client that missed the DROP notices the new id and starts the room
afresh, instead of mixing the two rooms' histories. The client also
discards what it has stored when the head a server reports is lower than
its sync point for that id, as the sync point was when the client sent
the SYNC, JOIN or INFO that reported the head. This cannot happen with a
correct server, but it keeps the client consistent. Events stored past
the sync point do not count, and neither does a sync point that moved
after the command was sent, because another process sharing the
client's cache, such as a notification extension, may have stored
events after the server computed the head.

### 7.2. HISTORY

```
HISTORY <conv> [after=<seq>] [before=<seq>] [limit=<n>] [only=commit]
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
- **`only=commit`** returns only COMMIT events, so that a device can
  bring an encrypted conversation's group up to date before it fetches
  messages (12.11). `more` then says whether there are more COMMIT
  events. Such a page does not move the sync point (7.1), since it
  skips other events.

You may read the history of:

- rooms you are a member of
- rooms you hold the role `owner` or `mod` in, even after leaving them
  (6.3)
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
- In encrypted conversations it returns no ENC events, since the server
  cannot see what they target (12.11).

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

Sets the account's read marker for the conversation to `<seq>`. Any
conversation the account may read (7.2) can have a marker, not only
those it is in.

- The marker only moves forward. A lower value is ignored. A value
  beyond the conversation's head sets the marker to the head.
- The server sends `READ <conv> <seq>` to the account's other connections,
  so they can update their unread counts. This line is not an event. A
  CONV line from SYNC agrees with these lines as it does with events
  (3.6), so a client can take the higher of the two values.
- Read markers are private to the account. Nobody else sees them.
- Only identities can set read markers.

### 7.5. Retention

A server MAY delete events older than a retention period, which INFO
reports (8.5). A room may set a shorter period of its own (6.2).
Whichever period is shorter applies. So if a server later shortens its
period below a room's, the server's period applies to that room.

A server expires a conversation's events in seq order, oldest first, so
that no event it keeps is older than one it has expired. It stops at the
first event that is not old enough, even if a later event has an older
time, which can happen if its clock moves backwards. Clients rely on it to tell expired events
from gaps (7.1, 7.2).

The sequence numbers of expired events are never reused. Files expire
together with the messages they are attached to (5.6). Copies kept for
open reports do not expire (5.8). COMMIT events expire like other
events. Section 12.11 says what a device that missed expired commits
does.

### 7.6. Resending Safely

A connection might drop after a client sends MSG or ENC but before the
OK arrives. The client then cannot know whether the message went through.
To make resending safe:

- A client MAY tag MSG or ENC with `cid=<token>`. The token is a random
  value of at least 16 characters, chosen anew for each message.
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
- For guests, the server checks cids only within one guest session,
  which a resumed connection continues (4.2). A guest whose `OK` carried
  `resumed=yes` may resend with the same cid. A guest whose session has
  ended cannot resend safely. Its client SHOULD show a message that
  never got its `OK` as possibly not sent, rather than send it again.
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

Only someone who may send messages in the conversation may send TYPING
(5.3). Others get `ERR forbidden`. A server MAY drop TYPING that comes
more often than about once a second per conversation; it still replies
`OK`.

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
[<name...>]` to the connections that share a conversation with you,
and to your own other connections. A
guest's display name lasts as long as its session (4.2).

Display names are not unique and prove nothing, since anyone can call
themselves anything. Clients SHOULD show the uid whenever two people in
a conversation share a display name, and whenever the user asks:

- To decide whether two people share a display name, a client compares
  the names unescaped (3.4), after removing bidirectional text controls
  (U+061C, U+200E, U+200F, U+202A to U+202E and U+2066 to U+2069) and
  zero-width characters (U+200B to U+200D, U+2060 and U+FEFF), which are
  invisible, ignoring case, and collapsing each run of whitespace into one space,
  with none at either end.
- A client SHOULD show the uid as a separate element, not as text
  appended to the name, so that a name cannot pass for a uid. It SHOULD
  always show the uid when a name contains `@`, or a character that
  looks like one such as U+FF20 or U+FE6B, or otherwise looks like a
  uid.

Servers MAY refuse display names that contain bidirectional text
controls, with `ERR forbidden`.

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
  and `offline` otherwise. During the wait before PRESENCE reports
  someone offline (below), they still count as online, so MEMBERS and
  WHOIS agree with PRESENCE.
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
- A connection never receives PRESENCE about its own account.
- PRESENCE covers identities only. A guest is online for as long as it
  is a member, and its PART (4.2) says when it leaves.

A client learns the current presence of members from MEMBERS and of
others from WHOIS, then keeps it current with PRESENCE. PRESENCE only
reports changes, and a client misses those while it is disconnected. So
a client that shows presence SHOULD send MEMBERS again for the rooms it
shows, and WHOIS for the others, after it reconnects. Future versions
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
| `register=<domain>` or `register=no` | The identity domain for REGISTER, or `no` if the server offers no registration or it is closed right now. It does not say whether the server hosts an identity: KEY LIST does (4.7) |
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
- is in an encrypted room U is a member of (reason `message`)

Edits and reactions are never notable. In encrypted conversations,
though, the server cannot see mentions, replies, edits or reactions
(12.11). There, every ENC event from someone else is notable, even one
that only carries keys (12.9), and the app decides after syncing whether
to show a notification.

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
`<reason>` is `dm`, `mention`, `reply`, `message` or `read`, and
`<unread>` is the unread count. A reason is 1 to 32 characters of `a-z`,
`0-9` and `-`.
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
  commands of Section 6. They may join any room without an invitation,
  except an encrypted one (6.1). Their actions in rooms are recorded as
  events like anyone else's.
- Operators cannot read encrypted conversations, unless a member reports
  a message (5.8). They can still delete, purge and drop them.
- The ADMIN commands themselves create no events, except PURGE (10.4).

### 10.1. Operators

```
ADMIN OPS
ADMIN OP <uid>
ADMIN DEOP <uid>
```

- **`ADMIN OPS`** sends one `OP <uid>` line per operator, then OK.
- **`ADMIN OP`** makes an identity an operator. Guests cannot be
  operators. ADMIN OP of an identity covered by a server ban (10.2) gets
  `ERR forbidden`: lift the ban first.
- **`ADMIN DEOP`** removes an operator. Operators named in the server's
  configuration cannot be removed this way (`ERR forbidden`). DEOP of
  someone who is not an operator gets `ERR not-found`.

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
  for a banned identity. They check the signature first, and reply
  `ERR auth-failed` if it does not verify, so that only someone holding
  the identity's key learns that it is banned. A banned identity's open
  connections are closed with BYE. A domain ban is useful because one domain can mint any
  number of identities.
- **Address bans** apply only to guests. People with identities who
  happen to share an address with a spammer, such as at a university or
  on a mobile network, are not affected. Ban identities one at a time or
  by domain instead. A new address ban also ends the sessions of the
  guests connected from inside it, with BYE, and the sessions waiting
  to be resumed (4.2) whose last connection came from inside it.
- **Banning a guest** bans the address it is connected from: the
  IPv4 address itself, or the IPv6 `/64` that contains it, since one
  IPv6 user usually holds a whole `/64`. It also closes the guest's
  connection. BANS lists the ban under the address it applies to, and
  ADMIN UNBAN takes that address, not the guest's uid.
- **`ADMIN UNBAN`** of a target that is not banned gets `ERR not-found`.
- **Banning deletes nothing.** Use ADMIN PURGE (10.4) to remove what a
  user has sent.
- **Operators cannot be banned.** ADMIN BAN of a target that covers an
  operator, including the one sending it, gets `ERR forbidden`. Remove
  the operator with ADMIN DEOP first. Operators named in the server's
  configuration cannot be banned this way at all, and server bans do not
  apply to them when they sign in, even one made before they were added
  to the configuration.
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
  For a guest, it also ends a session waiting to be resumed (4.2). A uid
  with no connection and no session gets `ERR not-found`.
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
    roles, invitations and bans are deleted too, and so are its group,
    GroupInfo and pending Welcomes if it is encrypted (Section 12).
  - The server sends `@id=<id> DROP <room> [<reason...>]` to every
    connection in the room, and to the connections of its owners and
    moderators who are not members, where `<id>` is the dropped room's
    id (5.1).
    No event is recorded, since the room's events are gone. A client
    ignores a DROP whose id is not the one it has stored for the room,
    since it may be about an older room of the same name.
  - The room stops appearing in SYNC.
  - Clients SHOULD remove the room and the history they have stored for
    it.
  - Open reports about the room's messages stay, with their copies,
    until an operator resolves them (5.8).
  - The name becomes free. If anyone creates a room with it later
    (6.1), that is a new room with a new id, whose sequence numbers
    start again at 1. Clients that missed the DROP notice the new id
    (7.1). Links that name a seq in the old room (Section 15) do not
    carry over, and may point to a different message in the new room.
- **`ADMIN PURGE`** deletes the messages `<uid>` has sent, in every
  conversation.
  - Each message is deleted as if by DELETE (5.4), with the operator as
    the DELETE event's `from`.
  - With `hours=<n>`, only messages from the last `<n>` hours are
    deleted. For a guest uid, the purge covers messages sent under that
    name, which is why `hours` is useful there.
  - The server replies `OK deleted=<count>`, the number of DELETE
    events it recorded. Edits and reactions deleted along with their
    message are not counted.
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
  which locks the identity. A key added with ADDKEY can join the
  identity's encrypted conversations like any other device (12.6), so
  its users see it as a new device (12.12).
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
- Setting `guests` to `no` also ends every guest session: guests
  connected now get `BYE`, sessions waiting to be resumed (4.2) end too,
  and every guest leaves its rooms as in 4.2.
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
it, and a line that is too long counts once its LF arrives. This lets the
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

## 12. End-to-End Encryption

### 12.1. Overview

Direct conversations, and rooms whose `e2ee` setting is `yes` (6.2), are
**encrypted conversations**. Their messages are encrypted on the
sender's device, and only the devices of the conversation's members can
read them. The server stores and relays them, but cannot read them.

risala uses Messaging Layer Security (MLS) [RFC9420] for this, with
post-quantum algorithms (12.2):

- Each encrypted conversation has one MLS **group**. Each device in it
  is one member of the group, called a **leaf**.
- A group moves through numbered **epochs**. Each commit (12.5), for
  example one that adds or removes devices, starts a new epoch with new
  keys.
- The server is the group's delivery service. It puts commits in order,
  checks them against the conversation's membership, and keeps the
  public part of each group, so that devices can join while no one else
  is online. It never holds a group's secrets.
- Messages are encrypted with a **history key** that devices derive for
  each epoch (12.9). Devices keep these keys, so they can decrypt stored
  history at any time: after reconnecting, offline, and on a new device.

Encrypted conversations need a client that implements MLS, and cannot
be used by hand. Everything else in this document still can.

In the examples of this section, long base64 values are shortened with
`…`.

### 12.2. Algorithms

All encrypted conversations use one MLS cipher suite, `0x0052`:

| Part | Algorithm |
|---|---|
| KEM | X-Wing, which combines ML-KEM-768 and X25519 [XWING] |
| AEAD | ChaCha20-Poly1305 [RFC8439] |
| Hash | SHA-384 |
| Signatures | ML-DSA-44 [FIPS204] |

- The KEM is post-quantum and classical at once. Its keys stay secret as
  long as either ML-KEM-768 or X25519 holds.
- Within HPKE [RFC9180], the suite uses the KEM `0x647a` (X-Wing
  [XWING]), the KDF HKDF-SHA384 (`0x0002`) and the AEAD
  ChaCha20-Poly1305 (`0x0003`).
- Everywhere else MLS needs a hash or a KDF, for example in
  ExpandWithLabel, DeriveSecret, the tree and transcript hashes and the
  exporter, it uses SHA-384 and HKDF-SHA384 [RFC5869].
- Signatures are ML-DSA-44 alone, as for signing in (4.5): plain
  ML-DSA.Sign, with an empty context string and no prehash.
- OpenMLS 0.9 calls this suite
  `MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44`.
- The MLS protocol version is `mls10`.
- `<keypackage>`, `<groupinfo>`, `<commit>` and `<welcome>` in this
  section are each an MLSMessage [RFC9420] in base64 with padding
  [RFC4648]. `<tree>` is a ratchet tree, encoded as the data of a
  `ratchet_tree` extension (the `optional<Node>` vector of [RFC9420]),
  in base64 with padding.

Credentials:

- A leaf's credential is an MLS `basic` credential. Its identity is the
  identity's uid in lower case, in UTF-8.
- Its signature key is one of the identity's device keys (4.4), as the
  raw 1312-byte ML-DSA-44 public key. A device uses the same key to sign
  in and to sign in MLS. The labels that MLS and Section 4.5 put in front
  of what they sign keep the two uses apart.
- Two leaves of a group never share a signature key [RFC9420].
- A leaf's credential and signature key never change. A commit's path
  MUST NOT change those of the committer's leaf. A new key means a new
  leaf: the device joins again with it, and its old leaf is removed
  (12.6).
- Only identities have leaves. Guests cannot take part in encrypted
  conversations.

Every group carries a **conversation extension** in its group context,
of type `0xF2A1` (Section 15). Leaves list this type, and the
`last_resort` extension type `0x000A` [MLS-EXT], in their capabilities,
and the group lists `0xF2A1` in its `required_capabilities`. It
ties the group to one conversation, and holds the room's `history`
setting (12.9):

```
enum {
    reserved(0),
    direct(1),
    room(2),
    (255)
} ConversationKind;

enum {
    reserved(0),
    shared(1),
    joined(2),
    (255)
} HistoryMode;

struct {
    ConversationKind kind;
    opaque name<V>;
    HistoryMode history;
} RisalaConversation;
```

- For a direct conversation, `name` is the uids of its two participants
  in lower case, sorted byte by byte and joined by one space. For a
  conversation with yourself, it is your uid alone. `history` is
  `shared`.
- For a room, `name` is the room's id (5.1), and `history` is the room's
  setting.

### 12.3. Encrypted Conversations

- **Direct conversations** are always encrypted, including a
  conversation with yourself.
- **Rooms** are encrypted when an owner sends INIT while they are the
  room's only member (12.5). The room is then private for good: `public`
  is `no`, `guests` is `none` and `e2ee` is `yes`, and none of these can
  change again (`ERR forbidden`). Events from before INIT stay as they
  were, unencrypted.
- **Public rooms** are never encrypted. Anyone may join them, so
  encryption would protect nothing.

In an encrypted conversation, messages are sent with ENC (12.8), and MSG
gets `ERR encrypted`. In an encrypted room, INVITE also gets
`ERR encrypted`, because inviting someone means adding their devices to
the group (12.6). ENC and COMMIT in a room that is not encrypted get
`ERR forbidden`. Section 12.11 lists what else changes.

A client MUST NOT send MSG to a direct conversation, or to a room for
which it holds a group, whatever the server says about the room's
settings. Otherwise a server could make it send in the clear.

### 12.4. Key Packages

To add a device to a group, a member needs one of that device's
KeyPackages. Devices upload KeyPackages in advance, so that others can
add them while they are offline.

```
KEYPKG ADD <keypackage>
KEYPKG COUNT
KEYPKG GET <uid>
```

- **`KEYPKG ADD`** stores a KeyPackage for this connection's device, and
  replies `OK`. The server checks that the KeyPackage uses the cipher
  suite of 12.2, that its credential is the connection's uid, that its
  signature key is the connection's device key (4.5), that its leaf
  lists the conversation extension and `last_resort` in its
  capabilities (12.2), that its signatures verify, and that its lifetime
  is acceptable (below). Otherwise it replies `ERR invalid`. A server
  MAY limit how many KeyPackages it keeps for each device
  (`ERR forbidden`).
- **`KEYPKG COUNT`** replies `OK count=<n> last-resort=<yes or no>`: the
  number of ordinary KeyPackages the server holds for this device, and
  whether it holds a last-resort one.
- **`KEYPKG GET`** sends one `KEYPKG <uid> <keypackage>` line for each
  device of `<uid>` that has a KeyPackage, then `OK`. It leaves out the
  device that asks, and devices whose keys are no longer in the
  identity's key file. A uid the server does not know gets
  `ERR not-found`.

The server hands out each ordinary KeyPackage once, then deletes it. A
device MAY also upload one KeyPackage with the `last_resort` extension
[MLS-EXT]. The server hands that one out only when the device has no
ordinary KeyPackage left, and keeps it, so the device can always be
added. A new one replaces it.

A device SHOULD keep about ten ordinary KeyPackages on the server, and
upload more when KEYPKG COUNT reports fewer than five. Servers delete
KeyPackages whose lifetime has ended, and SHOULD rate-limit KEYPKG GET,
since every request uses KeyPackages up.

Only identities can use KEYPKG.

**Lifetimes.** A KeyPackage's lifetime is acceptable if the current time
is within it, and it spans at most 12 weeks and one hour (7261200
seconds from `not_before` to `not_after`). The server checks this when a
KeyPackage is uploaded, and the server and every device check it again
when a commit adds the KeyPackage to a group (12.5, 12.6).

A leaf keeps its KeyPackage's lifetime until its device commits a fresh
leaf (12.6), which has none [RFC9420]. So the lifetime can end while the
leaf is still in the group. The server, and devices that join by Welcome
or by external commit, do not check the lifetimes of leaves already in
the group's tree. This departs from Section 7.3 of [RFC9420], which
recommends that a client check the lifetime of every leaf it receives,
including the leaves of a group it joins. With that check, one device
that stayed offline for longer than its lifetime would stop everyone
else from joining the group, until someone removed it.

### 12.5. Groups and Commits

```
INIT <conv> <groupinfo> <tree>
```

→ for a room, SET events; then `OK id=<id> epoch=0`

INIT creates the group of an encrypted conversation. The client creates
an MLS group with a new random 32-byte group id, in which its own device
is the only member, and whose conversation extension (12.2) names the
conversation. It sends the group's GroupInfo for epoch 0, with the
`external_pub` extension, and its ratchet tree. The server checks them
as it checks commits (below), as far as that applies without a commit:
the tree has one leaf, whose signature key is the connection's device
key, and the GroupInfo matches the tree, is signed by that leaf, and has
`external_pub` and no `ratchet_tree`. It also checks the conversation
extension, and rejects a group id it has seen before (`ERR invalid`).
`<id>` in the reply is the conversation's id (5.1).

- **A direct conversation** must not have a group yet (`ERR stale`). If
  the conversation does not exist, INIT starts it, under the rules of
  5.1.
- **A room** must not be encrypted yet (`ERR stale`). The sender must be
  an owner and the room's only member (`ERR forbidden`). Since the
  extension names the room's id, the client gets it from INFO first. The
  server sets `public` to `no`, `guests` to `none`, `e2ee` to `yes` and
  `history` to the extension's value, and records a SET event for each,
  with the sender as `from`. It also ends the room's pending
  invitations, which were made without the group.

```
COMMIT <conv> <commit> <groupinfo> [<welcome>]
```

→ COMMIT event, then `OK seq=<seq> epoch=<epoch>`

COMMIT changes the group:

- `<commit>` holds a Commit. It is sent as a PublicMessage, or as an
  external commit (12.6), so the server and every device can check it.
- `<groupinfo>` is the GroupInfo of the new epoch, with the
  `external_pub` extension and without a `ratchet_tree` extension.
- `<welcome>` is the Welcome for the devices the commit adds. It is
  present exactly when the commit adds devices (`ERR invalid`).

The server records the commit as an event. Unlike other events, it does
not repeat the command's parameters. `<epoch>` is the new epoch:

```
@seq=<seq>;t=<timestamp>;from=<uid> COMMIT <conv> <epoch> <commit>
```

Devices apply commits in seq order. The server accepts a commit only if
all of these hold:

1. **It is for the current epoch.** Otherwise the server replies
   `ERR stale`, because another commit came first. The client applies
   the commits it missed, then makes its change again if it is still
   needed.
2. **It is valid.** It verifies under MLS as far as someone outside the
   group can check: its signatures, the lifetimes of the KeyPackages it
   adds (12.4), the new ratchet tree and its parent hashes, and the
   GroupInfo. The GroupInfo's group context must be the one the commit
   produces, its confirmation tag must be the commit's, and its signer
   must be the committer's leaf in the new epoch. Its signature must
   verify, and it must have the `external_pub` extension and no
   `ratchet_tree` extension. Otherwise `ERR invalid`.
3. **The committer may change the group** (`ERR forbidden`). The
   committer's signature key is the connection's device key, and its
   identity is a participant of the direct conversation, or a member or
   invitee of the room. The commit's path, if any, keeps the credential
   and signature key of the committer's leaf (12.2).
4. **Its proposals are allowed** (`ERR forbidden`). All proposals are
   inside the commit, by value. There are no separate proposals.
   - **Add** adds a device whose key is in its identity's key file. In a
     direct conversation, the identity must be one of the participants.
     In a room, it must be a member, someone already invited, or someone
     the committer may invite (6.4). In the last case the commit is an
     invitation (12.6). If the device's key already has a leaf, the
     same commit removes that leaf.
   - **Remove** removes a leaf of the committer's own identity, a leaf
     whose signature key the same commit adds again (see Add), a leaf
     whose key is no longer in its identity's key file, or, in a room, a
     leaf of an identity that is neither a member nor invited.
   - **GroupContextExtensions** is allowed only in a room, and the
     committer must be an owner. Its extension list is the group's
     current one, with only the `history` field of the conversation
     extension changed. The server records `SET <room> history <value>`
     after the COMMIT event.
   - **ExternalInit** is allowed only in an external commit. An external
     commit may hold at most one Remove, and only of the leaf whose
     signature key is the joiner's (12.6).
   - No other kinds are allowed. A device refreshes its own keys with a
     commit that has no proposals (12.6).
5. **The group stays small enough.** A group has at most 512 leaves.

The server cannot check the confirmation tag itself, or that the path's
secrets decrypt, since both need the group's secrets. So a member can
send a commit that the server accepts and other devices reject. Section
12.6 says what those devices do.

A client that adds many devices SHOULD split them over several commits
of at most 256 devices each. This keeps COMMIT and WELCOME lines well
under the limit of 2.3.

After it accepts a commit, the server:

- records the COMMIT event
- records an INVITE event (6.4) for each identity the commit invites,
  after the COMMIT event, with the committer as `from`
- keeps the new GroupInfo, and the new ratchet tree, which it builds
  from the commit
- stores the Welcome for each device the commit adds (12.7), and keeps
  the ratchet tree of the new epoch for as long as any of them is
  pending

```
GROUPINFO <conv>
```

→ `GROUPINFO <conv> <epoch> <seq> <groupinfo> <tree>`, then `OK`

Returns the group's current GroupInfo, as sent with the last commit, and
its current ratchet tree. `<seq>` is the seq of the COMMIT event that
started the epoch, or `0` in epoch 0. A device uses these to join by
external commit (12.6), so only identities that may do that can ask
(`ERR forbidden`): a participant of the direct conversation, or a member
or invitee of the room that has a leaf in the group. A conversation
without a group gets `ERR not-found`.

### 12.6. Membership

Devices check every change to a group before applying it, besides what
MLS itself requires.

**Joining.** When a device joins a group, by Welcome (12.7) or by
external commit, it checks the whole group:

- The conversation extension names the conversation the device meant to
  join: for a direct conversation, its two participants, and for a
  room, the id that the room's JOIN, INFO or SYNC reports.
- In a direct conversation, every leaf belongs to one of its two
  participants, or in a conversation with yourself, to you.
- Every leaf's key passes the key check below.

A device MUST NOT join a group that fails the first two checks. It does
not check the lifetimes of leaves already in the tree (12.4).

**Commits.** For every commit, a device MUST reject it if it:

- in a direct conversation, adds a leaf of anyone other than the
  participants, or in a conversation with yourself, of anyone else
- changes the group's extensions other than the `history` field of the
  conversation extension
- changes the credential or signature key of the committer's leaf
- is an external commit by an identity that had no leaf in the group
  before it, except a participant of a direct conversation
- is an external commit that removes a leaf other than the one with the
  joiner's signature key
- removes a leaf for no reason the device can see: the leaf belongs to
  the committer's own identity, the same commit adds its signature key
  again, its key is no longer in its identity's key file, or, in a room,
  the conversation's events show that its identity left, was kicked or
  banned, or declined an invitation

It also applies the key check to every leaf that the commit adds or
changes. A device that rejects a commit can no longer follow the group.
It SHOULD warn the user, and stop sending in that conversation.

A device may also fail to process a commit that passes these checks,
because MLS itself rejects it: for example, its path secrets do not
decrypt, or its confirmation tag is wrong, which the server cannot check
(12.5). Such a device MAY join the group again by external commit, as a
new device does, with the checks for joining. It then gets the history
keys of the epochs it missed as in 12.9. A device that rejected a commit
for one of the reasons above MUST NOT do this, since joining again would
accept the change it rejected.

**The key check.** A leaf passes if its signature key is listed in the
key file of the identity in its credential (12.12). If the device cannot
confirm that, because the key is not listed, or because the key file
cannot be fetched right now, the leaf is **unconfirmed**. This happens
to honest devices too, for example when a device catches up on a commit
that added a key that has been revoked since. So the device does not
reject the commit, but while any leaf of a group is unconfirmed:

- it MUST NOT send ENC in that conversation
- it tries the key file again from time to time
- it SHOULD commit the removal of the leaf, which the server allows when
  the key is not in the key file (12.5)

Together these rules mean the server cannot, on its own, let anyone else
read an encrypted conversation. A direct conversation only ever holds
the devices of its two participants, every new identity in a room is
added by a member's device, and a device that joins by itself must use a
key from its identity's key file. Section 14 covers the one exception,
whoever controls an identity's key file.

**Starting a direct conversation.** Alice's device:

1. Sends INIT for the conversation.
2. Fetches KeyPackages for Bob's devices and her own other devices with
   KEYPKG GET.
3. Sends a COMMIT that adds them all, with a Welcome.
4. Sends her message with ENC (12.8).

```
C: init bob@example.net AAEABA… gAAU…
S: OK id=d7hq2klm epoch=0
C: keypkg get bob@example.net
S: KEYPKG bob@example.net AAEABQABAFI…
S: KEYPKG bob@example.net AAEABQABAFI…
S: OK
C: commit bob@example.net AAEAAQ… AAEABA… AAEAAw…
S: @seq=1;t=2026-11-07T10:02:11.540Z;from=alice@example.org COMMIT bob@example.net 1 AAEAAQ…
S: OK seq=1 epoch=1
```

If both participants send INIT at about the same time, one of them gets
`ERR stale`, and its device then joins the other's group by Welcome or
external commit.

**Creating an encrypted room.** The owner creates the room with JOIN
(6.1), reads its id with INFO, then sends INIT for it.

**Inviting.** In an encrypted room, someone who may invite (6.4) fetches
the invitee's KeyPackages and sends a COMMIT that adds the invitee's
devices, with a Welcome. The server records the invitation as an INVITE
event. The invitee's devices are in the group from that epoch on, and
the invitee joins the room with JOIN as usual. An invitee who does not
want to join sends PART for the room, which ends the invitation.

In an encrypted room, joining always takes an invitation made this way,
including for owners and moderators who left and for server operators
(`ERR forbidden`). If every member leaves, no device remains that could
add anyone, so the room cannot be used again.

**New devices.** A device that signs in for the first time joins each of
its identity's encrypted conversations listed by SYNC (7.1), starting
with the conversation with itself, so that the identity's other devices
can send it history keys (12.9). It can join in either of two ways:

- Another device of the same identity adds it with a KeyPackage.
- It joins by **external commit**: it fetches GROUPINFO, then sends a
  COMMIT holding an external commit. This is allowed when its identity
  is a participant of the direct conversation, or a member or invitee of
  the room that already has a leaf in the group. If the device's key
  still has a leaf, for example after the app was reinstalled with the
  same key, the external commit MUST remove that leaf.

**Leaving.** An identity's leaves must be removed from a room's group
when it is no longer a member or invited: after PART, KICK, BAN or
UNREGISTER. A device's leaves must be removed from every group when its
key leaves its identity's key file (4.7).

- The server stops sending the conversation's events to an identity
  that left straight away, as for any room (6.1).
- While a group has a leaf that the server knows must be removed, the
  server refuses ENC in that conversation with `ERR stale`. The device
  then commits the removal and sends again. So no message is encrypted
  for someone who has left.
- Devices learn that keys were removed by fetching key files again
  (12.12). A device whose own identity removed a key SHOULD remove that
  key's leaves from all its groups.

Since PART removes an identity's leaves, coming back to an encrypted room
always takes a new invitation.

**Refreshing keys.** A device SHOULD commit a fresh leaf of its own,
with a commit that has no proposals, about once a week while it is in
use. After that commit, keys that someone may have stolen from the
device no longer decrypt new messages.

### 12.7. Welcome Messages

A device that a commit adds gets a Welcome. The server keeps it until
the device deletes it.

```
WELCOME LIST
WELCOME DEL <id>
```

The server sends each Welcome to the device's connections as soon as it
accepts the commit, and `WELCOME LIST` sends every pending one, then
`OK`:

```
WELCOME <conv> <id> <seq> <welcome> <tree>
```

- `<conv>` names the conversation as for events (5.2).
- `<id>` identifies the Welcome. It is chosen by the server, in the
  form of an id (3.5).
- `<seq>` is the seq of the COMMIT event that added the device.
- `<tree>` is the ratchet tree of the epoch the commit started. The
  server attaches it, and keeps it while any of the commit's Welcomes is
  pending. The device checks it against the tree hash in the Welcome.

The device checks the group as in 12.6, then joins it in that epoch. It
then reads the conversation's commits after `<seq>`, once it may read
the conversation (an invitee, once it has joined the room), and applies
them.

Once it has joined, the device deletes the Welcome with
`WELCOME DEL <id>`, which replies `OK`. It SHOULD NOT delete the Welcome,
or the private keys of the KeyPackage it was made for, before then, so
that it can try again if joining is cut short, for example by a crash.
It also deletes a Welcome whose group fails the checks of 12.6.

A device SHOULD send `WELCOME LIST` after each sign-in. The server
deletes the pending Welcomes of a device whose leaf has been removed, or
whose key has been removed.

### 12.8. Encrypted Messages

```
ENC <conv> <epoch> <payload...>
```

→ ENC event, then `OK seq=<seq>`

Sends an encrypted message:

- `<epoch>` is the epoch whose history key encrypts the message. It MUST
  be the group's current epoch, and the group MUST NOT have a leaf that
  must be removed (`ERR stale` for both, see 12.6).
- The connection's device key MUST have a leaf in the group
  (`ERR forbidden`). Who may send is otherwise as for MSG (5.3).
- `<payload...>` is the encrypted message in base64 with padding. It
  MUST decode to at least 48 bytes, the salt and the AEAD tag
  (`ERR invalid`). This only catches payloads that cannot be messages:
  a real one is a few kilobytes, since its signature alone is 2420
  bytes. The server checks nothing more about it.
- The `frank` tag is required (`ERR invalid`). It is the message's
  franking commitment, 48 bytes in base64 with padding (64 characters),
  which lets the content be reported (5.8).
- The `file` tag (5.6) and the `cid` tag (7.6) MAY be added, and work as
  for MSG.

```
C: @frank=hT3m…;cid=q2r8sv0alm3nb7xk enc bob@example.net 1 3qG8w…
S: @seq=2;t=2026-11-07T10:02:12.003Z;from=alice@example.org;frank=hT3m… ENC bob@example.net 1 3qG8w…
S: OK seq=2
```

An ENC event has the parameters of the command, but two kinds of ENC
event have an empty payload: a deleted placeholder (5.4), which also has
no `frank` tag, and the copy of a reported event that reviewers receive
(5.8). So the syntax of the event is:

```
@seq=<seq>;t=<timestamp>;from=<uid>[;<tag>...] ENC <conv> <epoch> [<payload...>]
```

Every other ENC event has a payload and a `frank` tag. The command
always needs both.

The structures below use the notation of MLS [RFC9420]:

```
struct {
    opaque message_id[16];
    opaque sender_key_id[48];
    opaque frank_key[32];
    opaque content<V>;
    opaque signature<V>;
    opaque padding<V>;
} RisalaMessage;

struct {
    opaque group_id<V>;
    uint64 epoch;
    opaque message_id[16];
    opaque sender_key_id[48];
    opaque frank_key[32];
    opaque content<V>;
} RisalaMessageTBS;

struct {
    opaque group_id<V>;
    uint64 epoch;
} RisalaMessageAAD;
```

To encrypt a message, the sender's device:

1. Writes the content lines (below) as `content`.
2. Sets `message_id` and `frank_key` to new random values.
3. Sets `sender_key_id` to the SHA-384 hash of its raw signature key.
4. Signs: `signature` is SignWithLabel(signature key, "risala message",
   RisalaMessageTBS) [RFC9420], with the fields above and the group's id
   and epoch. So the bytes signed are a SignContent whose label is
   `MLS 1.0 risala message`.
5. Sets `padding` to an empty vector. It SHOULD then fill `padding` with
   the fewest zero-valued bytes that make the encoded RisalaMessage a
   multiple of 256 bytes, so that the server learns less about lengths.
   The length prefix of `padding` grows from one byte to two at 64
   bytes, so this can take more than 255 bytes. Receivers ignore the
   contents of `padding`.
6. Picks a random 32-byte `salt`, and derives the message key:
   ExpandWithLabel(history_key, "risala message key", salt, 32)
   [RFC9420], where `history_key` is the epoch's history key (12.9).
   This is HKDF-Expand with SHA-384, with the 48-byte history key as the
   PRK, and the full label is `MLS 1.0 risala message key`.
7. Encrypts RisalaMessage with ChaCha20-Poly1305 under the message key,
   with a nonce of 12 zero bytes, and RisalaMessageAAD as the associated
   data. A message key is used only once, so a fixed nonce is safe. The
   ciphertext ends with the 16-byte tag.
8. Sends `salt` followed by the ciphertext as the payload, and
   HMAC-SHA-384(frank_key, content) [RFC2104] as the `frank` tag, in
   base64 with padding. The HMAC covers the bytes of `content` alone,
   without their length prefix, and the tag is 48 bytes.

Appendix B has a test vector for these steps.

To decrypt an ENC event, a device:

1. Checks that `<epoch>` is the epoch the group was in at the event's
   place in the conversation: the epoch of the latest COMMIT event before
   it, or `0`. If retention (7.5) has removed those COMMIT events, it
   uses the seqs it recorded for each epoch (12.9). A device that has
   neither, for example one that restored the history key from a backup
   (12.10), skips this step.
2. Finds the history key of the conversation and `<epoch>`.
3. Derives the message key from the first 32 bytes of the payload, and
   decrypts the rest, which must be exactly one RisalaMessage.
4. Finds the sender's key. If the device was in the group in that epoch,
   it is the signature key of the leaf of `from` whose SHA-384 hash is
   `sender_key_id`. Otherwise it is a key of `from` with that hash that
   the device has seen in a key file or a group. It verifies `signature`
   with that key.
5. Checks that HMAC-SHA-384(frank_key, content) equals the `frank` tag.
6. Checks that it has not already seen `message_id` in the conversation,
   so that the server cannot replay a message under a new seq.

If any step fails, the device MUST NOT show the content, and MAY show
that the message could not be read. There is one exception to step 4. A
device that was not in the group in that epoch, and does not know the
sender's key, for example because the key was revoked before the device
restored the history key from a backup (12.10), MAY show the content
marked as unverified. A device that was in the group in that epoch knows
every leaf, and MUST NOT show the content unless the signature verifies.

The content is one or more lines in UTF-8, in the format of Section 3,
each ending in LF. It is either a single TEXT line, or any number of KEY
and RECOVERY lines. Devices ignore lines with verbs they do not know.

The rules of 2.3 for characters apply to these lines, but its length
limits do not. Instead, TEXT has its own limit (below), and the content
as a whole is at most 4 MiB (4194304 bytes). A device treats larger
content as a failure of step 3.

```
[@<tags>] TEXT <text...>
KEY <id> <epoch> <key>
RECOVERY <key>
```

- **TEXT** is a message. Its text follows the rules of MSG (5.3): it is
  escaped as in 3.4, it MUST NOT be empty, and it is at most 8192 bytes.
  It may carry these tags:
  - `reply`, `edit` and `react`, as in 5.3. Each comes with `target`,
    the target message's `message_id` in base64 with padding. A device
    ignores the reference unless the event at that seq is a message with
    that id, so the server cannot point it at another message.
  - `file-key` and `file-type`, for files (12.11).
- **KEY** shares a history key (12.9).
- **RECOVERY** shares a recovery key (12.10).

For example, a reply as it appears inside the encryption:

```
@reply=15;target=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12
```

### 12.9. History Keys

For each epoch of each group it is in, a device derives the epoch's
history key [RFC9420]:

```
history_key = MLS-Exporter("risala history", "", 48)
```

This is the exporter of Section 8.5 of [RFC9420], with an empty context,
where `exporter_secret` is the epoch's exporter secret:

```
history_key = ExpandWithLabel(
                  DeriveSecret(exporter_secret, "risala history"),
                  "exported", SHA-384(""), 48)
```

Appendix B has a test vector. MLS keeps only the current epoch's
exporter secret, so a device derives an epoch's history key before it
applies the commit that ends the epoch.

Devices keep history keys for as long as they keep the conversation, and
SHOULD protect them at rest as they protect their device key. With them,
a device can decrypt any ENC event of those epochs that HISTORY returns,
at any time. This is what lets clients download history and read it
offline (7.1).

With each history key of an epoch it was in, a device also keeps the
signature keys of that epoch's leaves, for step 4 of decryption (12.8),
and the seq of the COMMIT event that started the epoch, for step 1.

History keys reach a device in three ways:

1. **Its own epochs.** A device derives the key of every epoch from the
   one it joined in.
2. **From its identity's other devices.** When a new device joins an
   identity's conversation with itself, the identity's other devices can
   send it every history key they hold, as KEY lines in ENC messages in
   that conversation. Whoever controls the identity's key file could add
   a device of their own (Section 14), so a device MUST NOT send history
   keys to a new device until the user has confirmed on it that the new
   device is theirs, for example by comparing fingerprints (12.12). Once
   one device has sent the keys, the others MAY skip it.
3. **From other members of a room.** When the `history` field of the
   room's conversation extension (12.2) is `shared`, the device that adds
   a new identity (12.6) also sends, in ENC messages in the room right
   after its commit, the history keys of every earlier epoch of the room
   that it holds. When it is `joined`, devices MUST NOT send earlier
   history keys to an identity they add, so new members can read only
   what was sent after they were added. Devices read this setting from
   the group, not from SET events, which the server could forge.

In a KEY line, `<id>` is a conversation's id (5.1), `<epoch>` is an
epoch number, and `<key>` is the 48-byte history key, in base64 with
padding. A set of keys that does not fit in one message is split over
several. A device accepts KEY lines only in its conversation with
itself, or in a room for that room's own id. When it gets two different
keys for the same epoch, it keeps the one it derived itself, then one
from its own identity's devices or backup, then the first one it got,
and SHOULD warn the user.

### 12.10. Key Backup

A device can get history keys from another of its identity's devices
(12.9). If someone loses all their devices, a **recovery key** lets a
new device restore history keys from an encrypted backup on the server
instead. Backups are optional for users. Servers MUST support them.

- A recovery key is 32 random bytes. Clients show it as 52 characters of
  lower-case base32 [RFC4648], without padding, in groups of four
  separated by spaces. When reading one that a user typed, they ignore
  case, spaces and `-`.
- The backup key is derived from it with HKDF [RFC5869] and SHA-384:
  HKDF-Expand(HKDF-Extract("", recovery key), info, 32), where `info` is
  `risala backup ` followed by the uid. Its **key id** is the first 8
  bytes of its SHA-384 hash.
- A client that creates a recovery key shows it to the user once, and
  sends it to the identity's other devices as a RECOVERY line, in base64
  with padding, in the conversation with itself. Devices MUST ignore
  RECOVERY lines in any other conversation. A newer RECOVERY line
  replaces an older one.
- Every device that holds the recovery key backs up each history key it
  gets, as a **blob**: the key id, then a random 12-byte nonce, then the
  history key encrypted with ChaCha20-Poly1305 under the backup key and
  that nonce. The associated data is the conversation's id, a space and
  the epoch number, in ASCII. A blob is 84 bytes. In commands and lines,
  `<blob>` is the blob in base64 with padding, 112 characters long.

```
BACKUP ADD <id> <epoch> <blob>
BACKUP GET <id> [after=<epoch>] [limit=<n>]
BACKUP DEL [<id>]
```

- **`BACKUP ADD`** stores the blob for epoch `<epoch>` of conversation
  `<id>`, and replies `OK`. If the server already has a blob for that
  epoch with the same key id, it keeps the one it has and still replies
  `OK`.
- **`BACKUP GET`** sends one `BACKUP <id> <epoch> <blob>` line per stored
  blob of conversation `<id>`, oldest epoch first, then
  `OK more=<0 or 1>`:
  - Without `after`, it starts with the oldest blob, so epoch 0 is
    included.
  - With `after`, it returns only blobs of epochs greater than `after`.
    To fetch the next page, send BACKUP GET again with `after` set to
    the last epoch returned.
  - **`limit`** is at least 1 and defaults to 500. It is the most epochs
    one page returns blobs for. An epoch can have several blobs, one
    for each key id (see BACKUP ADD), and a page always holds all of
    them. A server MAY return fewer epochs than asked for.
  - `more=1` means there are blobs of later epochs than the last one
    returned.
- **`BACKUP DEL`** deletes the blobs of conversation `<id>`, or every blob
  of the identity, and replies `OK`.

Backups belong to the identity, not to a device. Only identities can use
BACKUP. The server MAY delete the blobs of conversations the identity is
no longer in.

To restore, a device that has the recovery key sends BACKUP GET for each
conversation SYNC lists, and decrypts the blobs whose key id matches. If
none match, the recovery key is wrong.

A device that is lost keeps the recovery key it was sent. So when one of
an identity's keys is removed, its client SHOULD offer to make a new
recovery key. It then deletes every blob, and backs up the history keys
again under the new one.

### 12.11. What Changes in Encrypted Conversations

The server cannot see what an encrypted message says, so some features
work differently:

- **Replies, edits and reactions** are tags on the TEXT line (12.8), with
  the meanings of 5.3. The server cannot check them, so devices apply
  the rules themselves. They ignore an edit from anyone other than the
  author of its target, a reaction longer than 64 bytes, and a second
  identical reaction from the same person to the same message.
- **Deleting** (5.4) works on ENC events. The server erases the payload
  and keeps a placeholder with the `deleted` tag, an empty payload and
  no `frank` tag. It cannot find the message's edits and reactions, so
  it leaves them.
  A client that deletes a message SHOULD also delete the edits of it
  that it knows about, and devices hide edits and reactions whose target
  is deleted. The server does delete the attached file, which it knows
  from the `file` tag.
- **Catching up** (7.1). A device must apply every COMMIT in order
  before it can decrypt later messages, so it first fetches the
  conversation's commits with `HISTORY <conv> after=<seq> only=commit`
  (7.2). It can then fetch messages page by page, newest first if it
  likes.
- **RELATED** (7.3) returns no ENC events, since the server cannot see
  their targets. A client that needs the edits and reactions of older
  messages reads the history in between.
- **Mentions** (5.5) and replies are hidden from the server, so push
  works differently (9.2).
- **Files** (5.6) are encrypted before they are uploaded. The device
  encrypts the file with ChaCha20-Poly1305 under a new random 32-byte
  key, with a nonce of 12 zero bytes and no associated data. It uploads
  the result with UPLOAD, giving the type `application/octet-stream` and
  the name `file`, so that the server learns neither. The ENC carries
  the `file` tag as in 5.6. The TEXT line carries `file-key`, the key in
  base64 with padding, and `file-type`, the file's media type. Its text
  is the caption or the file name, as for MSG.
- **Reports** (5.8) of ENC events use REPORTENC, which reveals their
  content to the reviewers, checked against the franking commitment.
- **Typing, read markers, display names and presence** (Section 8) are
  not encrypted.
- **Blocks** (5.7) work as before.
- **Retention** (7.5) also removes old COMMIT events. A device that
  missed commits that have since expired cannot catch up by reading
  them. It joins again by external commit (12.6), and gets the history
  keys it lacks from its identity's other devices or from a backup.

### 12.12. Checking Devices

A device does not take the server's word for which keys belong to whom:

- A device checks the signature key of every leaf it accepts against the
  key file of the identity in the leaf's credential (12.6). It fetches
  key files itself, under the rules of 4.4, and MAY cache them for up to
  an hour.
- For each identity it shares an encrypted conversation with, a device
  SHOULD fetch the key file again at least once a day, and remove the
  leaves of keys that have been removed (4.4, 12.6). A failed fetch
  removes nothing.
- Clients SHOULD show each identity's devices, and tell the user when
  one is added or removed, so that people notice a device they do not
  recognise.
- Clients SHOULD let people compare device keys through another channel.
  A key's fingerprint is `sha256:` followed by the SHA-256 hash of the
  raw public key in lower-case hex, as in 2.2.

---

## 13. Command Summary

Commands a client can send. "Before sign-in" means the command is
allowed before GUEST, AUTH or REGISTER. A guest that sends a command
marked "no" under "Guests" gets `ERR forbidden`. A guest that names a
uid as the `<conv>` of any other command gets `ERR not-found` (4.2).

| Command | Section | Before sign-in | Guests |
|---|---|---|---|
| `INFO [<room>]` | 8.5, 6.2 | without a room | yes |
| `GUEST <name> [token=]` | 4.2 | yes | – |
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
| `HISTORY <conv> [after=] [before=] [limit=] [only=]` | 7.2 | | yes |
| `RELATED <conv> <first> <last> [after=] [limit=]` | 7.3 | | yes |
| `READ <conv> <seq>` | 7.4 | | no |
| `TYPING <conv>` | 8.1 | | yes |
| `NAME [<name...>]` | 8.2 | | yes |
| `MEMBERS <room>` | 8.3 | | yes |
| `WHOIS <uid>` | 8.3 | | yes |
| `UPLOAD <size> <type> <name...>` | 5.6 | | no |
| `BLOCK <target>` / `UNBLOCK <target>` / `BLOCKS` | 5.7 | | no |
| `REPORT <conv> <seq> [<reason...>]` | 5.8 | | yes |
| `REPORTENC <conv> <seq> <frank-key> <content> [<reason...>]` | 5.8 | | no |
| `REPORTS <room>` / `RESOLVE <id>` | 5.8 | | no |
| `PUSH ADD <url> <tag>` / `PUSH DEL <url>` / `PUSH LIST` | 9.1 | | no |
| `KEYPKG ADD <keypackage>` / `KEYPKG COUNT` / `KEYPKG GET <uid>` | 12.4 | | no |
| `INIT <conv> <groupinfo> <tree>` | 12.5 | | no |
| `COMMIT <conv> <commit> <groupinfo> [<welcome>]` | 12.5 | | no |
| `GROUPINFO <conv>` | 12.5 | | no |
| `WELCOME LIST` / `WELCOME DEL <id>` | 12.7 | | no |
| `ENC <conv> <epoch> <payload...>` | 12.8 | | no |
| `BACKUP ADD <id> <epoch> <blob>` / `BACKUP GET <id> [after=] [limit=]` / `BACKUP DEL [<id>]` | 12.10 | | no |
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
| `MSG` `DELETE` `JOIN` `PART` `INVITE` `KICK` `BAN` `UNBAN` `SET` `ROLE` `ENC` `COMMIT` | events; `SET`, `BAN` and `ROLE` also as snapshots | 5.2, 6, 12 |
| `ROOM <room> <members> [<topic...>]` | response to LIST and ADMIN ROOMS | 6.1, 10.4 |
| `CONV <conv> <id> <head> <read>` | response to SYNC | 7.1 |
| `MEMBER <room> <uid> <role> <presence> [<name...>]` | response to MEMBERS | 8.3 |
| `USER <uid> <presence> [<name...>]` | response to WHOIS | 8.3 |
| `PRESENCE <presence> <uids>` | users came online or went offline | 8.3 |
| `BLOCK <target>` | response to BLOCKS, or a block made on your other devices | 5.7 |
| `UNBLOCK <target>` | a block lifted on your other devices | 5.7 |
| `REPORT <conv> <seq> [<reason...>]` or `REPORTENC <conv> <seq> <frank-key> <content> [<reason...>]`, then the reported event | a report, live or in response to REPORTS | 5.8 |
| `RESOLVED <id>` | a report was resolved | 5.8 |
| `KEY <key> [<label...>]` | response to KEY LIST and ADMIN KEYS | 4.7, 10.5 |
| `PUSH <url> <tag>` | response to PUSH LIST | 9.1 |
| `KEYPKG <uid> <keypackage>` | response to KEYPKG GET | 12.4 |
| `GROUPINFO <conv> <epoch> <seq> <groupinfo> <tree>` | response to GROUPINFO | 12.5 |
| `WELCOME <conv> <id> <seq> <welcome> <tree>` | a Welcome for this device, live or in response to WELCOME LIST | 12.7 |
| `BACKUP <id> <epoch> <blob>` | response to BACKUP GET | 12.10 |
| `READ <conv> <seq>` | read marker from your other devices | 7.4 |
| `TYPING <conv>` / `NAME [<name...>]` | not stored | 8.1, 8.2 |
| `NOTICE <message...>` | information | 8.4 |
| `DROP <room> [<reason...>]` | an operator deleted the room | 10.4 |
| `OP <uid>` | response to ADMIN OPS | 10.1 |
| `SERVERBAN <target> [<reason...>]` | response to ADMIN BANS | 10.2 |
| `CONNECTION <uid> <address> <since>` | response to ADMIN WHO | 10.3 |
| `PING <token>` / `BYE [<message...>]` | connection | 11 |

---

## 14. Security Considerations

- **What is encrypted end to end.** Direct conversations and encrypted
  rooms are end-to-end encrypted (Section 12). The server cannot read
  their messages or files. Public rooms, and private rooms that are not
  encrypted, are protected only by TLS, and their server's operators can
  read them. Clients SHOULD show users which kind of conversation they
  are in.
- **Post-quantum.** Connections use a hybrid key exchange (2.1), and
  encrypted conversations a hybrid KEM (12.2). Both stay secret as long
  as either their classical or their post-quantum half holds, so traffic
  recorded today cannot be decrypted later by a quantum computer.
  Signing in and MLS use ML-DSA signatures. TLS certificates still use
  classical signatures, because certificate authorities issue no other
  kind yet. A quantum attacker could therefore impersonate a server in
  real time, and read what passes through it, but not what is encrypted
  end to end.
- **Kept history keys.** Devices keep the history keys of every epoch
  (12.9), so that history works on new devices and offline. This gives up
  part of the forward secrecy of MLS: whoever takes a device can read the
  history it can reach. Commits still give post-compromise security: once
  a device has committed a fresh leaf (12.6), keys stolen earlier do not
  decrypt new messages.
- **Recovery keys.** A recovery key (12.10) decrypts the identity's whole
  backup, so it should be stored like a password. The server holds only
  encrypted backups. Every device of the identity knows the recovery
  key, so after a device is lost, the user should make a new one.
- **What the server can still do.** It can withhold, delay or reorder
  encrypted messages, and refuse commits. Devices detect replayed and
  re-pointed messages (12.8), but not ones that are withheld.
- **Commits the server cannot fully check.** A member's device can send
  a commit whose secrets other devices cannot decrypt (12.5). They then
  join the group again by external commit (12.6). This lets a member
  disrupt a conversation for a while, but not read more of it.
- **Who can add a device.** Whoever controls an identity's key file can
  add a key, and that key's device can join every encrypted conversation
  of the identity (12.6) and read what is sent there from then on. For
  identities a server hosts, this includes its operator (10.5). Members
  see such a device as a new device of the identity (12.12), and SHOULD
  check with its owner. Earlier history needs more: the identity's other
  devices send history keys to a new device only once the user confirms
  it (12.9). The server cannot add devices of identities it does not
  host, because devices check key files themselves.
- **Reports reveal content.** A report of an encrypted message reveals
  its content to the reviewers, by the choice of the member who reports
  it (5.8).
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
  replayed, or used on another server. This relies on servers accepting
  sign-ins only on connections whose SNI is a name they serve (4.5).
  Otherwise a malicious server could relay another server's nonce under
  its own name, and sign in there as its users.
- **Requests from the server.** Fetching key files and sending pushes
  both mean connecting to hosts that users choose. The rules in Sections
  4.4 and 9.3 stop these requests from reaching the server's internal
  network.
- **Hosted identities trust their host.** A server that hosts
  identities (4.6) publishes their key files. Its operator can therefore
  add a key and sign in as any of them on any server, or join their
  encrypted conversations as a new device. ADMIN ADDKEY (10.5) does
  exactly this to recover lost accounts. People who do not
  want to depend on a host can publish their own key file. While a host
  is unreachable, its users cannot sign in to servers that have no
  cached copy of their key file, and get `ERR unavailable` (4.5). An
  outage does not revoke keys: only a key file that no longer lists a
  key, or a 404 or 410 answer, does (4.4).
- **Open registration.** Each REGISTER creates an identity that works on
  every server. A server with open registration SHOULD rate-limit it,
  for example per network address, and close it if it is abused. The
  limit counts registrations that have succeeded or are still in
  progress, so that parallel connections cannot get around it (4.6).
  Other servers can answer abuse from such a server only by banning
  single identities or its whole domain (10.2), and a domain ban also
  shuts out that server's legitimate users.
- **Abuse.** Guests are anonymous. Servers SHOULD rate-limit commands and
  connections per network address, and limit how often they fetch any
  one key file. The `guests` setting restricts guests per room.
- **Room creation.** Anyone who controls a domain can make any number
  of identities, and each one can create rooms. Servers SHOULD limit how
  often one identity creates rooms (6.1), and can ban a whole domain
  that abuses this (10.2).
- **Display names** can be used to imitate other people (8.2).
  Bidirectional text controls can make one name look like another, or
  make the text after a name look like part of it. So clients compare
  names without them, and show the uid apart from the name. Servers can
  refuse names that contain them.
- **Reports and blocks.** Room owners and moderators do not learn who
  reported a message, but operators do (5.8). The server keeps reported
  messages until reports are resolved, even after their authors delete
  them. Blocks stop direct messages only (5.7). In rooms, people who
  have been blocked can still be seen by others and can still mention
  the person who blocked them.
- **Metadata.** The server sees who talks to whom, and when, even in
  encrypted conversations. There it also sees which devices each person
  uses, roughly how long messages are, file sizes, typing, read markers
  and presence. Because devices fetch key files themselves (12.12), the
  web server of an identity's domain learns the network addresses of
  devices that talk to it. Because identities work everywhere, different
  servers can tell that the same person uses all of them. Someone who
  does not want this can use a guest name or a separate identity.
- **Push.** Pushes carry no content (Section 9). The push service, and
  any gateway in between, still see when pushes happen and the unread
  count.
- **Deletion** removes text from the server, but not from copies that
  people have already made.
- **Files.** `get` URLs are capabilities (5.6). Anyone a URL is passed to
  can download the file, including people outside the room. In
  encrypted conversations they get only ciphertext (12.11). People will
  open these URLs in web browsers, so servers SHOULD serve files from a
  domain that is used for nothing else, and with the header
  `X-Content-Type-Options: nosniff`.
- **Operators** can read and remove anything on their server except the
  content of encrypted conversations, which they can only remove. ADMIN
  WHO shows them users' network addresses (10.3).

---

## 15. Assigned Values

- **Port:** 7472/tcp. The digits spell RISA on a phone keypad. The port
  is not yet registered with IANA.
- **ALPN identifier:** `risala/1`.
- **Well-known URI suffix:** `risala` [RFC8615].
- **URI scheme:** `risala://<host>[:<port>][/<room>[/<seq>]]`, where
  `<room>` is written without its `#`. For example,
  `risala://chat.example.org/general` points to `#general`, and
  `risala://chat.example.org/general/8813` to one message in it.
- **MLS cipher suite:** `0x0052`, for the algorithms of 12.2: X-Wing
  (HPKE KEM `0x647a`), ChaCha20-Poly1305, SHA-384 and ML-DSA-44. MLS
  cipher suites for post-quantum algorithms are not yet standardised
  [MLS-PQ]. This document fixes the meaning of `0x0052` for risala,
  whatever values a later standard assigns.
- **TLS key exchange:** X25519MLKEM768, value `0x11EC` [ECDHE-MLKEM].
- **MLS extension type:** `0xF2A1`, from the range for private use, for
  the conversation extension (12.2).
- **Labels:** the MLS exporter label `risala history` (12.9), the
  SignWithLabel label `risala message` and the ExpandWithLabel label
  `risala message key` (12.8), the HKDF info prefix `risala backup `
  (12.10), and the sign-in prefix `risala-auth-1` (4.5).

---

## 16. References

- [ECDHE-MLKEM] Kwiatkowski, K., Kampanakis, P., Westerbaan, B., and D.
  Stebila, "Post-quantum hybrid ECDHE-MLKEM Key Agreement for TLSv1.3",
  Internet-Draft draft-ietf-tls-ecdhe-mlkem, work in progress.
- [FIPS204] National Institute of Standards and Technology,
  "Module-Lattice-Based Digital Signature Standard", FIPS 204, August
  2024.
- [MLS-EXT] Robert, R., "The Messaging Layer Security (MLS)
  Extensions", Internet-Draft draft-ietf-mls-extensions, work in
  progress.
- [MLS-PQ] "MLS Cipher Suites with ML-KEM", Internet-Draft
  draft-ietf-mls-pq-ciphersuites, work in progress.
- [RFC2104] Krawczyk, H., Bellare, M., and R. Canetti, "HMAC:
  Keyed-Hashing for Message Authentication", RFC 2104, February 1997.
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
- [RFC5869] Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand
  Key Derivation Function (HKDF)", RFC 5869, May 2010.
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
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119
  Key Words", BCP 14, RFC 8174, May 2017.
- [RFC8439] Nir, Y. and A. Langley, "ChaCha20 and Poly1305 for IETF
  Protocols", RFC 8439, June 2018.
- [RFC8446] Rescorla, E., "The Transport Layer Security (TLS) Protocol
  Version 1.3", RFC 8446, August 2018.
- [RFC8615] Nottingham, M., "Well-Known Uniform Resource Identifiers
  (URIs)", RFC 8615, May 2019.
- [RFC9180] Barnes, R., Bhargavan, K., Lipp, B., and C. Wood, "Hybrid
  Public Key Encryption", RFC 9180, February 2022.
- [RFC9420] Barnes, R., Beurdouche, B., Robert, R., Millican, J., Omara,
  E., and K. Cohn-Gordon, "The Messaging Layer Security (MLS) Protocol",
  RFC 9420, July 2023.
- [RFC9525] Saint-Andre, P. and R. Salz, "Service Identity in TLS",
  RFC 9525, November 2023.
- [XWING] Connolly, D., Schwabe, P., and B. Westerbaan, "X-Wing: general-
  purpose hybrid post-quantum KEM", Internet-Draft
  draft-connolly-cfrg-xwing-kem-06, work in progress.

---

## Appendix A. Using risala by Hand

This needs OpenSSL 3.5 or later, for the post-quantum key exchange
(2.1) and ML-DSA (4.5). Encrypted conversations (Section 12) cannot be
used by hand.

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

If the hash printed is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, the
handshake failed and this is the hash of nothing, not a fingerprint. The
usual cause is an OpenSSL older than 3.5.

**Make a key, and print the line for your key file:**

```
openssl genpkey -algorithm ML-DSA-44 -out alice.pem
printf 'mldsa44 %s laptop\n' \
  "$(openssl pkey -in alice.pem -pubout -outform der | tail -c 1312 | openssl base64 -A)"
```

`genpkey` writes the private key in PKCS#8 with both the 32-byte seed
and the expanded private key. Appendix B shows the shorter seed-only
form, which `genpkey` writes if you add
`-provparam ml-dsa.output_formats=seed-only`. Clients that read private
keys from PEM files MUST accept both forms.

**Sign in.** Copy the nonce from the server's greeting. In a second
terminal, run:

```
printf 'risala-auth-1\n%s\n%s\n%s\n' chat.example.org <nonce> alice@example.org > chal
openssl pkeyutl -sign -rawin -inkey alice.pem -in chal | openssl base64 -A
```

The bytes to sign go in a file, because `pkeyutl` cannot read ML-DSA
input from a pipe and needs `-in`. Then type
`auth alice@example.org <signature>` in the first terminal. Servers
allow at least 120 seconds for this (4.1).

**Upload a file** (Section 5.6). Send `upload <size> <type> <name>`, then
PUT the file to the `put` URL from the response:

```
curl -T cat.png -H 'Content-Type: image/png' '<put URL>'
```

Then send `@file=<get URL> msg #general look at this`.

**Stay connected.** If the server sends `PING`, type anything, even an
empty line.

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

Key file line:

```
mldsa44 <the public key above, on one line> laptop
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

**History keys and encrypted messages** (12.8, 12.9). This vector
follows one message through the derivation of the history key and the
eight steps of encrypting it. It starts from the epoch's exporter secret
rather than from a whole MLS group, because a group's secrets depend on
random values that this document does not fix. The step from exporter
secret to history key is the MLS exporter, which can also be checked
against the MLS test vectors for cipher suite 7, since that suite uses
the same hash and KDF.

The signer is the key above, using the deterministic variant of
ML-DSA-44 as for AUTH. The random values of steps 2 and 6 are fixed, as
bytes counting up, so every correct implementation produces exactly
these bytes. The vector was generated with the MLS spike in the risala
repository (`spikes/mls`, `cargo run --release -- vectors`), which also
checks the exporter against the cipher suite 7 vectors, and each step
against a second implementation of its primitive.

Inputs, in hex:

```
exporter_secret (48 bytes):
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
202122232425262728292a2b2c2d2e2f

group_id (32 bytes):
404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f

epoch: 1

message_id (16 bytes):
808182838485868788898a8b8c8d8e8f

frank_key (32 bytes):
a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf

salt (32 bytes):
c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
```

The content is the reply of 12.8, 61 bytes including its LF:

```
@reply=15;target=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12
```

The history key (12.9), and the DeriveSecret step on the way:

```
DeriveSecret(exporter_secret, "risala history"):
0d81c7a79130adc8f81c42aaf57395c52332450d604544f5e34436e7c81fc423
0fcb06c5154c001efa43ff711e597b43

history_key:
a7187b710141caab8322e9f1cc1664a78d63821d360ce6ece27bec3b03e886d5
a87d17f40b15c365a59b238b80e568d0
```

The steps of 12.8:

```
sender_key_id, step 3:
9dd34a4b2e6712ac7d2c679a46caaaaf875c945aefc33a78cefe1a014b9dacfa
0f7c1460fbe5d395af0b70f54d51a994

RisalaMessageTBS, step 4 (199 bytes):
20404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e
5f0000000000000001808182838485868788898a8b8c8d8e8f9dd34a4b2e6712
ac7d2c679a46caaaaf875c945aefc33a78cefe1a014b9dacfa0f7c1460fbe5d3
95af0b70f54d51a994a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6
b7b8b9babbbcbdbebf3d407265706c793d31353b7461726765743d304a783148
6b593378397a326235523071576d3166413d3d20544558542073656520796f75
2061742031320a

signature, step 4: 2420 bytes, SHA-256
64033444c9e465b935808dcb6cf257b77ada5579f5fe82a40e4d0b9340939b07

RisalaMessage, step 5: 2816 bytes, SHA-256
a070ee7fdfc54f7caf69e20be49447642f49f825d705f21882723d3700287d62

message key, step 6:
34820bd2a459f65486d86ed9f9fcf984d9c8069bd2dc088affe4af93f5202e11

RisalaMessageAAD, step 7 (41 bytes):
20404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e
5f0000000000000001

payload, step 8: 2864 bytes, SHA-256
737abc1cf8642de1064a4fee45f6732d4caa7fbe8d492079fcb61ee4713d47ff

frank tag, step 8:
83d717202ee3a882e770e8ceaa04ff715561ecd5574e6576839cb99ec98f8b96
0277c6cc92ce07971b46e3a6935798ca
```

Before padding, RisalaMessage is 2581 bytes. Step 5 adds 234 zero bytes
of padding, and the length prefix of `padding` grows to two bytes, which
makes 2816, or 11 times 256.

The payload, in base64 (3820 characters, wrapped at 64 like the
signature above), and the `frank` tag as it appears on the ENC line:

```
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
```

```
g9cXIC7jqILncOjOqgT/cVVh7NVXTmV2g5y5nsmPi5YCd8bMks4HlxtG46aTV5jK
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
