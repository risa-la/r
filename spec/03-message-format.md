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

Verbs are case-insensitive, so `post` and `POST` mean the same. Servers
send verbs in upper case. This document writes client commands in upper
case too. Receivers SHOULD accept runs of spaces between the tags and the
verb, as between tokens (3.3).

Tag keys are always lower case. Elsewhere, where the ABNF in this
document lists only `a-z` for something case-insensitive, such as option
keys, names and keywords, it describes the form after folding:
receivers fold ASCII upper case to lower case first.

### 3.2. Tags

Tags carry metadata: the sequence number and time of a post, and the
id that matches a response to its command. Who wrote a message, and
what it replies to, are inside the encryption (12.9), where the server
cannot see them.

- The order of tags does not matter. A line MUST NOT repeat a tag key.
- A lone `@` carries no tags. Receivers MUST accept it, and senders
  SHOULD leave it out.
- Receivers MUST ignore tags they do not understand.
- A server copies no tag from a client command onto the post the
  command causes.
- Tag keys that begin with `x-` are reserved for experiments.
- The content of an encrypted message has tags of its own, which never
  appear on the connection (12.9).

| Tag | Set by | Value | Meaning |
|---|---|---|---|
| `ref` | client | tag value, at most 64 bytes | Matches a response to its command (3.6) |
| `seq` | server | sequence number | The post's position in its mailbox (5.2) |
| `t` | server | timestamp | When the server accepted the post or report |
| `from` | server | uid | On a report: who made it, if they were signed in (5.8) |
| `cid` | client | tag value, at most 64 bytes | Client post id for safe resending (7.6) |
| `retry` | server | seconds | With `ERR rate-limited` or `ERR unavailable`: when to try again |
| `report` | server | id | The report that a line belongs to (5.8) |
| `pseudonym` | server | base64 | On a report: the target post's pseudonym (5.8) |

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
box        = 26( %x61-7A / %x32-37 )            ; a-z 2-7: 16 bytes, base32
seq        = %x31-39 *18DIGIT                   ; 1 to 2^63-1
id         = 1*64( alnum / "-" / "_" )          ; report or Welcome id
blob-ref   = "sha384:" 96( DIGIT / %x61-66 )    ; a blob's hash, lower-case hex
timestamp  = full-date "T" time-hour ":" time-minute ":"
             time-second "." 3DIGIT "Z"         ; RFC 3339, UTC
```

- Timestamps are always UTC, with milliseconds. Senders write `T` and
  `Z` in upper case, and receivers MAY accept lower case. Seconds run
  from 00 to 59: leap seconds are not used.
- A **uid** identifies a user. It is either a guest such as `~sam`
  (Section 4.2) or an identity such as `alice@example.org` (4.3).
- A **box** names a mailbox, the place on the server where one
  conversation's posts are kept (5.2). It is 16 random bytes in
  lower-case base32 [RFC4648], without padding. A **room** name is used
  only for public rooms, to find them (6.1).
- A **blob-ref** names a blob, by the SHA-384 hash of its bytes (12.12).
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
  final response, such as the posts FETCH returns or the lines LIST
  returns. If the command had a `ref` tag, the server copies it onto
  these lines and onto the final response. This includes the `ERR` for a
  command it cannot parse, as long as it can still read a valid `ref`
  from the line's tags.
- **Consistent with live posts.** The `OK` of FOLLOW (7.1), which
  reports a mailbox's head, agrees with the live posts the connection
  receives. Every post of that mailbox sent to the connection before the
  `OK` is covered by it, and every post sent after it is newer. A server
  does this by queuing the `OK` while no post of that mailbox can be
  queued.
- **Live posts.** Posts that a command causes, such as the post a POST
  creates, are not part of its response. They go to every connection
  that follows the mailbox, without `ref`. The connection that sent the
  command receives the post before its final response if it follows the
  mailbox.

```
C: @ref=7 fetch ujzdegxdncf32epf3dhodzdoci after=9120 limit=2
S: @ref=7;seq=9121;t=2026-11-08T15:40:58.120Z POST ujzdegxdncf32epf3dhodzdoci AAEAAQ…
S: @ref=7;seq=9122;t=2026-11-08T15:41:02.377Z POST ujzdegxdncf32epf3dhodzdoci AAEAAg…
S: @ref=7 OK more=1
```

### 3.7. Error Codes

| Code | Meaning |
|---|---|
| `bad-syntax` | The line could not be parsed, or has the wrong parameters |
| `unknown-command` | The verb is not known |
| `too-long` | The line or one of its parameters is too long, or a file, blob or KeyPackage is too large |
| `not-authenticated` | The command needs ANON, GUEST, AUTH or REGISTER first, or needs a signed-in connection (4.1) |
| `already-authenticated` | This connection is already anonymous, a guest or signed in |
| `auth-failed` | The signature did not verify against the identity's keys, or the connection's SNI does not name this server (4.6) |
| `name-taken` | The guest name, identity name, room name or mailbox is already in use |
| `not-found` | The room, mailbox, user, post or blob does not exist, or is not visible to you |
| `forbidden` | Not allowed because of permissions, a ban, a mute or server policy |
| `not-supported` | The server does not offer this feature |
| `stale` | The send token is not valid for that epoch, or the epoch is too old: catch up on the mailbox and try again (7.2, 12.6) |
| `invalid` | MLS data, a key file, a signature or a franking commitment did not verify, or something required is missing (Sections 4, 5.8 and 12) |
| `rate-limited` | Too many requests. The `retry` tag says when to try again |
| `unavailable` | The server could not get an identity's key file, so it could not check a signature or which keys the identity has. Try again later (4.6, 12.5) |
| `internal` | Something went wrong on the server |

A name, room, id, text, URL or tag value that follows its grammar except
for being too long gets `too-long`, not `bad-syntax`. A number, key,
signature, token, hash or mailbox with the wrong number of digits or
characters gets `bad-syntax`, and so does base64 that is not valid.

Clients MUST treat an unknown code as a general failure.

### 3.8. Extending the Protocol

- **New verbs** may be added. Servers reply `ERR unknown-command` to
  verbs they do not know, and clients ignore lines with verbs they do not
  know. An unknown subcommand of a known verb, such as `KEYPKG FOO`, also
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
