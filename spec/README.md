# risala

```
risala                                                        draft-03
A Modern Chat Protocol                                      2026-11-08
Status: Draft. Anything in this document may change.
Copyright (c) 2026 Risala developers. Licensed under CC BY 4.0.
```

## Abstract

risala is a protocol for real-time chat on independent servers, in
which the server is not trusted with anything it does not need. It
provides:

- end-to-end encryption for every conversation, public rooms included,
  using MLS with post-quantum algorithms and a new key for every message
- deniable messages: a leaked message does not prove to anyone else who
  wrote it
- sealed sending and hidden membership: the server does not learn who
  sends a message, or who is in a direct conversation or a private room
- portable identities built on domain names, with keys published in a
  witnessed transparency log
- rooms of up to 10,000 members, and guest access to public rooms
- replies, edits, reactions, encrypted files and encrypted push
  notifications
- a standard set of commands for server operators

Servers do not federate: every conversation lives on exactly one server.
Servers keep no history: they hold encrypted messages only until the
devices of a conversation have had time to fetch them. History lives on
people's devices, which pass it to new devices themselves.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC2119] [RFC8174] when, and only when, they appear in all capitals, as
shown here.

Grammar is written in ABNF [RFC5234]. Binary structures are written in
the presentation language of TLS [RFC8446], with the variable-length
vectors (`<V>`) of MLS [RFC9420]. In examples, `C:` marks a line sent by
the client and `S:` a line sent by the server. These prefixes are not
part of the protocol. Examples use the domain names reserved by
[RFC2606], and long base64 values are shortened with `…`.

## Contents

The spec is this file followed by the files below, in order. Section
numbers run across all of them, so a reference such as "(12.9)" means
Section 12.9, in the file for Section 12.

| File | Section | What it covers |
|---|---|---|
| [01-introduction.md](01-introduction.md) | 1. Introduction | Goals, non-goals and an example session |
| [02-transport.md](02-transport.md) | 2. Transport | TLS, verifying the server, lines and their limits, versions |
| [03-message-format.md](03-message-format.md) | 3. Message Format | Grammar, tags, parameters, escaping, names, responses and error codes |
| [04-identity-and-authentication.md](04-identity-and-authentication.md) | 4. Identity and Authentication | Kinds of connection, guests, key files, the witnessed key log, signing in, registration, pairing and recovering devices |
| [05-conversations.md](05-conversations.md) | 5. Conversations | Kinds of conversation, mailboxes and posts, messages, deletes, mentions, files, blocking and reports |
| [06-rooms.md](06-rooms.md) | 6. Rooms | Public and private rooms, joining and leaving, settings, roles and moderation |
| [07-delivery-and-sync.md](07-delivery-and-sync.md) | 7. Delivery and Sync | Following mailboxes, send tokens, pseudonyms, catching up, retention and read markers |
| [08-other-lines.md](08-other-lines.md) | 8. Other Lines | Typing, display names, presence, notices and server information |
| [09-push-notifications.md](09-push-notifications.md) | 9. Push Notifications | Mailbox and account subscriptions, and encrypted pushes |
| [10-server-administration.md](10-server-administration.md) | 10. Server Administration | Operators, bans, connections, rooms and mailboxes, hosted identities and settings |
| [11-keepalive-and-closing.md](11-keepalive-and-closing.md) | 11. Keepalive and Closing | PING, QUIT and BYE |
| [12-end-to-end-encryption.md](12-end-to-end-encryption.md) | 12. End-to-End Encryption | MLS, leaf keys, the conversation extension, KeyPackages, commits, Welcomes, messages, confirming leaves, files, blobs, history and backups, safety numbers |
| [13-command-summary.md](13-command-summary.md) | 13. Command Summary | Every command, who may send it, and every server line |
| [14-security-considerations.md](14-security-considerations.md) | 14. Security Considerations | What is protected, what the server still learns and can do, and the risks accepted |
| [15-assigned-values.md](15-assigned-values.md) | 15. Assigned Values | Port, ALPN, cipher suite, extension types and labels |
| [16-references.md](16-references.md) | 16. References | Standards and papers cited |
| [a-checking-a-server-by-hand.md](a-checking-a-server-by-hand.md) | Appendix A | Checking a server and its fingerprint from a terminal |
| [b-test-vectors.md](b-test-vectors.md) | Appendix B | Test vectors, and the ones still to come |
| [c-push-gateways.md](c-push-gateways.md) | Appendix C | How push works with Apple's and Google's services (informative) |
| [d-threat-model.md](d-threat-model.md) | Appendix D | Adversaries, what each can and cannot do, non-goals, accepted risks, assumptions and changes (informative) |
