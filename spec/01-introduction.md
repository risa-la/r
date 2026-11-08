## 1. Introduction

risala is a modern chat protocol. A client connects to a server over
TLS, and the two exchange lines of UTF-8 text. People talk in rooms and
in direct conversations, under identities that work on any server.

Every conversation is an MLS group [RFC9420]. The server carries the
group's encrypted messages, but cannot read them, cannot tell who sent
them, and, outside public rooms, cannot tell who is in the
conversation. Devices check everything the server tells them that
matters: whose keys are whose, who may change a group, and what was
said.

### 1.1. Goals

- **Zero trust in the server.** Devices never take the server's word for
  anything they show or act on, or for whose keys are whose. Whatever a
  server can still do is listed in Section 14, and devices see most of
  it.
- **Everything encrypted.** Every conversation is end-to-end encrypted,
  public rooms included. There are no plaintext rooms. Each message has
  its own key, which devices delete once they have used it.
- **Deniable.** Messages are authenticated to the people in the
  conversation, but a message that leaks does not prove to anyone else
  who wrote it (12.10).
- **Little metadata.** The server does not learn who sends a message, or
  who is in a direct conversation or a private room (Section 7). What it
  still learns is listed in Section 14 and Appendix D.
- **Signal's kinds of protection.** Per-message forward secrecy,
  post-compromise security, post-quantum keys, sealed sending and key
  transparency. Where they are weaker than Signal's, for example
  post-compromise security that heals with each commit rather than each
  round trip, Section 14 says so.
- **Post-quantum.** Connections and conversations use hybrid
  post-quantum key exchange, so recorded traffic stays secret against a
  future quantum computer. Signatures use ML-DSA.
- **Rooms of thousands.** Private rooms of up to 1,000 members, and
  public rooms of up to 10,000 (6.1).
- **Independent servers.** Anyone can run a server. No server is special,
  and nothing depends on central infrastructure apart from the public
  witnesses of the key log (4.5).
- **Portable identity.** A person can prove the same identity, such as
  `alice@example.org`, to any server. Its keys are published in a log
  that witnesses check, so that a key cannot be swapped unnoticed. No
  operator can reset an identity.

### 1.2. Non-goals

This version does not provide:

- **Federation.** Messages never move between servers.
- **History on the server.** A server keeps encrypted messages only for
  its retention period (7.5), so that offline devices can catch up.
  Someone who joins a room sees only what is sent after they join. A
  person's own devices pass history to each other (12.13).
- **Hiding network addresses and timing.** The server sees the network
  address of every connection and when it sends. There is no support for
  Tor or other anonymity networks in this version (Section 14).
- **Hiding presence.** Whether an identity is online is kept by the
  server (8.3).
- **Browser clients.** There is no WebSocket or HTTP transport. Clients
  are native applications.
- **Binary data on the chat connection.** Files and large MLS objects
  travel over HTTPS (5.6, 12.12). Smaller MLS data travels in base64.
- **Group direct conversations.** A conversation is either a direct
  conversation between two people or a room. A group talks in a room,
  which can be private.
- **Operator resets.** No operator can give someone a new key for an
  identity. The recovery key is the only way back after losing every
  device (4.8).

### 1.3. Overview

```
S: RISALA 1 chat.example.org 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e Welcome!
C: anon
S: OK
C: list
S: ROOM #general ujzdegxdncf32epf3dhodzdoci 812 General chat. Be kind.
S: OK more=0
C: groupinfo ujzdegxdncf32epf3dhodzdoci
S: GROUPINFO ujzdegxdncf32epf3dhodzdoci 4410 9120 AAEABA… sha384:5d0c9a1e…
S: OK
C: follow ujzdegxdncf32epf3dhodzdoci
S: OK head=9121
S: @seq=9122;t=2026-11-08T15:40:51.208Z POST ujzdegxdncf32epf3dhodzdoci AAEAAQ… next=OWLXhHTd2X+O1uwHQ2Ylsj9LLdW2htn4UhwDp6x6TDrnYCbdMAQ4Hu4/aEVDqmGm
C: post ujzdegxdncf32epf3dhodzdoci 3J0nq8V2yXcY7Hq5uWmZ1aRk0tPpL9eBvC4sD6fG8hE= AAEAAg…
S: @seq=9123;t=2026-11-08T15:41:02.377Z POST ujzdegxdncf32epf3dhodzdoci AAEAAg…
S: OK seq=9123
S: @seq=9124;t=2026-11-08T15:41:09.512Z POST ujzdegxdncf32epf3dhodzdoci AAEAAg…
```

In this session:

1. The server greets the client, and the client opens an anonymous
   connection: it will not say who it is.
2. It lists the public rooms. `#general` has the mailbox
   `ujzdegxdncf32epf3dhodzdoci`.
3. It fetches the room's group information, and asks to join the
   room's MLS group by posting an external proposal (seq 9121). The
   proposal names the device, so the client posts it on a connection
   of its own (4.1, not shown). A join needs no send token (`-`).
4. It follows the mailbox, so that new posts reach it as they arrive.
   A member's device commits the proposal, and the client fetches its
   Welcome on a connection of its own (not shown). The commit carries
   the hash of the new epoch's send token (`next`).
5. It posts an encrypted message, proving with a send token that it is
   a member of the group in the current epoch.
6. It receives another member's message. The server does not know who
   sent either message. Inside the encryption, each says who wrote it
   and when.
