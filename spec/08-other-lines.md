## 8. Other Lines

### 8.1. Typing

A device tells the other members that its user is typing with a message
whose content is a single TYPING line (12.9), posted with `live=yes`
(5.2), so that the server neither keeps nor pushes it:

```
TYPING
```

A typing notification lasts 6 seconds, so clients repeat it about every
4 seconds while the user types. A message from the same member ends it.
Devices ignore typing from members who may not send messages (6.2).

Every message carries an ML-DSA signature of 2420 bytes, so typing costs
every member's device a few kilobytes each time. Devices SHOULD NOT send
typing notifications in rooms of more than 100 members.

### 8.2. Display Names

A member's display name is part of its leaf, in the profile extension
(12.3), so it is authenticated by the leaf and every member sees the
same one, including members who join later. A device sets or changes it
with a commit that updates its own leaf. Display names are free text of
up to 128 bytes, for example "Alice Martin" or "عائشة". There is no NAME
command, and the server never sees display names, except in public
rooms, whose tree it holds.

Display names are not unique and prove nothing, since anyone can call
themselves anything. Clients SHOULD show the uid whenever two people in
a conversation share a display name, and whenever the user asks:

- To decide whether two people share a display name, a client compares
  the names after removing bidirectional text controls (U+061C, U+200E,
  U+200F, U+202A to U+202E and U+2066 to U+2069) and zero-width
  characters (U+200B to U+200D, U+2060 and U+FEFF), which are invisible,
  ignoring case, and collapsing each run of whitespace into one space,
  with none at either end.
- A client SHOULD show the uid as a separate element, not as text
  appended to the name, so that a name cannot pass for a uid. It SHOULD
  always show the uid when a name contains `@`, or a character that
  looks like one such as U+FF20 or U+FE6B, or otherwise looks like a
  uid.
- A client SHOULD show the safety number status of an identity (12.14)
  next to its name where it matters, such as in a direct conversation.

Devices MAY ignore display names that contain bidirectional text
controls, and show the uid instead.

### 8.3. Presence and Members

Whether an identity is online is the one thing about people that the
server keeps in the clear. An identity is **online** while it has at
least one signed-in connection, and **offline** otherwise.

```
PRESENCE ON
PRESENCE OFF
WATCH [<uids>]
WHOIS <uid>
MEMBERS <room>
```

- **`PRESENCE ON`** and **`PRESENCE OFF`** choose whether the server
  reports the identity's presence to anyone, and reply `OK`. They need a
  signed-in connection. The default is `OFF`, since the server cannot
  tell who shares a conversation with whom and so cannot limit presence
  to them: while it is `ON`, anyone on the server can see it. While it is
  `OFF`, the identity is reported as `offline` to everyone. Clients ask
  before turning it on.
- **`WATCH`** sets the list of identities the connection wants presence
  for, replacing any earlier list, and replies with one
  `USER <uid> <presence>` line for each, then `OK`. `<uids>` is one or
  more uids, separated by commas with no spaces. Without `<uids>`, it
  clears the list. A server MAY limit the list, but MUST allow at least
  1,000 uids.
- **`WHOIS`** replies `USER <uid> <presence>`, then `OK`, or
  `ERR not-found` for an identity the server does not know.
- **`MEMBERS`** replies with one `MEMBER <room> <uid> <role> <presence>`
  line for each identity and guest with a leaf in a public room's group,
  then `OK`. `<role>` is `owner`, `mod` or `member`, from the room's
  conversation extension. Light clients (12.6), which do not hold the
  tree, use it to show members. Devices that hold the tree check it
  against their own. A room that is not public gets `ERR not-found`.

When a watched identity comes online or goes offline, the server tells
the connections that watch it:

```
PRESENCE <presence> <uids>
```

```
S: PRESENCE online alice@example.org,bob@example.net
S: PRESENCE offline carol@example.com
```

- `<presence>` is `online` or `offline`. Clients SHOULD show an unknown
  value as `online`.
- The server SHOULD collect changes for a short time, up to a few
  seconds, and send them together. It splits a list that does not fit
  within the line length limit (2.3) over several lines.
- The server SHOULD wait about 30 seconds after an identity's last
  connection closes before reporting it `offline`, so that a client
  reconnecting does not make it blink off and on.
- Guests have no presence. A guest is a member of a room for as long as
  it has a leaf there (6.1).

WATCH, WHOIS and MEMBERS work on any kind of connection. A client SHOULD
send WATCH on an anonymous connection, since the list says whom the user
talks to. Section 14 says what presence still reveals.

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
| `anon=yes` or `anon=no` | Whether anonymous connections are allowed (4.2). A server that allows none cannot carry conversations |
| `guests=yes` or `guests=no` | Whether guests are allowed |
| `register=<domain>` or `register=no` | The identity domain for REGISTER, or `no` if the server offers no registration or it is closed right now |
| `log=<url>` or `log=no` | The URL prefix of the server's current key log (4.5), or `no` if it keeps none |
| `log-key=<vkey>` | The signed-note verifier key of that log (4.4), present only with `log=<url>` |
| `retention=<days>` | How long posts, files and blobs are kept (7.5) |
| `push=yes` or `push=no` | Whether PUSH is supported |
| `upload=<bytes>` or `upload=no` | The largest file UPLOAD accepts, or `no` if the server offers no uploads (5.6) |
| `blobs=<url>` | The URL prefix that blobs are fetched from (12.12) |
| `files=<origins>` | The origins of the server's `get` URLs (5.6), as `https://<host>[:<port>]`, separated by commas. Present only with uploads |

`INFO <room>` is described in Section 6.1.
