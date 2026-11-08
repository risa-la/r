## 10. Server Administration

Every server has one or more **operators**: identities that may use the
ADMIN commands in this section. Standard commands mean any client can
offer administration tools for any server.

- Anyone who is not an operator gets `ERR forbidden` for every ADMIN
  command. ADMIN commands need a signed-in connection.
- A server MAY leave out commands that do not apply to it and reply
  `ERR not-supported`. For example, a server that hosts no identities has
  no use for the commands in Section 10.5.
- Operators cannot read any conversation, and have no role in any room
  (6.3). They see what the server sees (Section 14), and the content of
  reports made to them (5.8). They can refuse service: drop mailboxes
  and rooms, mute pseudonyms, and ban identities and network addresses.
- The ADMIN commands create no posts.

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
learns it is an operator from the `op=yes` value when it signs in (4.6).

### 10.2. Bans

```
ADMIN BAN <target> [<reason...>]
ADMIN UNBAN <target>
ADMIN BANS
```

`<target>` is one of these:

| Target | Example | Effect |
|---|---|---|
| An identity | `spam@example.net` | That identity cannot sign in, and its devices cannot join public rooms |
| A domain | `*@example.net` | The same, for every identity at that domain or any of its subdomains |
| A connected guest | `~sam` | Bans the network address the guest is connected from |
| A network address or prefix | `203.0.113.7`, `2001:db8::/32` | No anonymous or guest connection can be opened from it |

- **Identity and domain bans.** AUTH and REGISTER reply `ERR forbidden`
  for a banned identity. They check the signature first, and reply
  `ERR auth-failed` if it does not verify, so that only someone holding
  the identity's key learns that it is banned. A banned identity's open
  signed-in connections are closed with BYE. The server also refuses
  joins of public rooms by its devices (6.1). It cannot stop the
  identity from posting in private conversations it is already in, since
  it cannot tell who posts there.
- **Address bans** apply to anonymous and guest connections, which say
  nothing else about who opens them. Signed-in connections from the same
  address are not affected, so that people who share an address with a
  spammer, such as at a university or on a mobile network, can still
  sign in. A new address ban also closes the anonymous and guest
  connections from inside it, with BYE, and ends the guest sessions
  whose last connection came from inside it.
- **Banning a guest** bans the address it is connected from: the
  IPv4 address itself, or the IPv6 `/64` that contains it, since one
  IPv6 user usually holds a whole `/64`. BANS lists the ban under the
  address it applies to, and ADMIN UNBAN takes that address, not the
  guest's uid.
- **`ADMIN UNBAN`** of a target that is not banned gets `ERR not-found`.
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
  open connection, then OK. `<uid>` is the identity or guest, or `-` for
  an anonymous connection or one that has not signed in yet. `<address>`
  is the client's IP address, optionally with its port, written
  `203.0.113.7:51000` or `[2001:db8::1]:51000`. `<since>` is a timestamp.
- **`ADMIN DISCONNECT`** closes every connection of `<uid>`, sending
  `BYE` with the reason. The user can reconnect; ban them to stop that.
  For a guest, it also ends a session waiting to be resumed (4.2). A uid
  with no connection and no session gets `ERR not-found`.
- **`ADMIN NOTICE`** sends `NOTICE <message...>` to every open connection.

### 10.4. Rooms and Mailboxes

```
ADMIN ROOMS [after=<room>] [limit=<n>]
ADMIN DROP <target> [<reason...>]
ADMIN MUTE <box> <pseudonym> [hours=<n>]
ADMIN UNMUTE <box> <pseudonym>
ADMIN REPORTS
```

- **`ADMIN ROOMS`** lists every public room, as `ROOM` lines (6.1), then
  `OK more=<0 or 1>`. It pages like LIST. The server knows no private
  rooms.
- **`ADMIN DROP`** deletes a public room, named by `<room>`, or any
  mailbox, named by `<box>`, together with all of its posts. This cannot
  be undone.
  - The server sends `DROP <box> [<reason...>]` to every connection that
    follows the mailbox (6.1), and deletes its push subscriptions. Files
    uploaded for it expire as usual (7.5).
  - Open reports about its posts stay, with their copies, until an
    operator resolves them (5.8).
  - A dropped room's name becomes free. A new room with that name is a
    new group with a new mailbox. Links that name the old room (Section
    15) lead to the new one, which devices see is a different group.
  - The box and group id of a dropped mailbox are never used again
    (5.2).
- **`ADMIN MUTE`** and **`ADMIN UNMUTE`** work like MUTE and UNMUTE
  (6.4), for any mailbox.
- **`ADMIN REPORTS`** lists every open report (5.8).

There is no command that deletes what one person has posted, since the
server cannot tell which posts are whose. Room moderators delete
messages (5.4), and posts expire with retention (7.5).

### 10.5. Hosted Identities

```
ADMIN UNREGISTER <uid>
```

- **`ADMIN UNREGISTER`** deletes a hosted identity (4.7), as UNREGISTER
  (4.9) does: the server stops publishing its key file and answers 410
  for it, and closes its connections. Its records stay in the log.
  - The server SHOULD NOT let anyone register the same name again. Other
    servers and devices would take the new owner for the old one, or see
    a fork (4.5).

Operators cannot add or remove an identity's keys, and so cannot help
someone who has lost every device and the recovery key. That person
needs a new identity (4.8).

### 10.6. Server Settings

```
ADMIN SET <key> [<value...>]
```

| Key | Values | Meaning |
|---|---|---|
| `anon` | `yes` or `no` | Whether anonymous connections may be opened |
| `guests` | `yes` or `no` | Whether guests may connect |
| `registration` | `open` or `closed` | Whether REGISTER is accepted |
| `retention` | a number of days, at least 7 | The server's retention period (7.5) |
| `welcome` | any text up to 512 bytes | The message in the greeting (4.1) |

Keyword and number values ignore trailing spaces, and the welcome text
keeps them.

- Changes take effect immediately and show in INFO (8.5).
- Setting `guests` to `no` also ends every guest session: guests
  connected now get `BYE`, and sessions waiting to be resumed (4.2) end
  too.
- Setting `anon` to `no` closes every anonymous connection with `BYE`.
- Shortening `retention` also applies to posts already stored.
- Settings not listed here are left to the server's configuration.
