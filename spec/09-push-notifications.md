## 9. Push Notifications

Phones do not let apps keep connections open in the background. Push
lets a server wake an app when something needs attention. In risala, a
push says only that a mailbox has something new, or that the device has
a Welcome, and even that is encrypted to the device. The app then
connects and fetches the rest itself, over TLS.

### 9.1. Registering

```
PUSH ADD <url> <tag> <key> <auth> [box=<box> token=<token>]
PUSH DEL <url> [box=<box>]
PUSH LIST
```

- **`PUSH ADD`** asks the server to send pushes to `<url>`, an `https`
  URL of at most 512 bytes, and replies `OK`.
  - `<tag>` is 1 to 64 characters of printable ASCII (%x21-7E), chosen
    by the client, so that it can also be the value of a `quiet` option
    (7.1). It goes inside the encrypted body of every push, so the app
    knows what the push is about. Clients SHOULD choose a random tag for
    each subscription. The server compares tags byte for byte, within
    one mailbox.
  - `<key>` and `<auth>` are the subscription's P-256 public key, 65
    bytes, and its 16-byte authentication secret, each in base64 with
    padding. The server encrypts every push to them (9.3) [RFC8291].
  - With `box`, `<token>` is a send token of the mailbox's group, in
    base64 with padding, checked as for POST (5.2), so that only
    members can make or renew a mailbox subscription, without saying
    who they are. `box` and `token` come together (`ERR bad-syntax`).
  - Adding a URL that is already registered for the same mailbox, or for
    the same account, replaces its tag and keys, and renews it.
- **`PUSH DEL`** removes a subscription, and replies `OK`.
- **`PUSH LIST`** sends one `PUSH <url> <tag>` line for each of the
  device's account subscriptions, then OK.

```
C: push add https://push.example.net/w/q8c2Kf7 x7Kq2Lm9 BPLv7Mu8MXeNuZsIjwXGESxN4Q6ECl+wNXnodsPViB3HHjowvzVNQ3gdAyQwbezeAJXJXgnKhCGU2vyDnaDstEM= 7OISsGXIbzgRA8TyyMbgaA==
S: OK
C: push list
S: PUSH https://push.example.net/w/q8c2Kf7 x7Kq2Lm9
S: OK
```

There are two kinds of subscription:

- **Mailbox subscriptions,** with `box`, wake the device when a mailbox
  has a new post. They are made on an anonymous connection, and belong
  to no identity. The server learns that someone follows the mailbox
  through that URL, but not who. A mailbox subscription lasts one
  retention period (7.5) from the PUSH ADD that made or renewed it, so
  that a device that has left a group, or been removed or stolen, stops
  getting its pushes. A device renews each of its mailbox subscriptions
  with PUSH ADD, on the anonymous connection it posts from, at a random
  time at least once a week, for example with its weekly commit in that
  group (12.7). It deletes the subscription with PUSH DEL when it leaves
  the group, or when the group moves (7.8).
- **Account subscriptions,** without `box`, wake the device when it has a
  new Welcome (12.8). They are made on a signed-in connection, and
  belong to its device key. Removing the device removes them.

A client SHOULD use a different URL for every subscription, which push
gateways can provide (Appendix C), so that the server cannot link a
device's subscriptions by their URL. A server MUST limit the number of
subscriptions per mailbox, per connection and per device
(`ERR rate-limited`), so that nobody can make it send many pushes to one
URL. The limit per mailbox MUST allow at least one subscription for
each leaf that the group may hold (6.1). Guests cannot register for
push.

### 9.2. When to Push

- **A mailbox subscription** gets a push when the mailbox gets a post
  that is kept (not `live=yes`, 5.2).
- **An account subscription** gets a push when a Welcome arrives for its
  device.

The server MUST send at most one push every 10 seconds to each
subscription, and to each URL, whichever subscriptions it belongs to.
Posts that arrive in between go into the next push.

All of a mailbox's subscriptions would otherwise get their pushes at the
same moment, and the push services and gateways that carry them would
see the same devices woken together, again and again, which shows who
shares a conversation. So the server MUST delay each subscription's push
by a random time of its own, of up to 10 seconds by default, chosen
independently of the mailbox's other subscriptions. Clients MAY let the
user turn off mailbox pushes for a conversation, and then check it from
time to time instead.

The server does not push to a subscription while the device is
connected and reading:

- For a mailbox subscription, that is while a connection follows the
  mailbox with `quiet=<tag>` (7.1), where `<tag>` is the subscription's.
  A `quiet` tag stays the same from one session to the next, and so
  links them (7.4). Devices SHOULD leave it out, and drop pushes that
  arrive while they are reading.
- For an account subscription, it is while the device key has a
  signed-in connection.

A connection can still look open after its device has lost the network,
until the idle timeout closes it (Section 11). That could hold back
pushes for minutes. So when such a connection exists, the server checks
that it is alive:

1. On each of those connections that it has received nothing on in the
   last 10 seconds, the server sends `PING`.
2. If 10 seconds later none of them has sent a line since the check
   began, the server pushes as if there were none.

A mobile client SHOULD send QUIT when the app goes to the background and
stops reading from its connections, so that pushes start straight away.
It SHOULD close its connections one at a time, a short random time
apart, rather than all at once, which would show that they belong to one
device (7.4).

The server cannot tell which posts are worth a notification, or who
sent them. The device decides that once it has fetched and decrypted the
post: for example, it notifies the user of direct messages and
mentions, and not of their own messages or of read markers. A READ line
from another of the identity's devices (7.7) lets it clear a
notification it has already shown.

### 9.3. The Push Request

```
POST <url> HTTP/1.1
Content-Encoding: aes128gcm
TTL: 86400
Urgency: <urgency>

<encrypted body>
```

The body is encrypted with Message Encryption for Web Push [RFC8291],
to the subscription's key and authentication secret, using the
`aes128gcm` content coding [RFC8188]. Once decrypted, it is one line in
the format of Section 3, ending with LF:

```
NOTIFY <tag> <reason>
```

`<reason>` is `message` for a mailbox subscription and `welcome` for an
account subscription. A reason is 1 to 32 characters of `a-z`, `0-9` and
`-`. Later versions may add reasons. An app treats a reason it does not
know as new activity, and connects and syncs as for any other push.

The server pads the line with the record padding of [RFC8188] to 128
bytes before it encrypts it, so that every push body has the same size
whatever the tag. It makes a fresh ephemeral key for every push, as
[RFC8291] requires. `<urgency>` [RFC8030] is `high` for a `welcome`
push, and `normal` for a `message` push.

When sending a push, the server:

- MUST use HTTPS and validate the certificate
- MUST NOT follow redirects
- MUST apply the address restrictions of Section 4.4
- SHOULD give up on a request after 10 seconds

How the server handles the response:

- **2xx:** the push was accepted.
- **404 or 410:** the server MUST delete the subscription.
- **Any other failure:** the server SHOULD retry with increasing delays,
  and MAY delete the subscription after a day of failures.

When an app receives a push, it decrypts the body and uses the tag to
find what the push is about. For a mailbox, it connects anonymously,
fetches the new posts (7.4), and shows its own notification if one is
due. For a Welcome, it signs in and sends WELCOME LIST (12.8). If the
app cannot finish in time, it shows nothing, or a generic notification
such as "New activity". Appendix C explains how this works with Apple's
and Google's push services.
