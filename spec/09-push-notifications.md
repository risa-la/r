## 9. Push Notifications

Phones do not let apps keep connections open in the background. Push
lets a server wake an app when something needs attention. In risala, a
push says only that a mailbox has something new, or that the device has
a Welcome, and even that is encrypted to the device. The app then
connects and fetches the rest itself, over TLS.

### 9.1. Registering

```
PUSH ADD <url> <tag> <key> <auth> [box=<box>]
PUSH DEL <url> [box=<box>]
PUSH LIST
```

- **`PUSH ADD`** asks the server to send pushes to `<url>`, an `https`
  URL of at most 512 bytes, and replies `OK`.
  - `<tag>` is an opaque token of at most 64 bytes, chosen by the
    client. It goes inside the encrypted body of every push, so the app
    knows what the push is about. Clients SHOULD choose a random tag for
    each subscription.
  - `<key>` and `<auth>` are the subscription's P-256 public key, 65
    bytes, and its 16-byte authentication secret, each in base64 with
    padding. The server encrypts every push to them (9.3) [RFC8291].
  - Adding a URL that is already registered for the same mailbox, or for
    the same account, replaces its tag and keys.
- **`PUSH DEL`** removes a subscription, and replies `OK`.
- **`PUSH LIST`** sends one `PUSH <url> <tag>` line for each of the
  device's account subscriptions, then OK.

There are two kinds of subscription:

- **Mailbox subscriptions,** with `box`, wake the device when a mailbox
  has a new post. They are made on an anonymous connection, and belong
  to no identity. The server learns that someone follows the mailbox
  through that URL, but not who.
- **Account subscriptions,** without `box`, wake the device when it has a
  new Welcome (12.8). They are made on a signed-in connection, and
  belong to its device key. Removing the device removes them.

A client SHOULD use a different URL for every subscription, which push
gateways can provide (Appendix C), so that the server cannot link a
device's subscriptions by their URL. A server MAY limit the number of
subscriptions per mailbox and per device. Guests cannot register for
push.

### 9.2. When to Push

- **A mailbox subscription** gets a push when the mailbox gets a post
  that is kept (not `live=yes`, 5.2).
- **An account subscription** gets a push when a Welcome arrives for its
  device.

The server SHOULD send at most one push per subscription every 10
seconds. Posts that arrive in between go into the next push.

The server does not push to a subscription while the device is
connected and reading:

- For a mailbox subscription, that is while a connection follows the
  mailbox with `quiet=<tag>` (7.1), where `<tag>` is the subscription's.
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
