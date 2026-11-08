## Appendix C. Push Gateways (Informative)

Apple's push service (APNs) and Google's (FCM) accept pushes for an app
only from that app's developer, who holds the credentials. An
independent chat server cannot have those credentials. So whoever
publishes an app runs a small **push gateway**: an HTTPS service that
accepts encrypted pushes from any risala server and forwards them.

A typical setup:

1. The app gets a device token from APNs or FCM and registers it with the
   developer's gateway. The gateway can then hand out as many URLs for
   that device as the app asks for, each containing an opaque id, such
   as `https://push.app.example/n/3f9c...`. The chat server never sees
   the device token.
2. The app makes a P-256 key pair and an authentication secret for each
   subscription [RFC8291], and sends `PUSH ADD <url> <random tag> <key>
   <auth> box=<box> token=<token>` on an anonymous connection for each
   mailbox it follows, with a new URL each time, and `PUSH ADD` without
   `box` on its signed-in connection for its Welcomes (9.1). It
   remembers what each tag is for.
3. The server POSTs the encrypted body to the URL (9.3), and the gateway
   forwards it to the device unchanged. Only the app can decrypt it.

How each platform handles a push:

- **iOS.** The gateway sends a visible notification with generic text
  ("New activity"). It sets `mutable-content` and puts the encrypted
  body in the notification's data. The app's Notification Service
  Extension decrypts it, connects to the server, fetches the new posts,
  and replaces the generic text with the sender and message, or hides
  the notification if nothing needs one, where the platform allows. If
  it cannot finish in time, the generic text stays.
- **Android with FCM.** The gateway sends a high-priority data message.
  The app decrypts it, fetches the new posts and shows its own
  notification, if one is due.
- **Android with UnifiedPush.** The app registers the endpoint URLs from
  the user's UnifiedPush distributor directly. No gateway is needed.

A gateway sees only which of its URLs got a push, and when, and so do
Apple and Google. Over many pushes, that shows which devices are woken
together, which suggests who shares a conversation, even though the
server delays each push by its own random time (9.2). Anyone who knows a
gateway URL can send to it, so gateways SHOULD rate-limit each URL.
