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
timer, including an empty one or one the server cannot parse. Part of a
line does not reset it, and a line that is too long counts once its LF
arrives. This lets the server notice dead connections, which matters for
deciding when to push.

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
reasons, such as shutting down, an idle timeout or a removed device.
