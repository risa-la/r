## 11. Keepalive and Closing

```
PING [<token>]
```

→ `OK`, with the tag `t`

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

The server tags its `PING <token>` line, and the `OK` it sends for a
client's PING, with `t`, its time when it sent the line (3.2):

```
S: @t=2026-11-10T09:00:00.000Z PING k3j9w2
C: PONG k3j9w2
C: PING
S: @t=2026-11-10T09:00:04.512Z OK
```

**Server time.** For each server, the **server time** a device knows
is the newest `t` it has seen from that server, on a post or on a PING
or its `OK`. It never goes backwards. Devices judge by it, and not by
their own clocks, the age of a commit they made (7.6) and when to
delete a past epoch's secrets (12.9), so that a device whose clock is
wrong, or that was offline, decides as the others do.

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
