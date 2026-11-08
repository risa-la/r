## 13. Command Summary

Commands a client can send, and the kinds of connection (4.1) that may
send them. "New" is a connection that has not yet become anonymous, a
guest or signed in. A connection that sends a command its kind may not
use gets `ERR not-authenticated` if it is new, and
`ERR wrong-connection` otherwise.

| Command | Section | New | Anonymous | Guest | Signed in |
|---|---|---|---|---|---|
| `INFO [<room>]` | 8.5, 6.1 | without a room | ✓ | ✓ | ✓ |
| `ANON` | 4.2 | ✓ | | | |
| `GUEST <name> [token=]` | 4.2 | ✓ | | | |
| `AUTH <identity> <signature>` | 4.6 | ✓ | | | |
| `REGISTER <name> <keyfile> <signature>` | 4.7 | ✓ | | | |
| `KEYS PUT <after> <records>` | 4.7 | ✓ | ✓ | | ✓ |
| `PAIR PUT <id> <data>` / `PAIR GET <id>` | 4.8 | ✓ | ✓ | | ✓ |
| `UNREGISTER <uid>` | 4.9 | | | | ✓ |
| `CREATE <box> <group-id> <token-hash> [epoch=]` | 5.2, 7.8 | | ✓ | ✓ | |
| `CREATE <box> <group-id> <token-hash> <room> <groupinfo> <tree>` | 5.2 | | | | ✓ |
| `POST <box> <token> <message> [live=] [groupinfo=] [next=]` | 5.2 | | ✓ | ✓ | public rooms' PublicMessages (12.6) |
| `UPLOAD <box> <token> <size>` | 5.6 | | ✓ | | |
| `REPORT <box> <report>` | 5.8 | | ✓ | ✓ | ✓ |
| `LIST [after=] [limit=]` | 6.1 | | ✓ | ✓ | ✓ |
| `GROUPINFO <box>` | 6.1 | | ✓ | ✓ | |
| `MUTE <box> <pseudonym> [hours=]` / `UNMUTE <box> <pseudonym>` | 6.4 | | | | ✓ |
| `FOLLOW <box> [quiet=]` / `UNFOLLOW <box>` | 7.1 | | ✓ | ✓ | |
| `FETCH <box> after= [limit=] [leaf=]` | 7.1 | | ✓ | ✓ | |
| `TOKEN <box> <epoch> <token> <hash>` | 7.2 | | ✓ | ✓ | |
| `PRESENCE ON` / `PRESENCE OFF` | 8.3 | | | | ✓ |
| `WATCH [<uids>]` / `WHOIS <uid>` / `MEMBERS <room>` | 8.3 | | ✓ | ✓ | ✓ |
| `PUSH ADD <url> <tag> <key> <auth> box=` / `PUSH DEL <url> box=` | 9.1 | | ✓ | | |
| `PUSH ADD <url> <tag> <key> <auth>` / `PUSH DEL <url>` / `PUSH LIST` | 9.1 | | | | ✓ |
| `KEYPKG ADD <keypackage>` / `KEYPKG COUNT` | 12.5 | | | | ✓ |
| `KEYPKG GET <uid>` | 12.5 | | ✓ | ✓ | ✓ |
| `WELCOME PUT <ref> <welcome>` / `WELCOME GET <ref> [light=]` | 12.8 | | ✓ | ✓ | ✓ |
| `WELCOME LIST` / `WELCOME DEL <id>` | 12.8 | | | | ✓ |
| `BLOB <hash> <size> [box= token=]` | 12.12 | | ✓ | ✓ | ✓ |
| `BACKUP PUT <generation> <hash> <key> [files=]` / `BACKUP GET` / `BACKUP DEL` | 12.13 | | | | ✓ |
| `ADMIN OPS` / `OP <uid>` / `DEOP <uid>` | 10.1 | | | | ✓ |
| `ADMIN BAN <target> [<reason...>]` / `UNBAN <target>` / `BANS` | 10.2 | | | | ✓ |
| `ADMIN WHO` / `DISCONNECT <uid> [<reason...>]` / `NOTICE <message...>` | 10.3 | | | | ✓ |
| `ADMIN ROOMS [after=] [limit=]` / `DROP <target> [<reason...>]` / `MUTE <box> <pseudonym> [hours=]` / `UNMUTE <box> <pseudonym>` / `REPORTS` | 10.4, 5.8 | | | | ✓ |
| `RESOLVE <id>` | 5.8 | | | | ✓ |
| `ADMIN UNREGISTER <uid>` | 10.5 | | | | ✓ |
| `ADMIN SET <key> [<value...>]` | 10.6 | | | | ✓ |
| `PING [<token>]` / `PONG <token>` | 11 | ✓ | ✓ | ✓ | ✓ |
| `QUIT [<message...>]` | 11 | ✓ | ✓ | ✓ | ✓ |

Lines a server can send:

| Line | Kind | Section |
|---|---|---|
| `RISALA <version> <host> <nonce> [<message...>]` | greeting | 4.1 |
| `OK [<key>=<value> ...]` / `ERR <code> [<message...>]` | final response | 3.6 |
| `POST <box> <message> [next=<hash>]` | a post, live or in response to FETCH | 5.2, 7.1 |
| `ROOM <room> <box> <members> [<topic...>]` | response to LIST and ADMIN ROOMS | 6.1, 10.4 |
| `GROUPINFO <box> <epoch> <seq> <groupinfo> <tree>` | response to GROUPINFO | 6.1 |
| `GONE <box> <uid>` | a guest's session ended | 6.1 |
| `DROP <box> [<reason...>]` | an operator deleted the mailbox | 6.1, 10.4 |
| `USER <uid> <presence>` | response to WATCH and WHOIS | 8.3 |
| `MEMBER <room> <uid> <role> <presence>` | response to MEMBERS | 8.3 |
| `PRESENCE <presence> <uids>` | watched identities came online or went offline | 8.3 |
| `REPORT <box> <report>` | a report, live or in response to ADMIN REPORTS | 5.8 |
| `RESOLVED <id>` | a report was resolved | 5.8 |
| `RECORD <index> <hash>` | response to KEYS PUT | 4.7 |
| `PAIR <id> <data>` | response to PAIR GET | 4.8 |
| `PUSH <url> <tag>` | response to PUSH LIST | 9.1 |
| `KEYPKG <uid> <keypackage>` | response to KEYPKG GET | 12.5 |
| `WELCOME <id> <welcome>` | a Welcome, live or in response to WELCOME LIST or WELCOME GET | 12.8 |
| `BACKUP <generation> <hash> <key> [files=<list>]` | response to BACKUP GET | 12.13 |
| `NOTICE <message...>` | information | 8.4 |
| `OP <uid>` | response to ADMIN OPS | 10.1 |
| `SERVERBAN <target> [<reason...>]` | response to ADMIN BANS | 10.2 |
| `CONNECTION <uid> <address> <since>` | response to ADMIN WHO | 10.3 |
| `PING <token>` / `BYE [<message...>]` | connection | 11 |
