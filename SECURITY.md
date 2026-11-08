# Security

## Reporting a vulnerability

Report vulnerabilities privately through GitHub:

<https://github.com/risa-la/r/security/advisories/new>

This opens a private advisory that only you and the maintainers can
see. Please do not report vulnerabilities in public issues, pull
requests or discussions.

This covers the code in this repository and the protocol itself. A flaw
in the spec ([`spec/`](spec/README.md)) that any correct implementation would share is a
vulnerability too.

A useful report says:

- what is affected: the spec section, crate, client or commit
- what an attacker can do, and what they need first (a guest, a member
  of a room, a server operator, someone on the network)
- how to reproduce it, such as a session typed into `openssl s_client`,
  a test or a short program

## What happens next

- We reply within 14 days to say we have the report.
- We work on a fix in the private advisory, and may ask you questions
  there.
- When the fix is on `main`, we publish the advisory, with a CVE when
  one fits. We credit you unless you ask us not to.

## Supported versions

risala has no releases yet. Fixes go to `main` only.
