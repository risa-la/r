# Proofs

Formal models of parts of the risala protocol. They model the spec
([`spec/`](../spec/README.md), draft-03), not the Rust code. Each model
checks claims that the spec makes, or that a client relies on, over
every possible interleaving of events, within small bounds.

The tools come with the dev shell (`nix develop`), as `tlc`.

[`archive/`](archive/) keeps models of earlier drafts, as history:
[`archive/draft-02-sync`](archive/draft-02-sync/README.md) modelled
draft-02's room sync, and its findings shaped draft-03's sync points,
cids and FOLLOW. There is no model of draft-03 yet.
