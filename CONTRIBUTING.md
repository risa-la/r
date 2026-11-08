# Contributing

Thank you for helping with risala. The project is at an early stage, and
the spec and the code both still change.

## Reporting bugs

Open an issue at <https://github.com/risa-la/r/issues>. Say what you
did, what you expected and what happened instead, and include:

- the commit or version, and the operating system
- which part is affected: the spec, `risalad`, librisala, `risala-cli`
  or an app
- the lines sent and received, when it is a protocol problem, or the
  log with `RUST_LOG=debug`, when it is a server problem

Report security problems privately instead, as described in
[SECURITY.md](SECURITY.md).

Questions, ideas and feature requests are welcome as issues too.

## Making changes

1. For anything larger than a small fix, open an issue first, so we can
   agree on the approach before you write it. This matters most for
   changes to the spec ([`spec/`](spec/README.md)).
2. Set up the development environment and build as described in the
   [README](README.md#development).
3. Make the change in a branch, and open a pull request against `main`.
   Changes to the Apple client use the pull request template in
   `.github/PULL_REQUEST_TEMPLATE/apple-client.md`.

Before you open the pull request, run:

```
nix flake check
```

It runs what CI runs: formatting, clippy with warnings as errors, the
tests, the REUSE check and Nix formatting. CI must pass before a change
is merged.

### Tests

New features and bug fixes come with tests. A bug fix gets a test that
fails without it. The risala-proto tests parse every example line in
the spec, so a change to the protocol updates its examples too.

### Commits

- Start the subject with the part it changes, then say what changed in
  plain words: `server: ...`, `librisala: ...`, `cli: ...`,
  `proto: ...`, `keyfetch: ...`, `apple: ...`, `Spec: ...`, `docs: ...`,
  `nix: ...`.
- Keep each commit to one change, and keep it building with its tests
  passing.
- History stays linear. We rebase pull requests onto `main` rather than
  making merge commits, so rebase your branch instead of merging `main`
  into it.

## License

By contributing, you agree that your contribution is licensed under the
same terms as the file it changes: [CC BY 4.0](LICENSES/CC-BY-4.0.txt)
for the spec in `spec/`, and the [Apache License 2.0](LICENSES/Apache-2.0.txt) for
everything else. See [`REUSE.toml`](REUSE.toml).
