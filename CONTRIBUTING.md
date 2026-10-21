# Contributing to Gatehouse

Thanks for helping. Issues, fixes and pull requests are welcome.

## Before you start

- **Security problems:** do not open an issue or pull request. Report them privately as described in [SECURITY.md](SECURITY.md).
- **Bugs and ideas:** open an issue first for anything larger than a small fix, so we can agree on the approach before you write it.
- **Upstream fixes:** a fix that helps every Agent Vault user, not only Gatehouse, may belong in [Infisical/agent-vault](https://github.com/Infisical/agent-vault). We offer such fixes upstream too; see [upstream maintenance](docs/upstream-maintenance.md).

## Make a change

1. Fork the repository and branch from `main`.
2. Build and test. You need Go (the version in `go.mod`), Node.js, Python 3 and Docker.

   ```sh
   make build                     # the web UI and the agent-vault binary
   go test -race -count=1 ./...   # the full test suite
   go vet -tags e2e ./...         # the end-to-end build
   python3 scripts/upstream-update-test.py
   ```

   For changes to the broker, the database path or the demo, also run the local demonstration:

   ```sh
   docker build -f examples/credential-proxy/Dockerfile -t credential-proxy-verification .
   docker run --rm --network none credential-proxy-verification
   ```

3. When behavior changes, update the matching guide in [docs/gatehouse](docs/gatehouse/) in the same pull request.
4. Open a pull request against `main`. Say what it changes and why, and how you tested it.

## What CI checks

- The Go tests with the race detector, the end-to-end build, `go vet`, golangci-lint, actionlint and `go mod tidy`.
- The local demonstration, against a real Vault and PostgreSQL.
- A check that refuses a list of known internal hostnames, project names and similar identifiers. It catches only what it lists. Use `example.com` and `example-*` placeholders in code, tests and docs.

A maintainer reviews every pull request, and the required checks must pass before it merges. Please reply to or fix every automated review comment.

## Keep secrets out

Never put a real credential, internal endpoint or deployment detail in code, tests, docs, commits or pull request text. Tests use synthetic values only.

## Names

The binary, Go module path and environment variables keep the upstream `agent-vault` and `AGENT_VAULT_` names so upstream changes merge cleanly. Please keep them.

## Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT license](LICENSE) that covers this repository.
