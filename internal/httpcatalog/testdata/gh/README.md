# gh GraphQL fixtures

Each file is one gh command's requests, as gh 2.89.0 sent them, used by
`graphql_test.go` and `internal/mitm/github_graphql_test.go`. `{{PR}}`,
`{{LABEL}}` and `{{REPO}}` stand for the node IDs gh had just read. They were recorded
against `recorder/`, a local stand-in for GitHub, with a placeholder token:
nothing reached GitHub and no real token was used.

To record again (after a gh upgrade), from the repository root:

```sh
go build -o /tmp/gh-recorder ./internal/httpcatalog/testdata/gh/recorder
/tmp/gh-recorder 127.0.0.1:18731 /tmp/gh-calls.jsonl &
mkdir -p /tmp/gh-repo /tmp/gh-config /tmp/gh-cache && cd /tmp/gh-repo
git init -q -b cursor/pool-agent/x && git remote add origin https://github.localhost/example-org/example-repo.git
export GH_HOST=github.localhost GH_TOKEN=__vault_GITHUB_TOKEN__ HTTP_PROXY=http://127.0.0.1:18731 \
  GH_CONFIG_DIR=/tmp/gh-config XDG_CACHE_HOME=/tmp/gh-cache GH_PROMPT_DISABLED=1 GH_PAGER=cat
gh pr view 12   # one command at a time; move /tmp/gh-calls.jsonl's lines into a fixture after each
```

gh sends `github.localhost` traffic in plain HTTP to `api.github.localhost`,
which `HTTP_PROXY` routes to the recorder. Use a fresh cache directory: gh
caches feature-detection answers for a day. Replace the recorder's node ID
in mutations with `{{PR}}`, `{{LABEL}}` or `{{REPO}}` (a repository's ID).

Two commands need the recorder to answer differently. Start it with
`RECORDER_NOT_DRAFT=1` for `gh pr ready 12 --undo`, which does nothing to a
draft, and with `RECORDER_NO_PULL_REQUESTS=1` for
`gh pr create --head cursor/pool-agent/x --base main --title t --body b`,
which stops when the branch already has an open pull request.
