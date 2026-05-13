# InstallGuard GitHub Action

Composite action that installs `installguard` and runs `installguard ci`
against your repository's lockfile, emitting `::warning::` / `::error::`
annotations on the PR and failing the job on any **block** decision.

## Quick start

```yaml
- uses: actions/checkout@v4
- uses: dtolnay/rust-toolchain@stable
- uses: installguard/installguard/.github/actions/installguard@v1
  with:
    path: .
    summary-file: installguard-summary.json
```

A complete workflow example lives at
[examples/workflows/installguard.yml](../../../examples/workflows/installguard.yml).

## Inputs

| Input            | Default                    | Description                                                                |
| ---------------- | -------------------------- | -------------------------------------------------------------------------- |
| `path`           | `.`                        | Project root containing the lockfile.                                      |
| `policy`         | `<path>/installguard.yaml` | Policy file path.                                                          |
| `summary-file`   | _(none)_                   | If set, writes the JSON summary to this path (e.g. for upload-artifact).   |
| `max-warn`       | _(none)_                   | Fail the job if warnings exceed this count. Blocks always fail.            |
| `no-cache`       | `false`                    | Disable the on-disk signal cache.                                          |
| `concurrency`    | `16`                       | Maximum concurrent registry requests.                                      |
| `ignore-scripts` | `false`                    | Treat lockfile as if `npm install --ignore-scripts` will be used.          |
| `comment-on-pr`  | `true`                     | Post/update a sticky risk-summary comment on the PR.                       |
| `github-token`   | `${{ github.token }}`      | Token used to post the PR comment (`pull-requests: write` required).       |
| `version`        | `github.action_ref`        | Git ref of InstallGuard to install. Defaults to the action's own version.  |
| `source-repo`    | `github.action_repository` | `owner/repo` to install from. Override for forks.                          |

## How it works

1. Resolves the install source (`source-repo` @ `version`) — defaults align
   the binary version with the action version, so `@v1` of the action always
   pulls the matching binary.
2. Restores `~/.cargo/bin/installguard` from cache when possible; otherwise
   `cargo install --locked --git … --rev …`.
3. Invokes `installguard ci` with the supplied inputs. `GITHUB_ACTIONS=true`
   is already set by the runner, so workflow annotations are emitted
   automatically.
4. On `pull_request` events, posts (or updates) a single sticky comment with
   a Markdown table summarising the run. The comment is identified by an
   HTML marker (`<!-- installguard-summary -->`) so subsequent runs replace
   it rather than piling up. Disable with `comment-on-pr: false`.

## Required permissions

For the PR comment to be posted, the workflow must grant write access:

```yaml
permissions:
  contents: read
  pull-requests: write   # required only when comment-on-pr is true
```

## Exit codes

| Code | Meaning                                                  |
| ---- | -------------------------------------------------------- |
| 0    | Clean (no blocks, warnings within `max-warn`).           |
| 1    | One or more **block** decisions, or warnings over limit. |
| 2    | Internal error (bad policy, lockfile missing, …).        |
