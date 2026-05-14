# Homebrew packaging

This directory holds the assets needed to publish InstallGuard via a
personal Homebrew tap. The aim is the user experience:

```sh
brew tap jt-systems/installguard
brew install installguard
```

Long term we will also submit InstallGuard to `homebrew-core` (so plain
`brew install installguard` works), but that requires the project to
clear Homebrew's notability bar (stars / forks / watchers) and to have a
track record of stable releases — neither of which a fresh `0.1.0-alpha`
satisfies. The tap is shippable today and gives adopters a one-line
install in the meantime.

## One-time setup (manual)

1. **Create the tap repository** on GitHub: `jt-systems/homebrew-installguard`.
   Homebrew discovers taps by the `homebrew-` prefix; the rest of the
   name is arbitrary.

2. **Seed it with the formula template** in this directory:

   ```sh
   git clone git@github.com:jt-systems/homebrew-installguard.git
   cd homebrew-installguard
   mkdir -p Formula
   cp /path/to/installguard/packaging/homebrew/installguard.rb Formula/
   git add Formula/installguard.rb
   git commit -m "Seed installguard formula"
   git push
   ```

   The template ships with placeholder `sha256` values; the first real
   release will rewrite them automatically (see below).

3. **Issue a fine-grained Personal Access Token** scoped only to the
   `jt-systems/homebrew-installguard` repo with `Contents: Read & write`
   permission. Add it as a secret named `HOMEBREW_TAP_TOKEN` on
   `jt-systems/installguard` (Settings → Secrets and variables → Actions).

4. **Tag a release**: `git tag -s v0.1.0 -m "v0.1.0" && git push --tags`.
   The release workflow will build the binary matrix, publish a GitHub
   Release with sha256 checksums, and then the new
   `homebrew-publish` job will open a PR against the tap repo bumping
   `version` and the four `sha256` values. Merge that PR and
   `brew install jt-systems/installguard/installguard` works for everyone.

## Automation

The bump is handled by
[`mislav/bump-homebrew-formula-action`](https://github.com/mislav/bump-homebrew-formula-action),
invoked from `.github/workflows/release.yml`. The job is gated on the
`HOMEBREW_TAP_TOKEN` secret being present; until you create the tap and
the PAT, the job is a no-op and tagging a release does no harm.

## Verifying the formula locally

Once the formula is in the tap, you can dry-run it without publishing:

```sh
brew tap jt-systems/installguard
brew install --build-from-source --verbose --debug installguard  # not used here — bottle install
brew audit --strict --new-formula installguard
brew test installguard
```

`brew audit` is what `homebrew-core` reviewers run; passing it now
shortens the future submission cycle.
