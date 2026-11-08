# Releasing

Releases are published by CI: a pushed `v*` tag runs
[`.github/workflows/release.yml`](.github/workflows/release.yml), which checks the
package, creates a GitHub Release with the notes from `CHANGELOG.md` and publishes
to npm with [trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC,
no token in the repository). Nothing is published from a laptop.

## One-time setup

Register this repository and workflow as the trusted publisher of the package. This
needs npm 11.5.1+, which comes with Node 24 (`.nvmrc`), and a login as an owner of
the `@irbisadm` scope:

```sh
nvm use
npm trust github @irbisadm/sip-pcap --file release.yml --repo irbisadm/sip-pcap --allow-publish
npm trust list @irbisadm/sip-pcap
```

This was done before 0.1.0. npm accepted it while the package did not exist yet and
reserved the name with a placeholder version `0.0.0-stage` ("Temporary package
placeholder for staged publishing"); that version is npm's, not a release.

Register it again if the GitHub repository is ever deleted and recreated, even under
the same name: after that, the 0.1.1 publish failed with `E404` on `PUT` until the old
entry was revoked (`npm trust revoke`) and a new one created.

## Each release

1. On `main`, the changes since the last release are under `## [Unreleased]` in
   `CHANGELOG.md`. Choose the version by [Semantic Versioning](https://semver.org/)
   (before 1.0.0: a breaking change bumps the minor version).
2. Create a branch `release/X.Y.Z` with one commit `chore(release): X.Y.Z` that
   - sets `"version": "X.Y.Z"` in `package.json` and `package-lock.json`
     (`npm version X.Y.Z --no-git-tag-version`);
   - renames `## [Unreleased]` to `## [X.Y.Z] — YYYY-MM-DD`.
3. Open a pull request into `main`; merge it when CI is green.
4. Tag the merge commit and push the tag:

   ```sh
   git checkout main && git pull
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

5. Watch the Release workflow (`gh run watch`). It
   - fails unless the tag equals `v` + the `package.json` version;
   - runs the type check, tests, build and package-contents check;
   - fails unless `CHANGELOG.md` has a `## [X.Y.Z]` section, and uses it as the
     release notes;
   - creates the GitHub Release (skipped if it exists, so the job can be re-run);
   - publishes to npm (skipped if the version is already there).

   If the publish step fails with `403 … You cannot publish over the previously
   published versions`, check whether the version is in fact on npm
   (`curl -s https://registry.npmjs.org/@irbisadm/sip-pcap/X.Y.Z`): for v0.1.0 the
   upload succeeded and a second request of the same `npm publish` got the 403. Re-run
   the failed job (`gh run rerun <id> --failed`) once `npm view` shows the version;
   both the release and the publish steps then report it as done.

## Pre-releases

A version with a suffix (`0.2.0-rc.1`, tag `v0.2.0-rc.1`) is published under the npm
dist-tag `next` and marked as a pre-release on GitHub, so `latest` and the latest
GitHub Release do not move. Install it with `npm install @irbisadm/sip-pcap@next`.
