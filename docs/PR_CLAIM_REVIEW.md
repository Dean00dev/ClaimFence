# Pull Request Claim Review contract

Pull Request Claim Review removes one adoption barrier from Evidence Drift: a team can
compare proposed documentation with a local base commit without first producing, storing,
or downloading a previous ledger.

```bash
claimfence README.md docs --root . --fail-on none \
  --compare-ref origin/main \
  --drift-output claimfence-drift.json \
  --fail-on-drift review
```

## What the command does

1. Requires `--root` (or the current directory) to resolve to the Git worktree root.
2. Resolves the supplied local revision to one exact commit identifier.
3. Reads the selected Markdown blobs from that commit without checkout.
4. Materializes directly referenced repository-local evidence blobs for status, size, and
   SHA-256 comparison.
5. Scans both the base snapshot and current worktree with the **current worktree policy**.
6. Emits normal Evidence Drift events plus the resolved commit and policy source.

The operation does not change `HEAD`, the index, or working files. It does not run Git
hooks, invoke checkout filters, initialize submodules, fetch a remote, execute commands
found in Markdown, or fetch external URLs.

## GitHub pull requests

The chosen revision must exist in the runner's local object database. A shallow checkout
often lacks the pull request base, so make history available explicitly:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
    with:
      fetch-depth: 0
  - uses: Dean00dev/ClaimFence@v0.6.0
    id: claimfence
    with:
      paths: README.md docs
      compare-ref: ${{ github.event.pull_request.base.sha }}
      fail-on: warning
      fail-on-drift: review
      drift-output: claimfence-drift.json
```

The `drift-base-commit` output exposes the resolved identifier for later workflow steps.
Passing a branch name is supported locally, but an event SHA is preferable in CI because a
branch can move between workflow construction and review.

## Policy boundary

ClaimFence does **not** load the configuration as it existed at the base commit. It loads
the current worktree configuration once and applies it to both scans. That choice makes the
comparison answer:

> Under the policy proposed for this run, how did the selected claim and evidence state
> change between the base commit and current worktree?

It does not separately report policy drift. A rule, exclusion, or context-radius change can
therefore alter both reconstructed inventories. Review configuration changes as code.

## Filesystem and Git boundaries

- The selected scan paths must exist in the current worktree and remain inside its root.
- A selected Markdown file absent from the base is treated as new, not as invalid input.
- Only regular Git blobs are materialized. A selected Markdown or referenced evidence
  symbolic link fails closed rather than being followed with platform-dependent behavior.
- Directory evidence is reconstructed from matching tree prefixes.
- Files above 16 MiB retain the existing `present-unhashed` size-only boundary.
- Tree listings above 64 MiB are rejected to bound untrusted repository metadata.
- Non-UTF-8 Git paths are rejected because ClaimFence's public path contract is UTF-8 text.

## Trust boundary

An exact commit identifier binds the comparison to local Git objects. It does not prove:

- that the ref name resolved to the intended branch or merge base;
- that branch protection, review, or required checks governed the commit;
- who authored or approved the bytes;
- that the local object database came from an authentic remote;
- that equal or changed evidence bytes are true, current, relevant, or sufficient.

Use an exact event SHA from a trusted workflow context, retain the drift receipt, and treat
commit provenance as a separate supply-chain concern. ClaimFence recommends review; it
does not become the authority that decides whether a pull request may merge.
