# ClaimFence rule reference

ClaimFence rules identify documentation that deserves human review. They do not declare
that a technical claim is false.

## CF001 - Absolute assurance claim

**Default severity:** error

Detects phrases such as `unbreakable`, `100% secure`, and absolute guarantees of security
or safety. Nearby evidence and scope can satisfy the rule only when both are explicit;
maintainers should normally rewrite the absolute.

## CF002 - Unbounded assurance language

**Default severity:** warning

Detects assurance verbs and adjectives such as `verified`, `hardened`, `production-ready`,
and `prevents`. A bounded use needs both:

- **scope:** a version, configuration, fixture set, campaign, or explicit tested condition;
- **evidence:** a concrete command, URL, or repository-local reference. Evidence-shaped
  words such as “tested” and “report” do not satisfy the rule on their own.

## CF003 - Universal or zero-result claim

**Default severity:** warning

Detects constructions such as `zero violations`, `every attack`, and universal negatives
such as `the browser never receives a key`. The surrounding logical blocks must name the
relevant boundary and concrete evidence.

Epistemic limitations remain exempt: “this review does not establish that the browser
never receives a key” limits what the review proves. This ordering is intentional; broad
negation suppression must not hide the universal-negative form used by assurance claims.

## CF004 - Unanchored test-result claim

**Default severity:** info

Detects statements that a named number of tests or checks passed when the nearby text does
not include a reproduction command, CI link, report, or other evidence anchor.

## CF005 - Broken local evidence reference

**Default severity:** warning

Checks local Markdown evidence links and path tokens in reproduction commands near a
matched claim. A finding is emitted when the resolved path escapes the selected repository
root or does not exist. Markdown links resolve from the document directory; command paths
resolve from the repository root.

A path-shaped inline-code example is not treated as evidence unless the surrounding block
contains an evidence cue such as `inspect`, `reproduce`, `report`, or `verification`.

This rule verifies reference integrity only. It does not inspect whether the target is
non-empty, relevant, current, authentic, or sufficient. External URLs are not fetched.

## CF101 - Missing limitations section

**Default severity:** warning

When a document contains at least two assurance findings, ClaimFence expects a section
marker containing one of: limitation, boundary, scope, residual risk, non-goal, or “what
this does not”.

## CF102 - Missing verification section

**Default severity:** warning

When a document contains at least two assurance findings, ClaimFence expects a heading or
bold subsection marker that names verification, reproduction, tests, checks, or evidence.

## Suppression contract

Suppressions are written on the line immediately before a prose block and require a
non-empty reason. They apply to that whole logical block, so wrapping it differently does
not change the suppression:

```markdown
<!-- claimfence-disable-next-line CF002: quoted name from the upstream specification -->
The Secure Channel field is required.
```

Use comma-separated rule identifiers for multiple rules or `ALL` only when the reason
justifies ignoring every finding in that block. ClaimFence deliberately has no unreasoned
blanket comment syntax.
