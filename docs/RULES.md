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
- **evidence:** a test, report, receipt, link, workflow, artifact, or reproduction command.

## CF003 - Universal or zero-result claim

**Default severity:** warning

Detects constructions such as zero violations or every attack. The surrounding text must
name the measured space and the evidence. This rule does not reject a zero result; it asks
which campaign produced it.

## CF004 - Unanchored test-result claim

**Default severity:** info

Detects statements that a named number of tests or checks passed when the nearby text does
not include a reproduction command, CI link, report, or other evidence anchor.

## CF101 - Missing limitations section

**Default severity:** warning

When a document contains assurance findings, ClaimFence expects a heading containing one
of: limitation, boundary, non-goal, or “what this does not”.

## CF102 - Missing verification section

**Default severity:** warning

When a document contains assurance findings, ClaimFence expects a heading that names
verification, reproduction, testing, or evidence.

## Suppression contract

Suppressions apply to the immediately following line and require a non-empty reason:

```markdown
<!-- claimfence-disable-next-line CF002: quoted name from the upstream specification -->
The Secure Channel field is required.
```

Use comma-separated rule identifiers for multiple rules or `ALL` only when the reason
justifies ignoring every finding on that line. ClaimFence deliberately has no unreasoned
blanket comment syntax.
