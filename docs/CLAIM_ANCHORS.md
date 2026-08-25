# Stable Claim Anchors contract

Stable Claim Anchors provide opt-in identity for assurance claims that are expected to move
or be deliberately rewritten. They solve an identity problem only. They do not make a claim
true, preserve its meaning, satisfy required context, or count as evidence.

## Syntax

Place one directive immediately before one logical Markdown block containing a recognized
claim:

~~~markdown
<!-- claimfence-id: gateway/readiness -->

Under version 2, this gateway is hardened for the included malformed-token fixtures.
~~~

The value must contain 1–128 lowercase ASCII letters, digits, `.`, `_`, `:`, `/`,
or `-`, beginning with a letter or digit. Use a repository-wide namespace such as
`component/claim` when several documents are scanned together.

The directive applies to the next source-mapped logical block. Blank lines and standalone
HTML comments may separate it from that block. A heading or another prose block becomes the
next block, so put the directive directly beside the intended claim.

## Identity model

Unanchored identifiers continue to derive from repository-relative path, normalized claim
text, and duplicate occurrence. Rewrapping remains stable, while a wording change or file
move normally changes the identifier.

For an anchored claim, ClaimFence derives the internal `CLM-…` identifier only from a
domain-separated form of the selected stable value. The ledger also records the original
value as `stable_id`. The Evidence Map displays both values.

This allows Evidence Drift to join the old and current records after a file move or rewrite.
Changes to `path` and `text` are still emitted as `claim-field-changed` events and
require review.

Changing or removing the directive changes identity and normally produces one removed claim
and one added claim. Adding a directive to an existing unanchored claim has the same one-time
migration effect.

## Fail-closed validation

The scan is invalid when:

- the value contains uppercase letters, whitespace, non-ASCII text, or unsupported symbols;
- two recognized claims in the selected scan use the same value;
- more than one directive targets the same logical block;
- one directive would identify multiple distinct claims in a single block;
- a directive has no following block or the following block has no recognized claim.

Directive-shaped text inside fenced or indented code is ignored. This permits documentation
and fixtures to show the syntax without changing the surrounding claim inventory.

These errors return the normal invalid-input exit code. ClaimFence does not silently fall
back to an automatic identifier because that could make a workflow appear stable while using
an unintended identity.

## Ledger and drift compatibility

`stable_id` is optional in the v1 ledger schema. Older v1 ledgers remain valid and can seed
comparison with v0.6. The deterministic `id` field remains the join key; `stable_id` is
human-readable context carried into ledger records and drift events.

Comparison-ledger validation recomputes the expected `CLM-…` value from every supplied
`stable_id` and rejects a mismatch. A ledger cannot attach a readable stable label to an
unrelated machine join key.

Stable anchors do not change finding fingerprints or fingerprint baselines. They affect only
claim-ledger identity and the reports derived from that ledger.

## Trust boundary

An untrusted change can retain a stable ID while rewriting the claim. This is not hidden:
the changed text and path are review-classified drift events. Use `--fail-on-drift review`
with a previous ledger from a protected source when those changes must halt a workflow.

The directive is declared metadata, not authenticated provenance. It does not prove that the
same author, component, guarantee, evidence, or semantic meaning survived the change.
