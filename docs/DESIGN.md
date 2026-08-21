# Design boundaries

## Threat model

ClaimFence addresses accidental or promotional overstatement in Markdown documentation.
It assumes maintainers want review prompts and are not trying to evade the tool.

It does not defend against malicious authors. An author can rephrase a claim, insert
irrelevant evidence words, disable a rule in configuration, or alter the scanner itself.

## Why deterministic rules

A documentation gate should be reproducible, inspectable, inexpensive, and usable without
sending repository text to an external service. ClaimFence therefore uses standard-library
regular expressions and explicit context markers rather than a model judgment.

This choice creates visible limitations:

- lexical rules miss paraphrases;
- context markers do not establish evidence quality;
- English wording is privileged;
- false positives require configuration or reasoned suppression.

Those limitations are preferable to presenting a probabilistic prose classifier as an
authority on whether a claim is justified.

## Logical Markdown model

Before rules run, ClaimFence joins soft-wrapped paragraph, list-item, and blockquote lines
into logical blocks while retaining a character-to-source map. Rules operate on the joined
text and findings map back to the original line and column. Fenced code, indented code,
HTML comments, and inline code are excluded from phrase matching.

This makes ordinary prose rewrapping stable over rule identifiers, claims, severities, and
fingerprints. Source coordinates may move because the source moved. ClaimFence deliberately
implements a narrow Markdown model rather than claiming full CommonMark conformance.

## Evidence model

For each matched assurance phrase, the scanner inspects a configurable radius of logical
blocks. The model recognizes three context classes:

1. **Scope** - version, configuration, fixture, scenario, campaign, or tested condition.
2. **Evidence** - a concrete command, URL, or repository-local link/path.
3. **Limitation** - explicit negation, prototype status, non-goals, or unsupported scope.

Phrase rules declare the context classes they require. Document rules check for dedicated
verification and limitation sections when at least two assurance findings make the missing
document structure actionable. Markdown headings and bold `Tests` or `Residual risk`
subsection labels count as structure. Generic evidence words do not qualify without an
anchor.

For local evidence, `CF005` verifies that the path resolves inside the selected repository
root and exists. This is intentionally a floor: an empty or irrelevant file passes path
integrity. ClaimFence does not fetch external URLs or authenticate any evidence.

When a repository root is explicitly selected, every requested and discovered scan path is
resolved and required to stay inside it. This includes Markdown files reached through
symbolic links. The bundled Action always passes its configured root. For compatibility,
an ad hoc CLI invocation without `--root` can still scan an explicitly named absolute file
outside the working directory; the working directory remains its evidence-resolution root.

Inline path-shaped examples are not evidence merely because they resemble a filename. A
bare inline path is considered an anchor only beside an evidence cue; paths inside a
recognized reproduction command remain anchors. This keeps examples such as `NUL.txt`
from becoming broken-evidence findings.

## Claim ledger model

The scanner retains a record for every matched assurance claim, including claims whose
required context is present. Matches in the same logical claim are aggregated across rule
identifiers and receive one of three dispositions: `linked`, `review`, or `suppressed`.
These are lexical states, not truth values.

Ledger and HTML reporters enrich present local-file anchors with SHA-256 only when one of
those outputs is requested. The ordinary finding path therefore does not read linked
evidence contents. Files larger than 16 MiB are not hashed. Generated HTML escapes all
document-derived strings and contains only static reporter JavaScript.

## Evidence Drift model

Evidence Drift compares two structurally checked v1 claim ledgers by stable claim
identifier. Source line and column changes are ignored. Repository-local anchors use their
resolved repository-relative path as identity when available, so spelling-only changes
such as `examples/bounded-readme.md` to `./examples/bounded-readme.md` do not create drift.

The comparator emits deterministic added, removed, and changed events. Events requiring
review include lost evidence, changed evidence state or bytes, lost context, increased
severity, new suppression, and a current claim that is not `linked`. Additions and removals
that do not meet those conditions remain visible as change-only events. The `any` gate is
available when each inventory change should halt a workflow.

The receipt records both tool versions, but a version difference is not itself a drift
event. Unanchored claim rewrites normally appear as a removed identifier and an added
identifier. An optional stable claim anchor derives identity from an author-selected value,
allowing rewrites and file moves to remain joined while still producing review-classified
field events. These boundaries are explicit because the comparator detects state change; it
does not infer whether the change preserved meaning or improved the underlying evidence.

For `present-unhashed` files above 16 MiB, the ledger retains size but no digest. A size
change creates drift; a same-size byte change is outside the comparison model.

Comparison ledgers are capped at 32 MiB and checked for schema version, producer,
identifiers, consumed field types, allowed dispositions, and digest shape before use.
GitHub summary values derived from ledgers are escaped and flattened to one line.

## Negation ordering

Universal negatives are assurance claims when they state system behaviour, for example
`the browser never receives a key`. Epistemic negation limits what an assessment
establishes: “this review does not establish that the browser never receives a key.”
ClaimFence detects the universal-negative form and then applies the outer epistemic
exemption. Paired fixtures hold that distinction stable.

## Stability contract

Rule identifiers are the compatibility boundary. Message wording may improve between patch
releases; a rule identifier will not silently change meaning within a minor release.
Baselines use stable fingerprints derived from the rule, repository-relative path, and
normalized logical sentence.
