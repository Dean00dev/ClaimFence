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
verification and limitation sections when assurance findings exist. Generic evidence words
do not qualify without an anchor.

For local evidence, `CF005` verifies that the path resolves inside the selected repository
root and exists. This is intentionally a floor: an empty or irrelevant file passes path
integrity. ClaimFence does not fetch external URLs or authenticate any evidence.

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
