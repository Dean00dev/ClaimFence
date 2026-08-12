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

## Evidence model

For each matched assurance phrase, the scanner inspects a configurable window around the
line. The initial model recognizes three context classes:

1. **Scope** - version, configuration, fixture, scenario, campaign, or tested condition.
2. **Evidence** - tests, reports, links, artifacts, workflows, or reproduction commands.
3. **Limitation** - explicit negation, prototype status, non-goals, or unsupported scope.

Phrase rules declare the context classes they require. Document rules check for dedicated
verification and limitation sections when assurance findings exist.

## Stability contract

Rule identifiers are the compatibility boundary. Message wording may improve between patch
releases; a rule identifier will not silently change meaning within a minor release.
Baselines use stable fingerprints derived from the rule, filename, and normalized claim.
