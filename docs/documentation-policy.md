# Documentation policy

GitHub issues own scope, priority, assignments and acceptance criteria. PRs and
checks own delivery/review evidence. PLAN.md owns design and sequence. Current
guides/references own supported behavior; decision records preserve rationale.
Historical results are explicitly revision-bound.

The contributor changing behavior updates its canonical documentation in the
same PR. Reviewers validate technical claims. Do not invent maintainer identities,
secret storage guarantees or supported features. Investigate source/spec conflicts
instead of silently porting whichever interpretation is convenient.

Use architecture pages for boundaries, reference pages for exact implemented
contracts, guides for reproducible tasks, decisions for consequential choices,
security pages for threat models and archives for superseded plans/reports.
Do not create a second live status ledger or percentages in the docs.

Link source and named tests, distinguish planned/implemented/activated/qualified,
and retain evidence without duplicating stale PASS claims. Repository links use
relative paths or immutable GitHub source URLs, never workstation absolute paths.
Protocol changes update specifications, decisions and conformance tests together.

Run `npm run docs:check` and review technical semantics manually. The checker
currently validates local file links and the source pin, not heading anchors,
external URLs or correctness of protocol prose.
