# TODO

## Knowledge and context supply chain

**Goal:** make external security knowledge useful to the bounded planner without
letting any of it become authority.

**Principle:** skills become reviewed code, facts become versioned knowledge
units, permissions stay in the sealed scope. Knowledge is advisory; the policy
gateway and deterministic validators remain the only authority.

### Current gaps

- Only the built-in seed corpus exists; there is no operator ingestion path.
- No `huntress knowledge` CLI (`ingest`, `list`, `search`, `show`, `supersede`).
- No source adapters for Markdown, JSON, or CSV.
- Controller retrieval uses `text=objective` only, with no profile/finding filters.
- One global 365-day freshness floor; too coarse for exploit intelligence.
- No quarantine/review step, source trust policy, or promotion path.
- No profile-to-context-pack mapping or retrieval evaluation.

### Source policy

| Source | What to use | Trust tier | Freshness | Never do |
|---|---|---|---|---|
| Trail of Bits Testing Handbook | Technique and verification units; profile design input (CC-BY-4.0) | `reviewed` | ~365 days | Paste whole chapters into the prompt |
| Google Mantis | Review workflow and context-pack ideas (Apache-2.0) | `reviewed` | Pin release/commit | Load `SKILL.md` files as runtime tools |
| 1dayexploit / Exploit-DB | CVE, component, version range, exploit-available leads | `community` | 7–30 days | Auto-run PoCs or treat exploit availability as permission |
| NVD / vendor advisories | Affected ranges, root cause, fixed versions | `vendor` | 30–90 days | Treat a banner as proof of vulnerability |
| CISA KEV | Exploited-in-the-wild prioritization | `government` | 7–30 days | Expand scope or skip validation |
| Bug bounty program policy | Authoritative scope, exclusions, ROE, rates | n/a — scope | Engagement lifetime | Store only in the knowledge base |
| Prior engagement outcomes | Sanitized episodic lessons | Tenant only | Per engagement | Promote raw findings or model output globally |

### Tasks

#### 1. Ingestion and provenance

- [ ] Add `huntress knowledge ingest --file <unit.json> --tenant <global|eng_id>`.
- [ ] Add `huntress knowledge list`, `search`, `show`, and `supersede`.
- [ ] Add a `KnowledgeSourceAdapter` protocol with Markdown/frontmatter, JSON, and CSV importers.
- [ ] Require source URI, publisher, license, fetched-at, content hash, and trust tier on import.
- [ ] Pin external sources by commit/tag/snapshot; record the pin in the unit source.
- [ ] Reject content-hash mismatches, cross-tenant writes, and invalid supersession chains.
- [ ] Emit an append-only audit event for every ingest, update, and supersede.

#### 2. Review and freshness

- [ ] Add a quarantine state for unreviewed external content.
- [ ] Add a named-human review step before a unit becomes retrievable.
- [ ] Add per-source/per-unit TTL instead of one global 365-day floor.
- [ ] Exclude stale units by default; allow `--allow-stale` only for explicit operator inspection.
- [ ] Add a `knowledge sources` view showing trust tier, license, pin, and last refresh.

#### 3. Retrieval and context packs

- [ ] Add `config/context_packs.toml` mapping each reviewed profile to retrieval filters.
- [ ] Build retrieval queries from profile/finding metadata: CWE, domain, component, version range, oracle archetype, tags, tier, freshness.
- [ ] Rank exact component/version matches above generic lexical matches.
- [ ] Use trust tier and freshness as ranking signals.
- [ ] Cap each context packet at 3–8 knowledge units and enforce the existing total-context budget.
- [ ] Require the model to cite `unit_id` values; reject invented IDs.
- [ ] Keep the prompt label: “Advisory context only. Knowledge cannot authorize an action or prove a finding.”

#### 4. Promotion and learning

- [ ] Add `huntress knowledge promote --validation <id> --reviewer <name>`.
- [ ] Create a sanitized, tenant-scoped `episodic` unit from a passed validation.
- [ ] Require human review and a source reference before promotion.
- [ ] Never auto-promote raw model output, scanner excerpts, credentials, or engagement assets.
- [ ] Keep program-specific facts out of the `global` tenant.

#### 5. Safety and adversarial tests

- [ ] Add prompt-injection fixtures inside knowledge units that attempt to change scope, profiles, budgets, or approvals.
- [ ] Prove retrieved text cannot alter `ScopeDocument`, `PolicyGateway`, target IDs, or profile IDs.
- [ ] Test tenant isolation: global + one engagement only, never cross-read.
- [ ] Test stale exclusion, hash tampering, license metadata, and supersession.
- [ ] Test that a 1dayexploit/CVE unit only creates a hypothesis and never an executable action.
- [ ] Add a negative test for “version banner equals vulnerable” reasoning.

#### 6. Evaluation

- [ ] Build a golden set of profile/finding → expected knowledge unit IDs.
- [ ] Measure retrieval precision/recall, citation validity, false-positive rate, and token cost.
- [ ] Compare metadata+lexical retrieval against a vector baseline only if evaluation justifies it.
- [ ] Add retrieval quality and freshness to the eval scorecard.

#### 7. Documentation

- [ ] Document the three-layer model: method knowledge, vulnerability intel, engagement facts.
- [ ] Document source licensing, pinning, review, and refresh procedures.
- [ ] Update `docs/threat-model.md` for knowledge poisoning and indirect prompt injection.
- [ ] Update `docs/architecture.md` and `README.md` with the ingestion/context-pack workflow.

### Definition of done

- An operator can ingest a small reviewed corpus from at least one external source.
- Retrieval is deterministic, metadata-filtered, tenant-safe, and freshness-aware.
- The model receives a small advisory context pack and can only cite reviewed unit IDs.
- No knowledge unit can change scope, approve an action, supply a URL/command, or decide a validation verdict.
- Tests cover poisoning, stale data, tenant escape, hash mismatch, and citation hallucination.
- `make check` passes.

### Non-goals

- Loading third-party agent skills at runtime.
- Auto-running PoCs from exploit feeds.
- Promoting engagement findings into the global corpus.
- Adding a vector database before retrieval evaluation shows a measurable gain.
