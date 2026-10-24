# Threat model: AI-Powered Cloud Security Triage Agent

## 1. Overview

This model covers the local CLI, packaged synthetic data, analytical/model workflows, generated artifacts, optional public-feed reads, separately invoked Jira mutation and CI. User-provided context: an independent portfolio project, with no employer credentials, proprietary exports, patient records or production deployment. It is a reusable architecture model, not a completed vulnerability audit or proof of compliance.

A fresh-context source review mapped the architecture independently; the author verified the material resource paths and reconciled later source/CI changes. Scenarios below are design hypotheses and residual risks, not validated vulnerability findings.

| Component | Purpose and source |
|---|---|
| CLI and orchestration | Separate demo/triage/preview/approve/submit commands; src/cloudtriage/cli.py:21, src/cloudtriage/pipeline.py:151 |
| Input and intelligence | Typed synthetic adapters, conservative merge; fixture or public feeds; src/cloudtriage/models.py:76, src/cloudtriage/intel.py:38, src/cloudtriage/intel.py:63 |
| Authoritative policy | Configuration plus implementation digests; decisions cannot be model-authored; src/cloudtriage/policy.py:31 |
| Planner and tool dispatcher | Scripted demo or optional Responses tool loop; bounded analytical capabilities; src/cloudtriage/agent.py:69, src/cloudtriage/agent.py:82, src/cloudtriage/agent.py:127 |
| Remediation | Trusted proposal-only templates and static validation; src/cloudtriage/remediation.py:11, src/cloudtriage/remediation.py:93 |
| Approval and Jira | Local self-asserted approval, exact intent digest, atomic reservation, one remote attempt; src/cloudtriage/approval.py:31, src/cloudtriage/approval.py:47, src/cloudtriage/jira.py:65 |
| Evidence and CI | Escaped local reports, hash chain, offline checks and GitHub artifact upload; src/cloudtriage/pipeline.py:78, src/cloudtriage/audit.py:15, .github/workflows/ci.yml:29 |

~~~mermaid
flowchart TB
  subgraph External["Untrusted data and optional remote services"]
    I[Synthetic scanner-inspired export]
    F[Public EPSS / KEV]
    M[OpenAI Responses]
    J[Jira Cloud]
  end
  subgraph Host["Trusted operator workstation"]
    N[Normalize and validate]
    P[Deterministic policy]
    T[Bounded tool dispatcher]
    R[Trusted remediation proposals]
    O[Reports / local audit]
    H[Interactive human review]
    L[SQLite exact-intent ledger]
    S[Separate Jira submit]
  end
  I --> N --> P --> T --> R --> O
  F --> P
  T <--> M
  O --> H --> L --> S --> J
~~~

### Effective resources

All paths are relative to the operator-selected working directory unless absolute. Data-path resolution uses the installed package, not a guessed repository root. See src/cloudtriage/pipeline.py:22.

| Workflow | Resource/capability | Configuration and precedence | Effective destination/location | Recipients | Enforcing control / evidence |
|---|---|---|---|---|---|
| Demo / default triage | Findings | Packaged fixture unless --findings supplied | installed cloudtriage/data/findings.json or exact chosen file | Local parser | 1 MB, synthetic declaration, typed fields and record limits; models.py:26, models.py:76 |
| All triage | Policy | Packaged policy.toml plus policy.py implementation | installed cloudtriage/data/policy.toml; policy source | Evaluator, reports, optional model policy tool | Configuration validation and combined digests; policy.py:31 |
| Fixture | Intelligence | Default mode | installed cloudtriage/data/intel.json | Evaluator, reports, optional model | simulated=true, dates/bounds; intel.py:38 |
| Live intel | Catalog read | Explicit --intel live | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | CISA receives unauthenticated GET | Fixed host/path; intel.py:63 |
| Live intel | CVE queries | Unique normalized CVEs | https://api.first.org/data/v1/epss?cve=... | FIRST receives CVE IDs | Fixed host, regex CVE, four concurrent requests, response match; intel.py:78, models.py:76 |
| OpenAI CLI | Model egress | --provider openai + --allow-model-egress + OPENAI_API_KEY / OPENAI_MODEL | https://api.openai.com/v1/responses | OpenAI receives structured synthetic context, tool outputs, API authorization | CLI consent, field minimization, no redirects, bounded tools; cli.py:54, models.py:71, agent.py:92 |
| OpenAI embedding | Model egress | Trusted caller supplies planner/factory and credentials | Same fixed Responses endpoint | OpenAI | Caller owns consent and honest mode labeling; ten-finding cap is keyed to provider label; pipeline.py:151, agent.py:85 |
| Reports | JSON, Markdown, HTML | New --out directory | report.json, report.md, report.html under output | Local filesystem/browser | Exclusive run directory; escaped HTML/CSP; pipeline.py:78, pipeline.py:171 |
| Proposals | Terraform JSON | Trusted template and finding ID | output/<derived-finding-id>.tf.json | Local reviewers only | Exact proposal validation; no execution consumer; remediation.py:93, pipeline.py:229 |
| Dry run | Multiple Jira previews | Demo uses example.atlassian.net / SEC | output/jira-dry-run.json | Local reviewers | No submit call; single intent must be selected or freshly previewed; pipeline.py:220 |
| Jira preview | Single intent | --report, --finding-id, --host, --project, --out | Exact chosen intent path | Local human reviewer | Host/project checks and exclusive create; cli.py:85, jira.py:16 |
| Approval | Ledger | Exact --ledger path | SQLite approvals table | Trusted local user/processes | Full-envelope digest, one-hour TTL, primary key and atomic reservation; approval.py:16, approval.py:31, approval.py:47 |
| Jira submit | Remote creation | Reviewed envelope host/project/payload; JIRA_EMAIL/JIRA_API_TOKEN supplied separately | https://<approved-tenant>.atlassian.net/rest/api/3/issue | Approved tenant and its project participants | Exact approval reservation before one POST; credentials never in URL; jira.py:65 |
| Jira receipt | Receipt / evidence | New submit --out directory | receipt.json and audit.jsonl | Local reviewers | Returned key/project validation; no full issue-field readback; cli.py:107, jira.py:92 |
| Audit | Event chain | In-memory events flushed in finally | output/audit.jsonl or submit-output/audit.jsonl | Local verifier | Allowlisted fields and linked hashes, not authenticated durability; audit.py:15, audit.py:34 |
| CI | Runner execution / export | Push, PR and manual workflow | Ubuntu jobs; synthetic evidence stored in GitHub Artifacts for seven days | GitHub runner/artifact readers per repository policy | contents:read, pinned actions, no stored checkout credential, ten-minute jobs, offline integrations; .github/workflows/ci.yml:2, .github/workflows/ci.yml:7, .github/workflows/ci.yml:17, .github/workflows/ci.yml:49 |

All network consumers use the common HTTPS transport: exact logical host, port 443, no embedded URL credentials, no redirects, default certificate verification, 20-second request timeout and 8 MB response cap. Public GETs have at most three attempts; payload-bearing POSTs have one. Actual DNS, environmental proxies and certificate trust remain host assumptions (src/cloudtriage/http.py:18).

## 2. Threat model, trust boundaries and assumptions

**Protected assets.** Integrity of priorities, evidence/proposal provenance, approved Jira target/content, credentials, report confidentiality and externally shared artifacts. There is no cloud credential or deployment authority to protect within this implementation.

**Actors.** The operator controls installed code, policy, environment, input/output/ledger paths and any Python embedding callables. An export producer controls data the operator chooses to ingest. Feed services provide intelligence; an optional model provides tool requests. A reviewer is a local self-asserted alias. Jira independently authenticates the submitting account. CI executes repository code on ephemeral runners.

**Input boundary.** Attacker-controlled scanner text is excluded from reconstructed Finding objects; typed structured fields still influence priorities. synthetic=true is an assertion, not provenance validation or DLP. Format-valid aliases/classifications could still be sensitive if an operator violates the synthetic-only contract. Limits and field reconstruction constrain size and interpretation, not data truth (models.py:26, models.py:76).

**Model boundary.** The model has exactly five no-argument tools. Dispatcher checks names, arguments, prerequisites, uniqueness, completion and budget. The finding is bound by trusted orchestration, not an LLM identifier. It cannot author policy, select a URL, alter a template, read environment variables, run code, approve or submit. Source-level restrictions enforce this independently of prompt wording or provider schemas (agent.py:127). Free-form model prose is not promoted into evidence. Bad model output can still make a run fail or waste the bounded request budget.

**Privacy boundary.** CLI consent applies to the CLI wrapper; direct library callers already have the Python process's authority and must preserve consent, planner/provider consistency and budgeting. Model context excludes raw descriptions and asset/source aliases but retains structured risk/classification/CVE fields and derived tool output. store=false is not a residency, zero-retention, contractual or PHI approval guarantee (models.py:71, agent.py:92, cli.py:54).

**Remediation boundary.** Proposal generation is local trusted code and exact-object validation, not unconstrained AI patch execution. Static acceptance says nothing about a successful provider validate, state mapping, plan, connectivity, deployment or rescan. Existing modules, encryption/key policies, private DNS/endpoints and change/incident ownership must be reviewed outside this app (remediation.py:11, remediation.py:93).

**Approval boundary.** Human authorization is for the complete canonical intent: action, tenant, project, intent timestamp and payload. Ledger reservation is transactional and consumes before network activity, so races/replays cannot authorize a second attempt through the same ledger (approval.py:47). The terminal/full-digest step discourages accidental approval but does not authenticate a separate person. It is not a sandbox against the operator, library callers or a writer of the ledger/source. No file ownership, symlink, permission-hardening or ledger signature checks are implemented.

**Identity/provenance limits.** The digest does not bind the submitting Jira credential account. Preview does not authenticate a report's origin or independently establish its proposal's validity. Any syntactically valid Jira Cloud tenant can be deliberately chosen and approved. The human must inspect the full payload; Jira applies its own account permissions. Response validation checks the project/key, not independently read-back issue fields (jira.py:16, jira.py:65).

**Evidence boundary.** Audit verification checks internal chain consistency. Without a trusted external head/count it accepts a valid prefix and cannot resist deletion or full recomputation by a writer. Events use deterministic sequence/evaluation context rather than wall-clock event timestamps, and are buffered until completion. Early parsing/intelligence failures can occur before audit creation; process termination can lose buffered events. Output directories must be operator-owned. Protecting against a hostile same-user process is outside the app (audit.py:28, audit.py:34, pipeline.py:171).

**Build/CI boundary.** No runtime dependencies are declared, but Python/build tools and development dependencies still execute trusted code. Direct dev versions and Actions are pinned; transitive Python dependencies/build backend are not hash-locked. PR code can change test outputs within an unprivileged runner; no deployment secrets are supplied. An artifact's existence is not approval of its content (.github/workflows/ci.yml:29).

## 3. Attack surface, mitigations and attacker stories

These scenarios are hypotheses used to reason about controls and residual risk, not confirmed exploitation claims.

| Priority | Scenario / capability gain | Prerequisites | Impact | Existing controls | Mitigation / residual question | Evidence |
|---|---|---|---|---|---|---|
| High | Scanner description attempts instruction injection to obtain command or Jira authority | Operator ingests attacker-controlled export | Unauthorized change if analytical authority were expanded | Raw text omitted; schema-controlled fields; no write/command tool | Preserve capability boundary; test tool denial when extending adapters | models.py:76; agent.py:127; tests/test_agent.py |
| High | Hostile model asks for deployment, arbitrary endpoint, repeated call or premature completion | Explicit provider mode, compromised/incorrect response | Workflow failure or unauthorized mutation if dispatcher trusts model | Local allowlist, {}, ordering, uniqueness, budgets and completion checks | Keep external writes outside model registry; evaluate real-provider failure cases before reliance | agent.py:127 |
| High | Different Jira target/content substituted after human review | Attacker can replace intent file but not approval ledger | Misrouted ticket / unintended disclosure | Full-envelope digest recalculated at reservation; changes lose approval | Authenticate source report in production; bind credential principal where required | approval.py:31; approval.py:47; jira.py:65 |
| High | Local ledger forgery or direct approval-library call is mistaken for independent human authorization | Writer/process already has operator's filesystem/process authority | Apparent approval without separate reviewer | Explicit trusted-host scope; TTY check only in CLI | Central authenticated reviewers, signed intents, private service-owned state; not a new remote privilege boundary here | cli.py:91; approval.py:16 |
| High | Real sensitive data is mislabeled synthetic and intentionally sent to a model or Jira | Operator supplies sensitive structured data and opts into egress | Confidentiality/residency harm | Synthetic-only contract, omission of descriptions/asset aliases, explicit egress | Inventory-backed provenance, DLP, privacy/vendor approval, allowlisted projects; synthetic flag alone cannot prove safety | models.py:71; cli.py:54; jira.py:30 |
| Medium | Feed poisoning or stale intelligence suppresses remediation | Feed-origin compromise/inaccuracy or stale catalog | Incorrect prioritization | Fixed TLS origins, dates/bounds, unknown/stale P2 floor, conservative positives | Independently verify critical applicability, signed/cached source records; policy is heuristic | intel.py:26; intel.py:63; policy.py:49 |
| Medium | Jira POST succeeds but client times out; retry creates duplicates | Explicitly approved live write and ambiguous network outcome | Duplicate issues, notifications or incorrect evidence | Reserve before POST, no POST retry, consumed unknown state | Operator reconciles tenant; durable remote idempotency/readback would improve recovery | approval.py:47; jira.py:92; http.py:18 |
| Medium | Audit truncation/recomputation creates plausible incomplete evidence | Writer of local output files | Loss of evidence integrity/completeness | Internal sequence/hash checks detect ordinary altered entries | Immediate timestamped append, external anchored heads/counts and WORM retention | audit.py:15; audit.py:34 |
| Medium | Terraform snippet is applied blindly to an existing resource | Operator bypasses documented plan/change workflow outside app | Availability or configuration regression | Placeholder templates, static checks, explicit proposal-only status, no executor | Owner sandbox plan, dependency/identity/key review, staged rollout and rescan evidence | remediation.py:11; remediation.py:93 |
| Medium | Oversized/malformed data or expensive model behavior consumes resources | Chosen input or opted-in provider | Local denial of service / bounded API cost | 1 MB input, 500/vendor, 8 MB response, four feed reads, tool rounds/tokens/findings cap | Batch scheduling, budget enforcement and stronger streaming parsers for production | models.py:26; http.py:18; agent.py:127; pipeline.py:151 |
| Medium | Dependency or workflow code runs with broader secrets than intended | Future pipeline change or compromised dependency | Build/repository credential theft | No live credentials, contents:read, no persisted checkout token, pinned Actions, job limits | Hash-lock/attest dependencies; review workflow changes and artifact access; protect branches | .github/workflows/ci.yml:7; .github/workflows/ci.yml:23 |
| Low | Malicious report string becomes active browser HTML | Tampered report object or future relaxed adapters | Browser-side content execution | Escaping, no scripts/remote assets, CSP | Keep all dynamic contexts escaped and avoid adding inline scripts | pipeline.py:78; tests/test_integrations_cli.py |
| Low | Existing output accidentally replaced | Repeated operator run | Lost review evidence | Exclusive new output directory and JSON/audit creates | Preserve prior directories; host-write attackers remain trusted-host risk | pipeline.py:26; pipeline.py:171 |

## 4. Severity calibration

**Critical:** A future remotely reachable boundary that permits unapproved privileged cloud changes or exposes a large regulated data store could be critical. No cloud executor, public service or real patient dataset exists here, so a critical production scenario is unsupported by this repository alone.

**High:** A genuine bypass permitting an untrusted model/export to submit an unreviewed issue to an unintended tenant would violate a meaningful authority boundary. The current model registry lacks any submit tool, and exact-intent reservation blocks simple substitution. A local operator editing their own SQLite ledger is outside independent reviewer isolation and should not be mislabeled a remote approval bypass.

**Medium:** Poisoned valid feed data, loss of local evidence completeness, ambiguous external outcomes or unsafe human use of a snippet could cause operational harm, conditional on live mode or downstream actions. Existing fail-closed/read-only controls reduce automatic impact but do not validate the underlying data or deployment.

**Low:** Presentation errors or accidental local artifacts without credential/authority gain generally have lower impact. Existing output refusal and HTML escaping provide counterevidence. Actual malicious browser execution or broad exposure would require evidence beyond a malformed synthetic field.

Confidence in architecture claims comes from source inspection and targeted tests recorded separately in VALIDATION.md. No blanket audit coverage or regulatory assurance is claimed. Remaining production questions: authenticated vendor data/provenance, approved AI processing/residency, independent approver identity, principal binding, central durable audit/idempotency, actual Terraform plans and rollout/rescan evidence.

Repository: https://github.com/jayekwere/ai-cloud-security-triage-agent
Version: source snapshot SHA-256 854d2af94a2aed35b35ca485648a002ee407a7eafe1544fe643be47d67ef7b53

