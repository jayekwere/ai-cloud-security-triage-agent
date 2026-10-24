# Architecture and engineering decisions

## Runtime and trust

This is a local single-operator CLI, not a hosted service. It has no listener, authentication server, multi-tenant API or cloud credentials. Source code and installed dependencies execute with the user's workstation permissions. Run only in a dedicated working directory and use synthetic inputs.

| Component | Responsibility |
|---|---|
| `models.py` | Bounded JSON read, typed normalization, controlled enums, conservative deduplication |
| `intel.py`, `http.py` | Fixture provenance or fixed public HTTPS feeds, bounded async concurrency, dates and explicit uncertainty |
| `policy.py`, `data/policy.toml` | Authoritative score, priority, SLA target, version and canonical policy digest |
| `agent.py` | Planner protocol; deterministic replay and OpenAI Responses implementation; allowlisted tool dispatch |
| `remediation.py` | Trusted templates/runbooks and exact-object plus unsafe-construct validation |
| `pipeline.py` | Stable ordering, report generation, artifact digests and audit events |
| `approval.py`, `jira.py` | Exact intent binding, one-hour approval TTL, transactional reservation and optional Jira request |
| `cli.py` | Separate analysis, preview, interactive approval and explicit submission commands |

The LLM receives a capability list, not a Python interpreter. Each tool takes an empty object and is bound to the finding chosen by the trusted orchestrator, preventing model-selected identifiers or arbitrary URLs. Evidence and policy must be inspected before proposing remediation, and proposals must be validated. Each tool is allowed once per finding; unknown tools, arguments, repeats, duplicate call IDs and early completion fail the run. There is no parallel model tool execution. The dispatcher does not trust provider schema conformance alone.

OpenAI Responses returns function calls; the application executes only allowed analytical functions, then sends `function_call_output` back for the next model turn. Reasoning output items are carried forward and encrypted reasoning content is requested for stateless continuation. The final natural-language model response is not accepted as evidence or substituted for policy-controlled reports. This deliberately narrows model influence: it demonstrates tool orchestration and validation, not autonomous arbitrary patch generation.

## Input contract

`data/findings.json` is an envelope with exactly `synthetic`, `wiz` and `qualys`. Wiz-inspired rows use `resource`, `control`, `severity_score`; Qualys-inspired rows use `asset_id`, `category`, `cvss_base`. Common required fields are cloud, criticality (integer 1–5), internet_exposed and privileged (JSON booleans), and data_class. CVEs are required only for vulnerability findings. CVSS is numeric 0–10. Clouds: aws/azure. Classification: public/internal/confidential/restricted. Categories: vulnerability/storage_public/iam_wildcard/network_open.

These are small portfolio adapter contracts, not claims of fidelity to licensed Wiz/Qualys export formats. Extra per-row vendor fields are ignored, including description. Only recognized structured fields affect decisions. The input file is capped at 1 MB, each vendor at 500 records. Hashes bind cloud+asset+kind+CVE; aliases are bounded identifiers. No source content is executed.

Duplicate records retain the maximum CVSS, exposure/privilege union, highest criticality and most restrictive classification. The report retains source names. This is intentionally conservative; disagreements do not disappear through averaging. The truncated 16-hex identifier is suitable for this small demo; a production ingestion store should use full digests plus canonical key verification and inventory-backed IDs.

## Risk policy

Version 1.0 uses an additive triage heuristic, capped at 100:

| Signal | Points |
|---|---:|
| CVSS | `round(cvss × 3)` (0–30) |
| Cloud configuration finding | 25 baseline (CVE findings do not receive this) |
| EPSS | `round(epss × 20)` (0–20) |
| KEV present | 35 |
| Internet exposed | 15 |
| Asset criticality | `criticality × 2` (2–10) |
| Confidential/restricted classification | 10 |
| Privileged context | 10 |

Thresholds: P1 ≥80, P2 ≥55, P3 ≥30, otherwise P4. Internet-exposed KEV findings and exposed sensitive storage override to P1. Privileged wildcard entitlements have a P2 floor. Missing, older-than-seven-days, or future-dated CVE evidence adds an uncertainty flag and a P2 floor. Absence from a successfully retrieved KEV feed is a known catalog negative, not proof of safety; absent EPSS data remains unknown. Old positive evidence is retained conservatively and labeled uncertain.

Review targets: P1 24 hours, P2 72 hours, P3 14 days, P4 30 days from evaluation-day midnight UTC. Actual remediation deadlines require business and incident context. Policy parameters and scoring rules are operator-trusted source/configuration. Each decision includes separate digests of the parsed TOML configuration and canonical policy implementation text, plus their combined policy digest; they are not chosen by a model. The repository revision identifies the wider normalization/tooling context.

CVSS, EPSS and KEV have different meanings; adding weighted signals does not produce a calibrated exploitation probability. Weights and overrides are chosen to make tradeoffs inspectable, not claimed to have been empirically optimized. The high-CVSS internal scenario is prioritized below exposed KEV scenarios. Unknown evidence is expensive by design and may generate review load; production calibration should measure missed critical risks, false escalations and owner capacity on time-separated data.

## Data and egress

| Mode | Destination | What crosses the boundary |
|---|---|---|
| `demo` / fixture deterministic | None | Local synthetic files and reports only |
| `triage --intel live` | `www.cisa.gov` KEV feed; `api.first.org` EPSS endpoint | CVE IDs in EPSS query, standard request metadata; no asset or employer identifiers |
| `triage --provider openai --allow-model-egress` | `api.openai.com/v1/responses` | Synthetic finding ID, cloud/category/CVE, numeric risk context, classification, policy/evidence results, trusted proposal and validation results |
| `jira-preview` | None | Writes a local full intent including destination and Jira ADF payload |
| `jira-submit` | One approved `<tenant>.atlassian.net/rest/api/3/issue` | Reviewed payload plus operator-supplied Jira credentials via HTTPS Authorization header |

The model view omits asset aliases and source metadata. The context still includes classification and vulnerability information: minimization is not anonymization or a DLP guarantee. The `synthetic=true` declaration is caller-attested, not a content classifier. Do not supply employer exports or PHI. All output files are ordinary local artifacts; protect their containing directory.

Transport enforces HTTPS, the exact configured hostname, port 443, no URL credentials/fragments, no redirects, a 20-second request timeout and an 8 MB response limit. Public reads retry at most twice; model POSTs and Jira writes do not retry. CISA is fetched once, and EPSS reads are deduplicated by CVE with at most four concurrent requests. No scanner-provided link is fetched. System network/proxy and certificate store configuration remain trusted host dependencies.

`store=false` limits Responses storage as supported by the provider; it does not guarantee zero abuse-monitoring retention, Canadian residency or contractual authorization for health data. No provider key was needed for development's deterministic and mocked tests. Model availability, tool behavior and cost need explicit validation in the user's own API account.

## Remediation and approval

Templates are local trusted code. AWS S3 public-access-block and Azure Storage access controls are emitted as Terraform JSON using placeholders, alongside dependency checks, rollback considerations and rescan steps. CVE fixes use vendor-advisory verification instead of invented versions; IAM and network changes require entitlement/traffic analysis. Exact-object validation rejects modified or foreign proposals and separately scans for execution hooks, broad ingress and embedded credentials. It is intentionally stricter and less flexible than general LLM patch generation.

No Terraform process, cloud SDK, subprocess or cloud write exists. Snippets must be merged into the existing owner's module and reviewed against state; they are not complete root modules. Disabling public Azure network access can break service without private endpoint/DNS preparation, and an S3 public access block does not by itself establish encryption or incident containment. No static pass is called a successful plan.

Jira approval binds canonical JSON covering action, tenant, project, intent ID and complete request payload. An interactive terminal requires typing the full SHA-256 digest after the payload is printed. SQLite stores a self-asserted reviewer alias, expiry and state. `BEGIN IMMEDIATE` atomically reserves one attempt before POST; success becomes sent, exceptions become unknown and cannot replay. A crash after reservation also leaves the intent consumed. Jira reconciliation is required before a human chooses a new intent. This favors duplicate prevention over automatic recovery.

The ledger is a workstation trust boundary, not a signed authorization service. A user or process with local write access can edit it or call approval functions directly. There is no separation of duties between local operator and approver. Production needs independent authenticated reviewers and cryptographically bound, durable approvals.

## Audit and reports

Audit rows contain an ordered sequence, event type, fixed fields, relevant digests, previous hash and current hash. They intentionally exclude raw prompts, remote response bodies, credentials and descriptions. A chain detects editing against a known external copy/head, but a local attacker can rewrite the whole chain, truncate a valid prefix or delete the file. The demo uses deterministic event sequences and evaluation dates, not wall-clock timestamps. Events are flushed at operation completion, so process termination can lose audit events. Production requires immediate durable append, real timestamps and externally anchored/WORM storage.

Reports include input and policy digests, per-finding evidence provenance, uncertainty, tool-output digests, proposed controls and limits. HTML escapes input-derived strings and uses a restrictive content security policy, no scripts and no remote assets. Per-run directories are created exclusively; a later run does not overwrite an existing report. Use a directory owned only by the operator; local filesystem attackers are not isolated by the app.
