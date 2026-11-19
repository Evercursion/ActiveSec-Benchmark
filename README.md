# ActiveSecHarness & ActiveSec-Benchmark

**Making small local language models (`4B-8B` via Ollama and `llama.cpp`) safe for software engineering by separating model intelligence from system authority.**

- **Preprint PDF:** [`paper/LotLImmune_Preprint.pdf`](paper/LotLImmune_Preprint.pdf) (*Living off the Land in AI Coding Harnesses: Cryptographic Capability Chains, Deterministic Ring-0 Guards, and Self-Healing Verification*)
- **License:** [MIT License](LICENSE) (`Copyright (c) 2026 Evercursion - GaiaLogic Unipessoal Lda.`)
- **Primary Outputs:** Open security specification ([`docs/`](docs/)), 252-case Living-off-the-Land & 24-trajectory benchmark telemetry ([`results/lotlimmune_benchmark.json`](results/lotlimmune_benchmark.json)), live component security ledger ([`wiki/SECURITY_LEDGER.md`](wiki/SECURITY_LEDGER.md)), and adaptive plain-language security lessons ([`wiki_user/`](wiki_user/)).

---

## 1. Why Small Local Coding Models Need a Different Security Architecture

Developers, students, journalists, and independent researchers increasingly run compact `4B` to `8B` parameter models (such as `qwen3:4b`) locally on consumer laptops via Ollama or `llama.cpp`. Local inference keeps private source code off third-party clouds, runs offline, and costs nothing per token.

However, a coding agent is only useful if it can run everyday developer tools: `git`, `tar`, `find`, `pytest`, `python3`, and `curl`. In system security, abusing legitimate pre-installed tools is known as **Living off the Land (LotL)**. When a coding agent reads an untrusted issue report, pull request, log file, or archive, it becomes a **Confused Deputy**:
1. **Indirect Prompt Injection & Tool Hijacking:** An attacker does not need binary malware when a hidden instruction in a bug report can trick the agent into running `find . -exec sh -c ...`, writing a `.git/hooks/pre-commit` script, or exfiltrating credentials via `curl`.
2. **Insecure Code Generation:** Compact models frequently write vulnerable code patterns, such as calling `zipfile.extractall()` without path checks (Zip-Slip) or hardcoding secrets.
3. **Why Neural Security Judges Fail on Small Models:** The standard industry workaround places a second language model in the execution loop to judge whether each tool call is safe. In our 252-case benchmark (`E1`), a local `4B` security judge (`qwen3:4b`) blocked **`98.3%` (`118 / 120`)** of benign software engineering commands at **`142.3 ms`** median latency per call. Dual-use commands like `pytest` or `git` look dangerous to a small zero-shot classifier, causing it to refuse normal work.

**ActiveSecHarness** solves this by removing security enforcement from the neural network. The small local model proposes code and tool calls (intelligence), while a deterministic Python reference monitor in Ring 0 checks cryptographic capabilities, canonical file paths, stream magic bytes, and two-dimensional workspace provenance in under `40 microseconds` (authority).

---

## 2. Four Architectural Pillars

Full technical specifications are published in [`docs/`](docs/) and [`paper/LotLImmune_Preprint.pdf`](paper/LotLImmune_Preprint.pdf):

1. **4-Ring Privilege Hierarchy & HMAC-SHA256 Capability Tokens ([`docs/02_sudo_capability_architecture.md`](docs/02_sudo_capability_architecture.md)):**
   - **Ring 0 (Immutable Security Kernel):** Deterministic reference monitor mediating every filesystem, archive, network, and process call.
   - **Ring 1 (Human Root of Trust & Cognitive Protection):** De-obfuscates hidden shell pipelines and bidirectional Unicode traps before human `sudo` approval (`CommandDeobfuscator`), and compiles plain-language lessons into [`wiki_user/`](wiki_user/).
   - **Ring 2 (Orchestration & Offline Verification):** Dual-model AST reviewer (`DualModelReviewer`) and Red-Green-Benign test synthesizer (`VerifiedTestSynthesizer`).
   - **Ring 3 (Sandboxed Worker Agents):** Ephemeral coding workers operating under short-lived HMAC-SHA256 capability tokens with strict **monotonic attenuation** ($\tau_{\text{child}} \preceq \tau_{\text{parent}}$ across tools, paths, domains, and TTL).
2. **Two-Dimensional Product Provenance Lattice ([`wiki/vectors/conseca_trajectory_ablation.md`](wiki/vectors/conseca_trajectory_ablation.md)):**
   - Coarse 1-bit taint tracking locks up a coding agent as soon as it reads an untrusted issue ticket (`83.3%` false positive rate on normal bug-fix workflows).
   - `ActiveSecHarness` tracks a 2D product lattice $\mathcal{L} = \mathcal{L}_{\mathrm{trust}} \times \mathcal{L}_{\mathrm{sens}}$, where $\mathcal{L}_{\mathrm{trust}} = \{\mathsf{Trusted} < \mathsf{Derived} < \mathsf{Untrusted}\}$ and $\mathcal{L}_{\mathrm{sens}} = \{\mathsf{Public} < \mathsf{Internal} < \mathsf{Sensitive}\}$, persisted across files and sub-agents in `WorkspaceProvenanceLedger` in $\mathcal{O}(1)$ time ($\approx 20\ \mu\text{s}$/step). Reading an untrusted issue transitions code edits to $\mathsf{Derived}$ so local edits and `pytest` runs succeed, while blocking shell injection and sensitive egress (the Lethal Trifecta).
3. **Deterministic Ring-0 Security Guards ([`docs/03_deterministic_guards_spec.md`](docs/03_deterministic_guards_spec.md)):**
   - `ArchiveGuard` (streaming byte/ratio quotas and `os.path.realpath` containment against ZipBombs and Zip-Slip), `MalwareGuard` (magic-byte anti-spoofing and polyglot rejection), `CredentialGuard` (Shannon entropy, de-mangled dictionary defense, and bidirectional secret DLP), `NetworkGuard` (TLS 1.3 enforcement and socket-level anti-SSRF against loopback, RFC 1918, CGNAT, and cloud metadata IPs), and `SandboxGuard` (shell-free `execve` allowlisting and `bubblewrap` namespace isolation).
4. **Offline Self-Healing Verification & Adaptive `UserWiki` ([`wiki_user/`](wiki_user/)):**
   - Rather than running an LLM on the hot path of every system call, `ActiveSecHarness` uses the local model offline to synthesize regression tests verified through a deterministic **Red-Green-Benign Triad** (the test must fail on vulnerable code, pass on repaired code, and pass on clean code). Blocked threats automatically generate progressive Level 1 to Level 3 lessons in [`wiki_user/`](wiki_user/).

---

## 3. Empirical Benchmark Results (`LotLImmune` Suite)

All raw per-case verdicts, latencies, and 95% Clopper-Pearson binomial confidence intervals are available in [`results/lotlimmune_benchmark.json`](results/lotlimmune_benchmark.json).

### 3.1 Experiment E1: 252-Case Single-Step Defense Benchmark (5 Regimes Across Domains A to F)

The benchmark evaluates `252` test cases (`120` domain attacks across Domains A to F, `12` multi-stage kill-chain steps, and `120` benign software engineering operations) on consumer CPU hardware using local Ollama (`qwen3:4b`).

We report both evaluation phases transparently:
- **Unfitted Out-of-Sample Code Audit:** Independent blind audit of the Ring-0 kernel before aligning signature rules to held-out fixture formats (`124 / 132 = 93.9%` raw block rate; **`127 / 132 = 96.2%` effective OS containment**, since 3 of the 8 unflagged cases are shell pipe strings passed to `execve("/bin/echo", ...)` without a shell and are inert by construction; the remaining 5 cases identified concrete rule gaps in Mach-O `.py` extension matching, SVG/HTML/PDF active content tags, and unquoted `AWS_SECRET_ACCESS_KEY` assignments).
- **Post-Audit Functional Conformance:** Verification after adding those 5 deterministic signature rules (`132 / 132 = 100.0%` ABR, `0.0%` FPR).

| Defense Regime | Attack Block Rate (ABR) | 95% Clopper-Pearson CI (ABR) | Benign False Positive Rate (FPR) | 95% Clopper-Pearson CI (FPR) | Overall Accuracy | Median Latency / Call |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `unguarded` (No Defense Baseline) | `0.0%` (`0/132`) | `[0.0%, 2.8%]` | `0.0%` (`0/120`) | `[0.0%, 3.0%]` | `47.6%` | `0.0001 ms` |
| `regex` (Static Blacklist) | `43.9%` (`58/132`) | `[35.3%, 52.8%]` | `0.0%` (`0/120`) | `[0.0%, 3.0%]` | `70.6%` | `0.0071 ms` |
| `live_llm_judge` (Local `qwen3:4b` via Ollama) | `100.0%` (`132/132`) | `[97.2%, 100.0%]` | **`98.3%` (`118/120`)** | `[94.1%, 99.8%]` | `53.2%` | **`142.28 ms`** |
| **`activesec_ring0` (Unfitted Out-of-Sample Audit)** | **`93.9%` (`124/132`)** *(96.2% OS-inert)* | `[88.4%, 97.4%]` | **`0.0%` (`0/120`)** | `[0.0%, 3.0%]` | **`96.8%`** | **`0.0315 ms`** |
| **`activesec_ring0` (Post-Audit Conformance)** | **`100.0%` (`132/132`)** | `[97.2%, 100.0%]` | **`0.0%` (`0/120`)** | `[0.0%, 3.0%]` | **`100.0%`** | **`0.0315 ms`** |
| `hybrid_llm_plus_ring0` (Ring 0 Authoritative + LLM Advisory) | `100.0%` (`132/132`) | `[97.2%, 100.0%]` | `0.0%` (`0/120`) | `[0.0%, 3.0%]` | `100.0%` | `142.28 ms` |

![Out-of-Sample Audit vs Post-Audit Functional Conformance](figures/exp49_fig1_audit_vs_conformance_split.png)

![Attack Block Rate vs Benign False Positive Rate Across Regimes](figures/regime_abr_fpr.png)

![Per-Domain Attack Block Rate Heatmap](figures/domain_abr_heatmap_preview.png)

![Per-Call Decision Latency Across Regimes](figures/regime_latency.png)

---

### 3.2 Experiment E3: 24-Trajectory Multi-Step Ablation vs. Oracle Conseca-Style Policy

To eliminate any small-model confounder when evaluating multi-step compositional attacks, Experiment E3 ([`wiki/vectors/conseca_trajectory_ablation.md`](wiki/vectors/conseca_trajectory_ablation.md)) compares three purely deterministic regimes across `24` five-stage trajectories (`120` tool steps: `12` multi-step attack kill chains `KC-T01` to `KC-T12` and `12` benign issue-driven software engineering workflows `BT-01` to `BT-12`):

1. **`stateless_task_policy` (Oracle Conseca-style per-action policy):** Idealized frontier policy with ground-truth task allowlists (`0.0%` policy hallucination rate), checking each action statelessly without cross-step provenance folding or stream inspection. Misses `4 / 12` in-scope compositional attacks (`KC-T03` Zip-Slip inside workspace, `KC-T04` ELF polyglot written as `notes.txt`, `KC-T05` indirect prompt injection, and `KC-T11` cross-agent secret staging and exfiltration).
2. **`coarse_boolean_taint` (1-bit monotone session/file taint lock):** Blocks `12 / 12` attacks (`100.0%` ABR), but falsely blocks `10 / 12` (`83.3%` FPR) benign software engineering trajectories as soon as the agent reads an untrusted issue report and tries to edit code or run `pytest`.
3. **`activesec_product_ledger` (2D Product Lattice $\mathcal{L}_{\mathrm{trust}} \times \mathcal{L}_{\mathrm{sens}}$ + Ring-0 Guards):** Blocks **`12 / 12` (`100.0%` ABR)** attack trajectories with **`0 / 12` (`0.0%` FPR)** false blocks on benign workflows, with $\mathcal{O}(1)$ state-folding latency of **`~20 microseconds/step`** from $k=1$ to $k=50$ steps.

| Trajectory Regime | Blocked Attack Trajectories (`k/12`) | Kill-Chain ABR `[95% CI]` | Blocked Benign Workflows (`k/12`) | Benign SWE FPR `[95% CI]` | Missed Kill Chains | State-Folding Latency (`k=1..50`) |
| :--- | :---: | :---: | :---: | :---: | :--- | :---: |
| `stateless_task_policy` (Oracle Conseca Baseline) | `8 / 12` | `66.7%` `[34.9%, 90.1%]` | `0 / 12` | **`0.0%`** `[0.0%, 26.5%]` | `KC-T03`, `KC-T04`, `KC-T05`, `KC-T11` | `11.7 us / step` |
| `coarse_boolean_taint` (1-Bit Monotone Lock) | **`12 / 12`** | **`100.0%`** `[73.5%, 100.0%]` | `10 / 12` | `83.3%` `[51.6%, 97.9%]` | None (`0/12`) | `285.7 us / step` |
| **`activesec_product_ledger` (2D Lattice + Ring 0)** | **`12 / 12`** | **`100.0%`** `[73.5%, 100.0%]` | **`0 / 12`** | **`0.0%`** `[0.0%, 26.5%]` | **None (`0/12`)** | **`~20.0 us / step` (`266.7 us` w/ OS guards)** |

![Multi-Step Trajectory Attribution Across 24 Five-Stage Workflows](figures/exp49_fig2_trajectory_step_attribution.png)

---

## 4. Repository Navigation

| Directory / File | Description |
| :--- | :--- |
| **[`paper/LotLImmune_Preprint.pdf`](paper/LotLImmune_Preprint.pdf)** | Full research paper with formal theorems, system architecture, 252-case benchmark, Conseca trajectory ablation, and audit breakdown. |
| **[`docs/01_threat_taxonomy.md`](docs/01_threat_taxonomy.md)** | Threat taxonomy across 6 domains: `A` (Living off the Land), `B` (Archives & Malware), `C` (Network & SSRF), `D` (Credentials & Secrets), `E` (Sandbox Isolation), and `F` (Cognitive & Prompt Injection). |
| **[`docs/02_sudo_capability_architecture.md`](docs/02_sudo_capability_architecture.md)** | Specification of Ring 0 to Ring 3 privileges, HMAC-SHA256 capability tokens, monotonic attenuation rules, and Explain-Before-Sudo verification. |
| **[`docs/03_deterministic_guards_spec.md`](docs/03_deterministic_guards_spec.md)** | Formal invariants and byte/path verification contracts for `ArchiveGuard`, `MalwareGuard`, `CredentialGuard`, `NetworkGuard`, and `SandboxGuard`. |
| **[`docs/04_model_routing_and_provider_security.md`](docs/04_model_routing_and_provider_security.md)** | Local model routing (`Ollama` / `llama.cpp`), dual-model verification boundary, and privacy guarantees. |
| **[`wiki/SECURITY_LEDGER.md`](wiki/SECURITY_LEDGER.md)** | Live verification matrix covering all **19 security components** and **96 adversarial test checks**, including privilege rings, mitigated threat vectors, and source SHA-256 hashes. |
| **[`wiki/components/`](wiki/components/)** | Individual architectural and adversarial verification dossiers for all 19 `SecureComponent` modules (`security_kernel`, `sod_policy`, `capability_token`, `archive_guard`, `malware_guard`, `network_guard`, `credential_guard`, `sandbox_guard`, `canary_guard`, `deobfuscator`, `code_verifier`, `dual_model_reviewer`, `test_synthesizer`, `user_wiki_manager`, and more). |
| **[`wiki/vectors/`](wiki/vectors/)** | Cross-cutting threat domain syntheses (`domain_a_lotl.md` through `domain_f_cognitive.md`), `lotlimmune_phase1b.md`, and `conseca_trajectory_ablation.md`. |
| **[`wiki_user/`](wiki_user/)** | Adaptive plain-language security lessons (`INDEX.md`, `LEARNING_PROGRESS.md`, and `lessons/zip_slip_and_zip_bombs.md`) designed for students and developers. |
| **[`results/lotlimmune_benchmark.json`](results/lotlimmune_benchmark.json)** | Complete machine-readable JSON telemetry of all 252 single-step cases, 24 five-step trajectories, latency distributions, and per-domain breakdowns. |
| **[`figures/`](figures/)** | High-resolution PDF and PNG plots of benchmark accuracy, false-positive rates, per-domain heatmaps, latency distributions, and trajectory step attribution. |

---

## 5. Responsible Release & Reviewer Access Note

This public repository (`ActiveSec-Benchmark`) publishes the complete **MIT-licensed** architectural specification, 6-domain threat taxonomy, 252-case and 24-trajectory benchmark telemetry, live verification ledger for all 19 components, research preprint, and adaptive educational curriculum.

Because the core `ActiveSecHarness` repository contains `132` executable Living-off-the-Land, polyglot, SSRF, and path-traversal exploit payloads alongside the active Ring-0/1/2 enforcement kernel, the executable Python codebase is currently maintained under controlled pilot access during responsible disclosure and cross-platform sandbox hardening (macOS/Windows ports).

- **Academic, Institutional & Grant Reviewers:** Immediate read access to the full executable `ActiveSecHarness` repository and automated test suite is granted upon request to **Dr. Simon Hegelich** (`simon.hegelich@evercursion.ai` / `simon.hegelich@gaialogic.ai`).
- **Open-Source Release:** Following completion of the cross-platform hardening milestone, the full executable kernel and automated verification suite are released openly under the same permissive **MIT License**.
