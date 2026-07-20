# AI-Classified Honeypot Attack Monitor

A honeypot deployed on Azure that captures real-world SSH attack traffic and uses a hybrid rule-based + LLM pipeline to classify attacker behavior in real time.

## Architecture
## Real Results

Over multiple days of live internet exposure:

- **975 total attacker sessions** captured and classified
- **52 unique source IPs**
- **494 sessions classified at high confidence**
- **4 confirmed exploit attempts**
- One single IP (**45.156.87.253**) accounted for **762 sessions (78% of all traffic)**, cycling through reconnaissance, brute-force, and exploit-attempt phases across multiple days — consistent with dedicated, persistent botnet infrastructure rather than a one-off scan
- Attack tooling identified directly from session data included **ZGrab** (mass internet scanner), **Nmap SSH algorithm enumeration**, and generic Go-based SSH clients

## Design Decisions

**Hybrid classification, not pure LLM.** Early testing showed the vast majority of sessions follow near-identical patterns (successful login with default credentials → automated hardware/OS fingerprinting script). Sending every session to an LLM quickly exhausted free-tier API quotas at real traffic volume. The pipeline now classifies obvious patterns locally with zero API cost, and reserves the LLM for genuinely novel sessions — cutting API usage by over 80% while preserving classification quality for the cases that actually need it.

**Model selection.** Uses Google Gemini after evaluating cost and free-tier limits across providers — chosen specifically because it was the most cost-effective option for this classification task, not because of brand familiarity.

## Setup

See inline comments in `classify_sessions.py` for configuration. Requires:
- A Cowrie honeypot instance logging to JSON (`cowrie.json`)
- A Gemini API key (free tier available at aistudio.google.com/apikey)
- Python packages: `google-genai`, `streamlit`, `pandas`

```bash
pip install google-genai streamlit pandas
export GEMINI_API_KEY=your_key_here
export COWRIE_LOG_PATH=/path/to/cowrie.json
python3 classify_sessions.py
```

Run the dashboard separately:
```bash
streamlit run dashboard.py
```

## Security Note

Real administrative SSH access was moved to a non-standard port and restricted by source IP *before* the honeypot port was exposed to the public internet, to avoid any risk to the underlying VM.

## SIEM Integration — Splunk

Deployed **Splunk Enterprise** as a second, independent analysis pipeline alongside the Gemini-based classifier, ingesting the same real Cowrie log data to demonstrate SIEM operations skills: SPL query authoring, dashboard building, and log-based incident detection.

**Real findings surfaced through Splunk analysis:**

- **913 successful logins vs. only 7 failures** — expected honeypot behavior (Cowrie is intentionally permissive to maximize observed post-login attacker activity), not a misconfiguration.
- **A single source IP, `45.156.87.204`, generated 6,086 sessions** — over 20x the next-highest attacker — consistent with dedicated botnet infrastructure repeatedly targeting the honeypot.
- **A Splunk timeline query (`timechart span=1h count`) revealed a service outage**: 7,382 events compressed into a single hour on July 17, followed by a hard drop to zero. Root-caused to the Cowrie process being killed by the Linux OOM killer under memory pressure on the VM's 1GB RAM. Diagnosed via `splunkd.log` and system memory analysis, resolved by provisioning 4GB of swap space and restarting the service — the outage had gone undetected for approximately 3 days until identified through this analysis.
- **Identified an attacker running a sophisticated, multi-fallback system-fingerprinting script** (testing `busybox`/`bash`/`sh` execution paths, checking `/proc/device-tree/model` for ARM/embedded hardware) — consistent with reconnaissance for IoT/embedded-device botnet targeting, more advanced than the majority of observed recon attempts.

**Dashboard**: built in Splunk Dashboard Studio with three panels (login outcome breakdown, top attacking IPs, attack activity over time), backed by hand-authored SPL queries rather than Splunk's built-in defaults.

## SIEM Integration — Splunk

Deployed **Splunk Enterprise** as a second, independent analysis pipeline alongside the Gemini-based classifier, ingesting the same real Cowrie log data to demonstrate SIEM operations skills: SPL query authoring, dashboard building, and log-based incident detection.

**Real findings surfaced through Splunk analysis:**

- **913 successful logins vs. only 7 failures** — expected honeypot behavior (Cowrie is intentionally permissive to maximize observed post-login attacker activity), not a misconfiguration.
- **A single source IP, `45.156.87.204`, generated 6,086 sessions** — over 20x the next-highest attacker — consistent with dedicated botnet infrastructure repeatedly targeting the honeypot.
- **A Splunk timeline query (`timechart span=1h count`) revealed a service outage**: 7,382 events compressed into a single hour on July 17, followed by a hard drop to zero. Root-caused to the Cowrie process being killed by the Linux OOM killer under memory pressure on the VM's 1GB RAM. Diagnosed via `splunkd.log` and system memory analysis, resolved by provisioning 4GB of swap space and restarting the service — the outage had gone undetected for approximately 3 days until identified through this analysis.
- **Identified an attacker running a sophisticated, multi-fallback system-fingerprinting script** (testing `busybox`/`bash`/`sh` execution paths, checking `/proc/device-tree/model` for ARM/embedded hardware) — consistent with reconnaissance for IoT/embedded-device botnet targeting, more advanced than the majority of observed recon attempts.

**Dashboard**: built in Splunk Dashboard Studio with three panels (login outcome breakdown, top attacking IPs, attack activity over time), backed by hand-authored SPL queries rather than Splunk's built-in defaults.

## SIEM Integration — Splunk

Deployed **Splunk Enterprise** as a second, independent analysis pipeline alongside the Gemini-based classifier, ingesting the same real Cowrie log data to demonstrate SIEM operations skills: SPL query authoring, dashboard building, and log-based incident detection.

**Real findings surfaced through Splunk analysis:**

- **913 successful logins vs. only 7 failures** — expected honeypot behavior (Cowrie is intentionally permissive to maximize observed post-login attacker activity), not a misconfiguration.
- **A single source IP, `45.156.87.204`, generated 6,086 sessions** — over 20x the next-highest attacker — consistent with dedicated botnet infrastructure repeatedly targeting the honeypot.
- **A Splunk timeline query (`timechart span=1h count`) revealed a service outage**: 7,382 events compressed into a single hour on July 17, followed by a hard drop to zero. Root-caused to the Cowrie process being killed by the Linux OOM killer under memory pressure on the VM's 1GB RAM. Diagnosed via `splunkd.log` and system memory analysis, resolved by provisioning 4GB of swap space and restarting the service — the outage had gone undetected for approximately 3 days until identified through this analysis.
- **Identified an attacker running a sophisticated, multi-fallback system-fingerprinting script** (testing `busybox`/`bash`/`sh` execution paths, checking `/proc/device-tree/model` for ARM/embedded hardware) — consistent with reconnaissance for IoT/embedded-device botnet targeting, more advanced than the majority of observed recon attempts.

**Dashboard**: built in Splunk Dashboard Studio with three panels (login outcome breakdown, top attacking IPs, attack activity over time), backed by hand-authored SPL queries rather than Splunk's built-in defaults.

## SIEM Integration — Splunk

Deployed **Splunk Enterprise** as a second, independent analysis pipeline alongside the Gemini-based classifier, ingesting the same real Cowrie log data to demonstrate SIEM operations skills: SPL query authoring, dashboard building, and log-based incident detection.

**Real findings surfaced through Splunk analysis:**

- **913 successful logins vs. only 7 failures** — expected honeypot behavior (Cowrie is intentionally permissive to maximize observed post-login attacker activity), not a misconfiguration.
- **A single source IP, `45.156.87.204`, generated 6,086 sessions** — over 20x the next-highest attacker — consistent with dedicated botnet infrastructure repeatedly targeting the honeypot.
- **A Splunk timeline query (`timechart span=1h count`) revealed a service outage**: 7,382 events compressed into a single hour on July 17, followed by a hard drop to zero. Root-caused to the Cowrie process being killed by the Linux OOM killer under memory pressure on the VM's 1GB RAM. Diagnosed via `splunkd.log` and system memory analysis, resolved by provisioning 4GB of swap space and restarting the service — the outage had gone undetected for approximately 3 days until identified through this analysis.
- **Identified an attacker running a sophisticated, multi-fallback system-fingerprinting script** (testing `busybox`/`bash`/`sh` execution paths, checking `/proc/device-tree/model` for ARM/embedded hardware) — consistent with reconnaissance for IoT/embedded-device botnet targeting, more advanced than the majority of observed recon attempts.

**Dashboard**: built in Splunk Dashboard Studio with three panels (login outcome breakdown, top attacking IPs, attack activity over time), backed by hand-authored SPL queries rather than Splunk's built-in defaults.
