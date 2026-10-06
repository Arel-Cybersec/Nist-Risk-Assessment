# NIST RMF Security Risk Assessment: `Nist-Risk-Assessment`

| Field | Value |
|---|---|
| Assessment type | Static, read-only security control assessment (NIST SP 800-37 Rev.2 **Assess** step) |
| Control baselines | NIST SP 800-53 Rev.5 (Moderate baseline), NIST CSF 2.0, risk method per NIST SP 800-30 Rev.1 |
| Assessed revision | `5b1e5e4` (branch `main`), matches the uploaded archive `Nist-Risk-Assessment-main` byte-for-byte |
| Assessment date | 2026-10-06 |
| In-scope artifacts | `index.html`, `main.tf`, `iam.tf`, `s3.tf`, `providers.tf`, `scan.py`, `.gitignore`, `README.md`, git history |
| Method | Manual review of every file and line, review of git history for secrets and the earlier "vulnerable baseline", and test runs of `scan.py` (Appendix A) |

> **Scoring convention.** Each risk gets Likelihood (L) and Impact (I) on the same 1–5 scale the project's own 5×5 matrix uses. Score = L × I. **High** is 12 or more, **Moderate** is 6–11 and **Low** is 5 or less. These bands match `tierFor()` in `index.html:990-995`, with that tool's "Critical" band (20 and up) folded into High.

> **Scope honesty.** The repository has **no server-side application, no API, no database, no authentication layer and no container images**. Several of the 16 requested features (CORS, session tokens, SQLi/NoSQLi, file upload, Docker/K8s) therefore have **no implementation surface**. For each of these, this report either (a) assesses the nearest real equivalent in the Terraform cloud boundary or (b) marks the control *Not Applicable* and says so. It does not invent findings.

---

## 1. System Characterization & Boundary Scope

### 1.1 Components inventory

| ID | Component | File(s) | Role | Data handled |
|---|---|---|---|---|
| C1 | Risk calculator SPA | `index.html` (1,400 lines: CSS 10-728, markup 731-965, JS 969-1398) | Static client-side 5×5 L×I calculator with simulated "evidence stream" | User clicks only; nothing persisted or transmitted |
| C2 | Google Fonts | `index.html:7-9` | Third-party CSS and font delivery | Visitor IP and User-Agent sent to Google |
| C3 | VPC + subnet | `main.tf:2-12` | Network boundary `10.0.0.0/16`, single subnet `10.0.1.0/24` in `us-east-1a` | — |
| C4 | Security group | `main.tf:15-45` | Ingress 22/tcp from `192.168.1.50/32`, 80/tcp from `0.0.0.0/0`, all egress | — |
| C5 | EC2 app server | `main.tf:48-59` | "FinTech-Core-App", tagged `Environment=Production` | Application runtime (no user-data defined) |
| C6 | S3 bucket | `s3.tf:2-39` | `simulated-fintech-customer-data-2026`, tagged `DataClass=PII-PHI` | **PII / PHI** at rest |
| C7 | IAM group, policy, user | `iam.tf:2-55` | `FinTech-Developers` group, `dev-analyst-01` user | Human access to C5 and C6 |
| C8 | Terraform provider | `providers.tf:1-26` | AWS provider `~> 5.0` pointed at LocalStack `http://localhost:4566` | Static mock credentials |
| C9 | Policy-as-code scanner | `scan.py:1-20` | Substring linter over three `.tf` files | Reads IaC source |

### 1.2 Spatial boundary map (3D depth layout)

The map below reads as stacked **Z-planes**. Plane Z0 sits nearest the viewer (the untrusted public internet) and each lower plane is one trust boundary deeper. Arrows that cross a plane are data flows across a trust boundary; `╳` marks a boundary crossing with a control gap.

```
                         ┌────────────────────────────────────────────────────────────┐
  Z0  PUBLIC PLANE      ╱  Internet users / attackers          Google Fonts CDN (C2)    ╱│
  (untrusted)          ╱   ▲ browser loads index.html (C1)      ▲ IP+UA leak  ╳ no SRI ╱ │
                      └──────┼───────────────────────────────────┼─────────────────────┘  │
                             │ HTTP :80  ╳ no TLS, no CSP         │                       │
                             ▼                                    │                       │
                         ┌────────────────────────────────────────────────────────────┐  │
  Z1  EDGE PLANE        ╱  Security Group secure-api-sg (C4)                          ╱│ │
  (perimeter)          ╱   in: 80/tcp 0.0.0.0/0  ·  22/tcp 192.168.1.50/32           ╱ │ │
                      ╱    out: ALL 0.0.0.0/0  ╳ unrestricted egress                ╱  │ │
                     └──────┼─────────────────────────────────────────────────────┘   │ │
                            │  ╳ no ALB, no WAF, no IGW/route tables defined          │ │
                            ▼                                                         │ │
                         ┌────────────────────────────────────────────────────────────┐ │
  Z2  COMPUTE PLANE     ╱  VPC 10.0.0.0/16 → subnet 10.0.1.0/24 (us-east-1a only)     ╱│ │
  (workload)           ╱   EC2 FinTech-Core-App (C5)                                 ╱ │ │
                      ╱    ╳ IMDSv1 allowed  ╳ root EBS unencrypted  ╳ single AZ    ╱  │ │
                     └──────┼────────────────────────────────────────────────────┘    │ │
                            │ (no instance profile: app→S3 path is NOT wired)          │ │
                            ▼                                                          │ │
                         ┌────────────────────────────────────────────────────────────┐ │ │
  Z3  DATA PLANE        ╱  S3 simulated-fintech-customer-data-2026 (C6) PII-PHI       ╱│ │ │
  (crown jewels)       ╱   ✔ Public Access Block ×4                                  ╱ │ │ │
                      ╱    ╳ no SSE-KMS  ╳ no versioning  ╳ no TLS-only deny        ╱  │ │ │
                     ╱     ╳ no access logs ╳ no Object Lock ╳ no replication      ╱   │ │ │
                    └─────────▲──────────────────────▲─────────────────────────────┘   │ │ │
                              │ Get/Put/List          │ GetObject                       │ │ │
                              │ (human, direct)       │ role/FinTechCoreAppRole         │ │ │
                              │                       │ ╳ role not defined in code      │ │ │
                         ┌────┴───────────────────────┴───────────────────────────────┐ │ │ │
  Z4  CONTROL PLANE     ╱  IAM (C7): FinTech-Developers ← dev-analyst-01              ╱│ │ │ │
  (identity & IaC)     ╱   ╳ no MFA  ╳ no password policy  ╳ ec2:Start/Stop on "*"  ╱ │ │ │ │
                      ╱    Terraform (C8) → LocalStack http://localhost:4566        ╱  │ │ │ │
                     ╱     ╳ static creds in code ╳ local state ╳ no lock file     ╱   │ │ │ │
                    ╱      scan.py (C9) ╳ exit 0 always ╳ CWD-dependent            ╱    │ │ │ │
                   └──────────────────────────────────────────────────────────────┘     │ │ │ │
  Z5  ASSURANCE     (absent) CloudTrail · VPC Flow Logs · GuardDuty · AWS Backup · CI    ┘ ┘ ┘ ┘
```

### 1.3 Data flows

| Flow | Source → Sink | Crosses boundary | Protection observed | Gap |
|---|---|---|---|---|
| DF-1 | Browser → `index.html` origin | Z0→Z1 | None in repo (hosting unspecified) | No CSP or security headers; SG allows HTTP/80 only |
| DF-2 | Browser → `fonts.googleapis.com` / `fonts.gstatic.com` | Z0→third party | HTTPS | No SRI (not possible for dynamic Google CSS); privacy leak |
| DF-3 | Internet → EC2 :80 | Z0→Z2 | SG ingress | Cleartext, no WAF/ALB |
| DF-4 | Admin → EC2 :22 | Z0→Z2 | SG `/32` | Long-lived SSH; RFC1918 source cannot match internet traffic |
| DF-5 | `dev-analyst-01` → S3 PII (Get/Put/List) | Z4→Z3 | IAM group policy | Human write access to PII, no MFA, no TLS-only condition, unlogged |
| DF-6 | `FinTechCoreAppRole` → S3 PII (GetObject) | Z4→Z3 | Bucket policy | Principal unmanaged, hardcoded account ID |
| DF-7 | EC2 → `0.0.0.0/0` (any) | Z2→Z0 | None | Unrestricted egress (exfiltration / C2 path) |
| DF-8 | Terraform CLI → LocalStack | Z4 local | — | `http://` endpoints, static creds |
| DF-9 | In-page JS data → DOM via `innerHTML` | C1 internal | Constants only today | Unsafe sink pattern (see NIST-25) |

---

## 2. NIST Control Gap Analysis Table

Status legend: **✔ Implemented** · **◐ Partial** · **✖ Not Implemented** · **— N/A** (no implementation surface exists in this repo)

| # | Feature (800-53 family) | Key 800-53 Rev.5 controls | CSF 2.0 | Status | Evidence (file:lines) | Findings |
|---|---|---|---|---|---|---|
| 1 | **[AC]** Access Control: RBAC / BOLA | AC-2, AC-3, AC-5, AC-6, AC-6(9) | PR.AA-05 | ◐ | Admin wildcards removed (`iam.tf:7-39`), Public Access Block on (`s3.tf:12-19`). But humans hold Put/Get/List on the PII bucket (`iam.tf:15-26`) while the workload role only has Get (`s3.tf:29-35`), and `ec2:Start/StopInstances` applies to `Resource="*"` including Production (`iam.tf:28-36`). App-level RBAC/BOLA: — N/A (no API). | NIST-01, NIST-13 |
| 2 | **[IA]** Identification & Authentication: sessions, MFA, token TTL | IA-2(1), IA-2(2), IA-5(1), IA-11, AC-12 | PR.AA-01, PR.AA-03 | ✖ | IAM user `dev-analyst-01` (`iam.tf:42-44`) has no MFA requirement, no `aws:MultiFactorAuthPresent` condition, no `aws_iam_account_password_policy`, and is a long-lived user rather than SSO/federated. The SPA has no sessions, yet shows "Session Active" (`index.html:775,960`). | NIST-04, NIST-05 |
| 3 | **[SC]** System & Communications Protection: TLS, CORS, headers | SC-7, SC-7(5), SC-8, SC-8(1), SC-13, SC-18, SC-28 | PR.DS-02, PR.IR-01 | ✖ | HTTP/80 only (`main.tf:29-36`). No `aws:SecureTransport` deny (`s3.tf:25-38`). Egress `-1 / 0.0.0.0/0` (`main.tf:38-44`). No CSP, Referrer-Policy or Permissions-Policy (`index.html:3-10`). Inline handlers and script block a strict CSP (`index.html:858-860, 969-1398`). Terraform endpoints use `http://` (`providers.tf:20-25`). CORS: — N/A (no API). | NIST-02, NIST-09, NIST-10, NIST-21 |
| 4 | **[SI]** System & Information Integrity: injection, validation | SI-2, SI-3, SI-7, SI-10, SI-15 | PR.DS-01, ID.RA-01 | ◐ | No SQL, NoSQL or shell sinks exist. `innerHTML` + template literals at `index.html:1106, 1121, 1153, 1235, 1263, 1301, 1380, 1390` currently take constants only. **Information integrity failure:** fabricated CVE/EPSS/CVSS values from `Math.random()` (`index.html:1286-1298`). Unvetted AMI (`main.tf:49`). | NIST-05, NIST-11, NIST-25 |
| 5 | **[CA]** Security Assessment & Authorization: dependencies | CA-2, CA-7, RA-5, SA-11, SR-3 | ID.RA-01, DE.CM-09 | ✖ | `scan.py` cannot gate a pipeline: always exits 0, flags comments, passes silently from a different directory (verified, Appendix A). No `.terraform.lock.hcl`, no CI workflow, no IaC SAST (tfsec/Checkov/Trivy). Provider pinned `~> 5.0` while the 6.x major line is current (`providers.tf:5-6`). | NIST-07, NIST-12 |
| 6 | **[CM]** Configuration Management: secrets, env files | CM-2, CM-3, CM-6, CM-7, IA-5(7) | PR.PS-01, ID.AM-08 | ◐ | `.gitignore:5-6,16-17` correctly excludes `*.tfstate` and `*.tfvars`. Git history contains no real secrets (scanned for `AKIA`, `password` and `secret_key`). Still: static credentials in code (`providers.tf:12-13`), credential validation disabled (`providers.tf:15-17`), hardcoded account ID and AMI (`s3.tf:32`, `main.tf:49`), no `default_tags`, no remote state backend. | NIST-15, NIST-22 |
| 7 | **[CP]** Contingency Planning: backup, recovery, failover | CP-2, CP-6, CP-9, CP-10, SC-36 | PR.DS-11, RC.RP-01 | ✖ | No `aws_s3_bucket_versioning`, replication, AWS Backup plan or Object Lock (`s3.tf:2-9`). Single AZ subnet and single instance (`main.tf:8-12, 48-59`). Terraform state local only (no `backend` block in `providers.tf:1-9`). SPA results exist only in memory (`index.html:987`). | NIST-06, NIST-18 |
| 8 | **[IR]** Incident Response: verbose errors, detection | IR-4, IR-5, IR-6, SI-4, SI-11 | DE.CM-01, RS.MA-01 | ✖ / — | Verbose error leakage: — N/A (no server and no `try/catch` paths; the SPA throws nothing to users). Detection and response wiring is absent: no GuardDuty, CloudWatch alarms, SNS, EventBridge or Security Hub. The UI *claims* escalation and SIEM logging that does not exist (`index.html:1296-1298`). | NIST-08, NIST-05 |
| 9 | **[AU]** Audit & Accountability: tamper-resistant logs | AU-2, AU-3, AU-6, AU-9, AU-9(2), AU-10, AU-12 | DE.CM-03, PR.PS-04 | ✖ | No `aws_cloudtrail`, no S3 server access logging or data events, no VPC Flow Logs, no log bucket with Object Lock. The UI prints `AUDIT_HASH: 0x<random> · LOGGED TO SIEM` (`index.html:1287, 1298`), a fabricated non-repudiation artifact. | NIST-03, NIST-05 |
| 10 | **[MP]** Media Protection: uploads, ephemeral storage | MP-4, MP-6, SI-3, SC-28 | PR.DS-01 | ✖ / — | No upload UI or API (— N/A in the app). In the cloud boundary, humans can `s3:PutObject` arbitrary content into the PII bucket (`iam.tf:18-19`) with no content-type/size condition, no malware scanning, no lifecycle expiry and unencrypted EBS (`main.tf:48-59`). | NIST-14, NIST-26 |
| 11 | **[SA]** System & Services Acquisition: third-party scripts/CDNs | SA-9, SA-12 (now SR-3/SR-4), SR-11 | GV.SC-07, ID.SC | ◐ | No third-party **scripts** (good). Third-party **stylesheet** from Google Fonts (`index.html:7-9`). AMI of unknown provenance with no `owners` filter (`main.tf:49`). Provider install has no lock-file checksums. | NIST-12, NIST-11, NIST-23 |
| 12 | **[RA]** Risk Assessment: data-flow & sinks | RA-3, RA-3(1), RA-5, RA-7 | ID.RA-04, ID.RA-05 | ◐ | Data flows mapped in §1.3. The tool's own scoring has **inconsistent thresholds**: `tierFor()` (`index.html:990-995`) and `cellTone()` (`index.html:996-1002`) disagree for scores 10-11 and 15-19. The "NIST SP 800-30 Rev.1 compliant" claim (`index.html:772`) is not traceable to 800-30 Appendix G-I scales. | NIST-17 |
| 13 | **[PL]** Security Planning: trust boundaries | PL-2, PL-8, SA-8, SC-7(21) | GV.PO, PR.IR-01 | ✖ | No tiering: subnet labelled "public" but no IGW, route table, NACL, private subnet, ALB or WAF (`main.tf:2-12`). Web and app run on one host. No architecture or SSP document. Public/internal route split: — N/A (no API routes). | NIST-16 |
| 14 | **[PS]** Personnel Security: escalation, defaults, backdoors | PS-4, PS-5, AC-2(3), AC-6(5), CM-7 | GV.RR-04 | ◐ | No IAM self-escalation primitives (`iam:*`, `iam:PassRole`, `sts:AssumeRole`): ✔. No testing backdoors, debug routes or default admin accounts found. Gaps: no permissions boundary, no access review or expiry for the named user (`iam.tf:42-55`). `aws_iam_group_membership` is *exclusive* and silently evicts out-of-band members (`iam.tf:47-55`). | NIST-04, NIST-13 |
| 15 | **[PE]** Physical & Environmental: cloud deploy / root execution | PE-* (inherited from AWS), CM-7, SC-39, SC-28 | PR.IR-02 | ◐ | Docker/K8s: — N/A (no Dockerfile or manifests). Host equivalents: IMDSv1 not disabled, root EBS unencrypted, previous-generation `t2.micro`, `Environment=Production` on a single-AZ, non-redundant host (`main.tf:48-59`). Physical controls are inherited from the AWS shared-responsibility model. | NIST-09, NIST-20 |
| 16 | **[PT]** PII Processing & Transparency | PT-2, PT-3, PT-5, SC-28(1), SI-12 | PR.DS-01, GV.OC-03 | ✖ | Bucket tagged `DataClass=PII-PHI` (`s3.tf:7`) but no customer-managed KMS key, no bucket key, no Macie classification, and no separate bucket/prefix isolation for PHI vs PII. UI claims "Enc_AES-256-GCM" encryption it does not perform (`index.html:776, 946, 1361`). Google Fonts sends visitor PII (IP) to a third party without notice (`index.html:7-9`). | NIST-19, NIST-23, NIST-05 |

**Roll-up:** 0 fully implemented · 7 partial · 9 not implemented (two of those, IR and MP, are N/A at the application layer but failed at the cloud layer).

---

## 3. Risk Register

Sorted by score, highest first. Every entry cites file paths and exact line ranges at revision `5b1e5e4`.

### High (score of 12 or more)

- **NIST-01: Human principals hold read/write on the PII-PHI bucket and the workload role does not** · *AC-3, AC-6, AC-6(9)*
  - **Detail:** `FinTech-Developers` gets `s3:GetObject`, `s3:PutObject` and `s3:ListBucket` on the full PII-PHI bucket. The app role only gets `GetObject`. That reverses least privilege: people can bulk-list, exfiltrate and overwrite regulated data directly with long-lived keys, with no MFA, IP, VPC-endpoint or TLS condition.
  - **Likelihood 4 · Impact 4 · Score 16 · High**
  - **Files:** `iam.tf:14-26`, `s3.tf:2-9`, `s3.tf:28-36`

- **NIST-02: No encryption in transit, either at the web tier or for S3** · *SC-8, SC-8(1), SC-13*
  - **Detail:** The only public listener is HTTP/80 (no 443, ACM or ALB). The bucket policy has no `Deny` on `aws:SecureTransport = false` and no `s3:TlsVersion` floor, so a FinTech/PHI workload can serve cleartext.
  - **L 4 · I 4 · Score 16 · High**
  - **Files:** `main.tf:29-36`, `s3.tf:22-39`

- **NIST-03: No tamper-resistant audit trail for any critical state change** · *AU-2, AU-9(2), AU-12*
  - **Detail:** The code defines no CloudTrail (management or S3 data events), no S3 server access logging, no VPC Flow Logs and no immutable log store with Object Lock. Reads, writes and deletes of PHI, IAM changes and SG edits are unattributable.
  - **L 4 · I 4 · Score 16 · High**
  - **Files:** absent from all `.tf`. Should sit alongside `s3.tf:2-19`, `main.tf:2-5`

- **NIST-04: No MFA, password policy or federation for the human identity** · *IA-2(1), IA-5(1), AC-2(3)*
  - **Detail:** `dev-analyst-01` is a static IAM user with nothing that enforces MFA (`aws:MultiFactorAuthPresent`), no account password policy, and no expiry or review. One phished credential reaches the PII bucket (NIST-01).
  - **L 3 · I 5 · Score 15 · High**
  - **Files:** `iam.tf:41-55`, `iam.tf:11-38`

- **NIST-05: Fabricated security evidence and false assurance claims in the GRC UI** · *SI-7, AU-10, PT-5, PL-4*
  - **Detail:** The "Evidence Stream" invents CVE IDs, EPSS and CVSS with `Math.random()`. A random `CVE-2024-NNNNN` can collide with a real, unrelated CVE. It also prints a random "AUDIT_HASH … LOGGED TO SIEM" and a random-size "AES-256-GCM" evidence ZIP, and states "Chain of custody maintained". Badges assert "NIST_Compliant", "Enc_AES-256-GCM" and "Session Active" with nothing behind them. Anyone who puts this output in an audit file is presenting fabricated evidence.
  - **L 5 · I 3 · Score 15 · High**
  - **Files:** `index.html:772-777`, `index.html:938-949`, `index.html:958-963`, `index.html:1286-1298`, `index.html:1359-1361`

- **NIST-06: No backup, versioning or failover for regulated data and infrastructure state** · *CP-9, CP-10, CP-6, SC-36*
  - **Detail:** The bucket has no versioning, replication or Object Lock, so a `PutObject` overwrite (allowed by NIST-01) or ransomware is unrecoverable. Everything runs in one AZ on one instance. Terraform state is local with no remote backend or locking, so losing a laptop loses the infrastructure's source of truth.
  - **L 3 · I 4 · Score 12 · High**
  - **Files:** `s3.tf:2-9`, `main.tf:8-12`, `main.tf:48-59`, `providers.tf:1-9`

- **NIST-07: The compliance scanner cannot serve as an assessment control** · *CA-2, CA-7, RA-5*
  - **Detail:** Each defect below was verified (Appendix A):
    - (a) Always exits 0, so it cannot fail a pipeline.
    - (b) Uses CWD-relative paths and passes silently (zero findings) when run from another directory.
    - (c) Substring matching flags the *comment* at `s3.tf:21` as a HIGH wildcard finding.
    - (d) Misses semantic variants such as `block_public_acls = false` (single space), `"s3:*"`, `::/0`, missing `metadata_options`, missing encryption or logging.
    - (e) Does not tell ingress from egress `0.0.0.0/0`.
    - (f) Hardcoded file list skips `providers.tf` and any new file.
  - **L 4 · I 3 · Score 12 · High**
  - **Files:** `scan.py:3-8`, `scan.py:11-19`, `scan.py:20`

- **NIST-08: No threat detection or incident alerting path** · *IR-4, IR-5, SI-4, IR-6*
  - **Detail:** The code defines no GuardDuty, Security Hub, CloudWatch metric filters or alarms, SNS topic, or EventBridge rules. The UI's "IMMEDIATE ESCALATION REQUIRED" message has no real response hook behind it.
  - **L 4 · I 3 · Score 12 · High**
  - **Files:** absent from all `.tf`. UI claim at `index.html:1295-1296`

### Moderate (score 6-11)

- **NIST-09: IMDSv1 left enabled on the EC2 instance** · *SC-7, CM-7, AC-3*
  - **Detail:** With no `metadata_options { http_tokens = "required" }`, any SSRF in the public web tier can reach `169.254.169.254`. There is no instance profile today, which limits the blast radius. That changes the moment the app role from `s3.tf:32` is attached.
  - **L 3 · I 3 · Score 9 · Moderate**
  - **Files:** `main.tf:48-59`

- **NIST-10: Unrestricted egress** · *SC-7(5), SC-7(11)*
  - **Detail:** The rule allows all protocols to `0.0.0.0/0`, which gives a compromised host a free exfiltration and C2 channel. Deny-by-default egress is not applied.
  - **L 3 · I 3 · Score 9 · Moderate**
  - **Files:** `main.tf:38-44`

- **NIST-11: AMI of unknown provenance, hardcoded and unpatched** · *CM-2, SI-2, SR-4*
  - **Detail:** `ami-0c55b159cbfafe1f0` is a literal ID: no `data "aws_ami"` lookup, `owners` filter, golden-image pipeline or patch baseline. AMI IDs are region-specific and get deprecated, so the image is stale or unknown.
  - **L 3 · I 3 · Score 9 · Moderate**
  - **Files:** `main.tf:49-50`

- **NIST-12: No supply-chain integrity or continuous monitoring for the IaC toolchain** · *SA-11, SR-3, CA-7, CM-14*
  - **Detail:**
    - No `.terraform.lock.hcl` is committed, so provider binaries are not hash-pinned.
    - No CI workflow, IaC SAST, Dependabot or Renovate.
    - `~> 5.0` keeps the project one major provider version behind.
    - No `SECURITY.md` or vulnerability-disclosure policy.
  - **L 3 · I 3 · Score 9 · Moderate**
  - **Files:** `providers.tf:2-8`, repository root (no `.github/`)

- **NIST-13: Developers can stop or start the Production instance and memberships are exclusive** · *AC-5, AC-6, PS-5*
  - **Detail:** `ec2:StartInstances` and `ec2:StopInstances` on `Resource = "*"` have no `aws:ResourceTag/Environment` condition, so any developer can take Production down (an availability risk and a separation-of-duties gap). `aws_iam_group_membership` is authoritative for the group and evicts members added outside Terraform, which can cause unexpected access removals or hide drift.
  - **L 3 · I 3 · Score 9 · Moderate**
  - **Files:** `iam.tf:27-36`, `iam.tf:46-55`, `main.tf:55-58`

- **NIST-14: Uncontrolled writes into the PII bucket, with no object hygiene** · *MP-6, SI-3, SI-12*
  - **Detail:** Human `PutObject` (NIST-01) has no `s3:x-amz-server-side-encryption`, content-type or size condition. No malware scanning (GuardDuty Malware Protection for S3), no lifecycle expiry for transient objects and no retention schedule.
  - **L 3 · I 3 · Score 9 · Moderate**
  - **Files:** `iam.tf:17-20`, `s3.tf:2-9`

- **NIST-15: Static credentials and disabled validation in the provider block** · *IA-5(7), CM-6*
  - **Detail:** `access_key` and `secret_key` are literals with credential and account validation skipped, over `http://` endpoints. The values are mocks scoped to LocalStack, so there is no live exposure. The pattern itself is the risk: copied into a real environment, it becomes a committed secret, and secret scanners will keep raising noise on it.
  - **L 2 · I 4 · Score 8 · Moderate**
  - **Files:** `providers.tf:11-25`

- **NIST-16: No defined trust-boundary architecture** · *PL-8, SA-8, SC-7*
  - **Detail:** The subnet is called "public" but no internet gateway, route table or NACL is defined, so reachability is undefined and untestable. There is no private subnet, ALB/WAF tier, VPC endpoint for S3 or architecture document. Web, app and management share one host.
  - **L 3 · I 3 · Score 9 · Moderate**
  - **Files:** `main.tf:1-12`, `main.tf:47-59`

- **NIST-17: The risk-scoring engine disagrees with itself** · *RA-3, SI-7*
  - **Detail:** `tierFor()` uses bands of 20 and up / 12 / 6, while `cellTone()` uses 20 and up / 15 / 10 / 6. Scores 10-11 render in "high" colour but are labelled *Moderate*, and the "very-high" tone (15-19) has no matching tier. The UI also claims "NIST SP 800-30 Rev.1 compliant" while using a multiplicative 1-25 scale that 800-30 Appendices G-I do not define. Results are not traceable to the cited method.
  - **L 4 · I 2 · Score 8 · Moderate**
  - **Files:** `index.html:990-1002`, `index.html:772`, `index.html:1317-1362`

- **NIST-18: Assessments are not persisted or exportable** · *AU-3, CP-9, RA-3(1)*
  - **Detail:** Scores live in an in-memory array, and Reset or a page reload erases them. No export, timestamped record or assessor identity is kept, so a risk decision cannot be reconstructed.
  - **L 4 · I 2 · Score 8 · Moderate**
  - **Files:** `index.html:986-987`, `index.html:1376-1395`

- **NIST-19: PHI/PII is not encrypted with a customer-managed key and has no data isolation** · *SC-28(1), PT-2, SC-12*
  - **Detail:** No `aws_s3_bucket_server_side_encryption_configuration` or `aws_kms_key` is defined. Modern S3 defaults to SSE-S3, which partially mitigates this, but that gives no key-policy separation of duties, no key-usage audit trail and no crypto-shredding. PII and PHI share one bucket with no prefix or bucket isolation and no Macie classification.
  - **L 2 · I 4 · Score 8 · Moderate**
  - **Files:** `s3.tf:1-9`

- **NIST-20: Unencrypted root EBS volume** · *SC-28*
  - **Detail:** There is no `root_block_device { encrypted = true }` and no account-level `aws_ebs_encryption_by_default`.
  - **L 2 · I 3 · Score 6 · Moderate**
  - **Files:** `main.tf:48-59`

- **NIST-21: No browser security policy (CSP or headers)** · *SC-18, SI-10, SC-8*
  - **Detail:** The page has no `Content-Security-Policy`, `Referrer-Policy` or `Permissions-Policy`. Static hosts such as GitHub Pages cannot send headers, so a `<meta http-equiv>` CSP is the only option. Inline `onclick` handlers and one inline `<script>` block force `'unsafe-inline'` unless refactored.
  - **L 2 · I 3 · Score 6 · Moderate**
  - **Files:** `index.html:3-10`, `index.html:858-860`, `index.html:969-1398`

- **NIST-22: Bucket policy trusts a hardcoded, unmanaged principal** · *CM-2, CM-3, AC-3*
  - **Detail:** The bucket policy grants `arn:aws:iam::123456789012:role/FinTechCoreAppRole`. Both the account ID and the role are outside Terraform, so the grant drifts from reality. If the placeholder ID is ever replaced by an account the team does not control, the result is a cross-account data grant.
  - **L 2 · I 3 · Score 6 · Moderate**
  - **Files:** `s3.tf:30-33`

- **NIST-23: Third-party font CDN without integrity or privacy notice** · *SA-9, SR-11, PT-5*
  - **Detail:** Google Fonts CSS is generated per user-agent, so SRI cannot be applied. Every page view sends visitor IP and UA to Google; EU courts have ruled this unlawful without consent (LG München I, 3 O 17493/20). Self-hosting removes both issues.
  - **L 3 · I 2 · Score 6 · Moderate**
  - **Files:** `index.html:7-9`

- **NIST-24: Management via SSH from a non-routable "corporate" address** · *AC-17, AC-17(3)*
  - **Detail:** `192.168.1.50/32` is RFC 1918 space and can never be the source address of internet traffic. The rule is either dead or will be "fixed" by widening it. No `key_name` or SSM is defined, so there is no auditable management path at all.
  - **L 2 · I 3 · Score 6 · Moderate**
  - **Files:** `main.tf:20-27`

### Low (score 5 or less)

- **NIST-25: Unsafe DOM sink pattern (`innerHTML` with template literals)** · *SI-10*
  - **Detail:** `appendLog()` interpolates `text` raw into `innerHTML`, and so do the cell, button and formula builders. Every current input is a constant or a number, so this is **not exploitable today**. It becomes DOM XSS as soon as real CVE feeds, URL parameters or imported registers reach these functions.
  - **L 1 · I 4 · Score 4 · Low**
  - **Files:** `index.html:1106-1111`, `index.html:1121-1130`, `index.html:1153-1158`, `index.html:1235-1236`, `index.html:1259-1266`, `index.html:1380`, `index.html:1390-1391`

- **NIST-26: Animation loops ignore reduced-motion and visibility** · *SC-6 (resource availability), plus accessibility (non-NIST, WCAG 2.3.3)*
  - **Detail:** The canvas particle field (O(n²) line pass every frame) and the radar sweep run `requestAnimationFrame` forever. The `prefers-reduced-motion` guard applies only to CSS animations, so the JS loops keep running for vestibular-sensitive users and drain battery on low-power devices.
  - **L 5 · I 1 · Score 5 · Low**
  - **Files:** `index.html:725-727`, `index.html:1034-1065`, `index.html:1068-1082`

**Totals:** 8 High · 16 Moderate · 2 Low · **26 findings**

---

## 4. Prioritized Remediation Roadmap

Steps are ordered by risk score. Each step names the findings it closes and the files it touches. Effort is S (under 1 hour), M (under 1 day) or L (several days).

### Phase 0: Immediate (0-7 days): High findings

1. **Lock PHI access to workloads, not people** (NIST-01, NIST-04, NIST-13) · `iam.tf` · M
   - Remove `s3:PutObject` and `s3:ListBucket` on the PII bucket from `FinTech-Developers`. If humans need break-glass read access, grant it through an assumable role with `aws:MultiFactorAuthPresent = true` and `aws:MultiFactorAuthAge < 3600`.
   - Add a group-wide `Deny` on everything except `iam:*MFADevice*` and `sts:GetSessionToken` when MFA is absent.
   - Add `aws_iam_account_password_policy` (minimum length 14, reuse prevention 24, max age 90). Plan migration of `dev-analyst-01` to IAM Identity Center / SSO with a session duration of 8 hours or less.
   - Add `Condition = { StringNotEquals = { "aws:ResourceTag/Environment" = "Production" } }` to the EC2 start/stop statement.
   - Replace `aws_iam_group_membership` with `aws_iam_user_group_membership`, which is non-exclusive.

2. **Enforce TLS everywhere** (NIST-02) · `s3.tf`, `main.tf` · M
   ```hcl
   # s3.tf: add to the bucket policy Statement list
   {
     Sid       = "DenyInsecureTransport"
     Effect    = "Deny"
     Principal = "*"
     Action    = "s3:*"
     Resource  = [aws_s3_bucket.fintech_storage.arn, "${aws_s3_bucket.fintech_storage.arn}/*"]
     Condition = { Bool = { "aws:SecureTransport" = "false" } }
   },
   {
     Sid       = "DenyOldTLS"
     Effect    = "Deny"
     Principal = "*"
     Action    = "s3:*"
     Resource  = [aws_s3_bucket.fintech_storage.arn, "${aws_s3_bucket.fintech_storage.arn}/*"]
     Condition = { NumericLessThan = { "s3:TlsVersion" = "1.2" } }
   }
   ```
   Put an ALB in front of the instance with an ACM certificate and `ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"`. Redirect 80 to 443 at the ALB and allow the instance SG ingress **only** from the ALB SG.

3. **Stand up the audit plane** (NIST-03) · new `logging.tf` · M
   - Create a dedicated log bucket with `object_lock_enabled = true` (COMPLIANCE mode, at least 365 days), versioning on, and SSE-KMS.
   - Create an `aws_cloudtrail` that is multi-region, has `enable_log_file_validation = true` (AU-9(3) integrity digests) and S3 data events for the PII bucket.
   - Add `aws_s3_bucket_logging` on the PII bucket and `aws_flow_log` on the VPC.

4. **Replace fabricated evidence with real or clearly labelled values** (NIST-05) · `index.html` · S
   - Remove the random CVE, EPSS, CVSS, hash and file-size generation at `1286-1298` and `1359-1361`.
   - Derive the stream entirely from the user's inputs (L, I, score, tier, rule applied).
   - If you keep a demo mode, label every synthetic line `SIMULATED` in the UI and the log.
   - Remove or rephrase the badges at `775-777` ("NIST SP 800-30 aligned", no encryption claims) and the "chain of custody" sentence at `949`.
   - Compute a real `SHA-256` over the assessment record with `crypto.subtle.digest` if a hash is shown.

5. **Make data and state recoverable** (NIST-06) · `s3.tf`, `providers.tf`, `main.tf` · M
   - Add `aws_s3_bucket_versioning` (Enabled) plus MFA-delete on the PII bucket, cross-region replication to a KMS-encrypted replica, and an AWS Backup plan.
   - Add a `backend "s3"` block with `encrypt = true`, `use_lockfile = true` and a KMS key.
   - Move compute to an Auto Scaling Group across at least two AZs behind the ALB from step 2.

6. **Rebuild `scan.py` into a pipeline-grade control** (NIST-07) · `scan.py` · M
   - Resolve paths relative to the script or an argument (`pathlib.Path(__file__).parent`), and glob `**/*.tf` instead of a hardcoded list.
   - Fail closed: exit with status 2 if no files are found, and exit 1 if any HIGH or CRITICAL finding exists.
   - Skip comment lines (`#`, `//`, `/* */`) and match with whitespace-tolerant regexes such as `block_public_acls\s*=\s*false`, `"(?:[a-z0-9-]+:)?\*"` inside `Action`, and `0\.0\.0\.0/0|::/0` **inside `ingress` blocks only**.
   - Add absence checks (missing `metadata_options`, encryption config, versioning, CloudTrail, `aws:SecureTransport` deny).
   - Emit SARIF so findings appear in GitHub code scanning. Long term, run Checkov or Trivy alongside it and keep `scan.py` for project-specific policy.

7. **Wire detection to response** (NIST-08) · new `detect.tf` · M
   - Enable `aws_guardduty_detector` with S3 protection and Malware Protection for S3, and `aws_securityhub_account` with the NIST SP 800-53 Rev.5 standard subscription.
   - Add CloudWatch metric filters for root login, IAM policy changes, SG changes and S3 policy changes. Each gets an alarm routed to an SNS topic with KMS encryption.

### Phase 1: Near term (≤ 30 days): Moderate findings

8. **Harden the instance** (NIST-09, NIST-20, NIST-11, NIST-24) · `main.tf` · S
   ```hcl
   data "aws_ami" "hardened" {
     most_recent = true
     owners      = ["amazon"]            # or your golden-image account
     filter { name = "name" values = ["al2023-ami-*-x86_64"] }
   }
   resource "aws_instance" "app_server" {
     ami                    = data.aws_ami.hardened.id
     instance_type          = "t3.micro"
     metadata_options { http_tokens = "required" http_put_response_hop_limit = 1 http_endpoint = "enabled" }
     root_block_device { encrypted = true }
     iam_instance_profile   = aws_iam_instance_profile.ssm_core.name   # SSM, no SSH
     monitoring             = true
     # ...
   }
   ```
   Delete the port-22 ingress entirely and use SSM Session Manager, which writes session logs to the audit bucket. Add `aws_ebs_encryption_by_default`.

9. **Make egress deny-by-default** (NIST-10) · `main.tf` · S. Restrict egress to 443 toward VPC endpoints (S3 gateway endpoint, SSM interface endpoints) and the specific patch repos. Add a NAT gateway with Network Firewall domain allow-listing if broader egress is needed.

10. **Define the boundary architecture** (NIST-16) · `main.tf` + `docs/architecture.md` · L
    - Explicit IGW and route tables.
    - Public subnets (ALB only) and private subnets (app) across two AZs.
    - S3 gateway endpoint with an `aws:SourceVpce` condition in the bucket policy.
    - WAFv2 on the ALB with AWS Managed Rules Core and KnownBadInputs.
    - Write the result up as the system boundary in an SSP-style document (PL-2).

11. **Encrypt and isolate PII/PHI** (NIST-19, NIST-14) · `s3.tf` · M. Add an `aws_kms_key` with rotation and a key policy that separates key admins from key users, plus `aws_s3_bucket_server_side_encryption_configuration` (`aws:kms`, `bucket_key_enabled = true`). Deny `PutObject` without `s3:x-amz-server-side-encryption = aws:kms`. Split PHI into its own bucket or KMS key. Add lifecycle rules for transient prefixes and enable Macie discovery.

12. **Manage the principal in code** (NIST-22) · `s3.tf`, `iam.tf` · S. Define `aws_iam_role.fintech_core_app` in Terraform and reference `aws_iam_role.fintech_core_app.arn`. Use `data.aws_caller_identity.current.account_id` instead of a literal account ID.

13. **Clean up provider configuration** (NIST-15, NIST-12) · `providers.tf` · S
    - Remove the literal keys and let LocalStack pick them up from environment variables (`AWS_ACCESS_KEY_ID=test`) or a `localstack` profile.
    - Gate the `skip_*` flags and endpoints behind a `var.use_localstack` toggle.
    - Add `default_tags { tags = { Owner, DataClass, ManagedBy = "terraform" } }`.
    - Commit `.terraform.lock.hcl` with `terraform providers lock -platform=linux_amd64 -platform=darwin_arm64`.
    - Evaluate moving to the `~> 6.0` provider.

14. **Add a CI security gate** (NIST-12, NIST-07) · `.github/workflows/security.yml` · M. Run `terraform fmt -check`, `terraform validate`, `scan.py` (fail-closed), Checkov/Trivy (SARIF upload) and gitleaks on every PR. Add Dependabot for the `terraform` and `github-actions` ecosystems, plus `SECURITY.md`.

15. **Fix scoring integrity and methodology traceability** (NIST-17) · `index.html` · S. Drive both `tierFor()` and `cellTone()` from one `TIERS` constant so labels and colours cannot drift. Document the mapping from the 1-25 product to the five qualitative levels in NIST SP 800-30 Appendix I (Very Low → Very High), and cite it in the UI instead of claiming "compliance".

16. **Persist and export assessments** (NIST-18) · `index.html` · M. Save each assessment as a record (`{id, timestamp, assessor, L, I, score, tier, rationale, sha256}`). For a static page, offer JSON/CSV export and optional `localStorage` as a convenience cache, not the system of record. Make Reset confirm before discarding.

17. **Add a browser security policy** (NIST-21, NIST-23) · `index.html` · S
    - Self-host the two font families (WOFF2 in `/fonts`, `font-display: swap`) to eliminate the third-party call.
    - Move the script to `app.js` and replace `onclick=` attributes with `addEventListener`.
    - Then add:
    ```html
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self';
                   img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'">
    <meta name="referrer" content="no-referrer">
    ```
    Note that `frame-ancestors` is ignored in `<meta>`; set it as a header if the host allows it.

### Phase 2: Hardening (≤ 90 days): Low findings and assurance

18. **Remove the DOM sink pattern** (NIST-25) · `index.html` · S. Build nodes with `document.createElement` + `textContent`, or use `<template>` cloning. Change `appendLog(tag, tone, text)` to set `textContent` on each span. Add a Trusted Types policy (`require-trusted-types-for 'script'`) to the CSP to keep the guarantee.

19. **Respect motion and visibility preferences** (NIST-26) · `index.html` · S. Gate the canvas and radar `requestAnimationFrame` loops on `matchMedia('(prefers-reduced-motion: reduce)')` and `document.visibilityState`. Replace the O(n²) pass with a spatial grid, or cap at about 40 particles.

20. **Close the RMF loop.** Write an SSP (system description, boundary diagram from §1.2, control implementation statements per §2) and a POA&M that tracks NIST-01 to NIST-26 with owners and dates. Map `scan.py` and Checkov rule IDs to 800-53 control IDs so CA-7 continuous monitoring produces evidence automatically. Update `README.md`, which still cites **CSF v1.1** and should reference **CSF 2.0** (adding the GOVERN function).

### Interface & documentation presentation guidance

These recommendations apply to future UI work on the dashboard and to any rendered version of this report. They use a clean 3D kinetic style built on physical depth, spatial layout and spring motion. They **exclude** AI-generated or AI-driven gradients, LLM-driven visual skins and automated AI code generators. Colour stays as flat, solid design tokens; depth comes from geometry, light and motion.

- **Spatial risk matrix.** Render the 5×5 grid on a plane with `perspective: 1200px` and a slight `rotateX(18deg)`. Each cell lifts on its own layer with `translateZ(score * 1.2px)`, so severity reads as physical height. Animate only `transform` and `opacity` to keep work on the compositor (GPU), and set `will-change: transform` only during interaction.
- **Spring physics, not easing curves.** Selection, hover and focus use critically damped springs (motion.dev `animate(el, {...}, { type: "spring", stiffness: 380, damping: 32, mass: 0.9 })`). Springs are interruptible and preserve velocity when the user re-targets mid-motion.
- **Layout morphing for the register.** Expanding a register row uses FLIP / `layout` animations so the row morphs into a detail card in place. The matrix cell and its register row share an element ID, so selecting one morphs the other (a shared-layout transition) instead of cutting.
- **Depth hierarchy that mirrors the trust map.** Use the same Z-plane order as §1.2: public flows nearest the viewer, the data plane deepest. Shift the layers on scroll and pointer with parallax at no more than 6px per plane to orient without causing motion sickness.
- **Independent transforms.** Drive `x`, `y`, `scale` and `rotate` as separate motion values (motion.dev independent transforms) so hover-lift and selection-tilt compose without overwriting each other.
- **Motion safety.** Under `prefers-reduced-motion`, replace springs with 0 ms opacity cross-fades and drop parallax and Z-lift entirely. Pause all loops when `document.hidden`. Make every animated state reachable and legible without motion: keyboard focus rings and text tier labels, not colour alone.
- **Supply-chain discipline for the motion library (SA-9/SR-11).** Self-host a pinned build of `motion`, served under the `script-src 'self'` CSP from step 17, with its hash recorded in the repo. Do not load it from a live CDN at runtime.

---

## Appendix A: Verification performed

All commands were read-only and none modified repository files.

```text
$ cd <repo> && python3 -I scan.py ; echo "exit=$?"
=== STARTING SIMULATED COMPLIANCE AUDIT ===
Scanning s3.tf...
 [!] HIGH: Wildcard administrative permissions granted (F-02) on line 21: # Secure Bucket Policy: ... instead of "*"   ← comment, false positive
Scanning iam.tf...
 [!] HIGH: Wildcard administrative permissions granted (F-02) on line 35: Resource = "*"
Scanning main.tf...
 [!] CRITICAL: Port exposed to the public internet (F-05) on line 35: cidr_blocks = ["0.0.0.0/0"] ...
 [!] CRITICAL: Port exposed to the public internet (F-05) on line 43: cidr_blocks = ["0.0.0.0/0"]   ← egress, mislabelled "Port exposed"
=== SCAN COMPLETE ===
exit=0                                                   ← CRITICAL findings, success exit code

$ cd /tmp && python3 -I <repo>/scan.py
=== STARTING SIMULATED COMPLIANCE AUDIT ===
=== SCAN COMPLETE ===                                    ← zero files scanned, silent pass
```

- **Git history secret sweep:** `git log -p --all | grep -iE 'AKIA|secret_key|password'` returns only the mock `secret_key = "mock_secret_key"` and the `.gitignore` comment. No live credentials were found.
- **Baseline provenance:** the "vulnerable baseline" described in `README.md:21-25` (public S3, `Action: "*"`, SSH from `0.0.0.0/0`) **does not appear in git history**. Commit `4d21626` already adds the remediated files. The before/after remediation claim therefore cannot be shown from this repository's history, so evidence for CA-2 / CA-5 (POA&M) is missing.
- **Archive integrity:** `diff -r` between the uploaded archive and commit `5b1e5e4` shows no differences.

## Appendix B: Control ↔ finding cross-reference

| Finding | 800-53 Rev.5 | CSF 2.0 | Score | Level |
|---|---|---|---|---|
| NIST-01 | AC-3, AC-6, AC-6(9) | PR.AA-05 | 16 | High |
| NIST-02 | SC-8, SC-8(1), SC-13 | PR.DS-02 | 16 | High |
| NIST-03 | AU-2, AU-9(2), AU-12 | DE.CM-03 | 16 | High |
| NIST-04 | IA-2(1), IA-5(1), AC-2(3) | PR.AA-03 | 15 | High |
| NIST-05 | SI-7, AU-10, PT-5, PL-4 | GV.OC-03, ID.RA-01 | 15 | High |
| NIST-06 | CP-6, CP-9, CP-10, SC-36 | PR.DS-11, RC.RP-01 | 12 | High |
| NIST-07 | CA-2, CA-7, RA-5 | ID.IM-02, DE.CM-09 | 12 | High |
| NIST-08 | IR-4, IR-5, IR-6, SI-4 | DE.AE-02, RS.MA-01 | 12 | High |
| NIST-09 | SC-7, CM-7, AC-3 | PR.PS-01 | 9 | Moderate |
| NIST-10 | SC-7(5), SC-7(11) | PR.IR-01 | 9 | Moderate |
| NIST-11 | CM-2, SI-2, SR-4 | ID.RA-01, PR.PS-02 | 9 | Moderate |
| NIST-12 | SA-11, SR-3, CA-7, CM-14 | GV.SC-07 | 9 | Moderate |
| NIST-13 | AC-5, AC-6, PS-5 | PR.AA-05 | 9 | Moderate |
| NIST-14 | MP-6, SI-3, SI-12 | PR.DS-01 | 9 | Moderate |
| NIST-16 | PL-8, SA-8, SC-7 | PR.IR-01 | 9 | Moderate |
| NIST-15 | IA-5(7), CM-6 | PR.PS-01 | 8 | Moderate |
| NIST-17 | RA-3, SI-7 | ID.RA-05 | 8 | Moderate |
| NIST-18 | AU-3, CP-9, RA-3(1) | ID.RA-06 | 8 | Moderate |
| NIST-19 | SC-12, SC-28(1), PT-2 | PR.DS-01 | 8 | Moderate |
| NIST-20 | SC-28 | PR.DS-01 | 6 | Moderate |
| NIST-21 | SC-18, SI-10 | PR.PS-01 | 6 | Moderate |
| NIST-22 | CM-2, CM-3, AC-3 | PR.PS-01 | 6 | Moderate |
| NIST-23 | SA-9, SR-11, PT-5 | GV.SC-05 | 6 | Moderate |
| NIST-24 | AC-17, AC-17(3) | PR.AA-05 | 6 | Moderate |
| NIST-25 | SI-10 | PR.PS-06 | 4 | Low |
| NIST-26 | SC-6 | PR.IR-04 | 5 | Low |
