# NIST Risk Assessment & Automated Cloud Infrastructure Hardening Pipeline

## Project Overview
This project bridges the gap between Governance, Risk, and Compliance (GRC) frameworks and hands-on technical execution. It simulates a comprehensive DevSecOps lifecycle—mapping vulnerabilities identified through a **NIST Cybersecurity Framework (CSF)** risk assessment to an enterprise infrastructure-as-code (IaC) deployment, programmatically auditing the posture, and engineering robust remediations.



## The GRC & Cloud Security Scope
Using a **5×5 risk matrix (Likelihood × Impact)** aligned with industry standards, this project analyzes critical architectural weaknesses in a cloud ecosystem (AWS) to prioritize remediation efforts based on business risk.

### Technical Skills Demonstrated
* **Governance, Risk, and Compliance (GRC):** Risk identification, categorization, and tracking based on NIST CSF v1.1.
* **Infrastructure as Code (IaC):** Blueprinting cloud layers natively using Terraform.
* **Static Application Security Testing (SAST):** Building a policy-as-code linting engine in Python (`scan.py`).
* **Defensive Hardening:** Applying the Principle of Least Privilege (PoLP) and strict network boundary controls.

---

## The DevSecOps Lifecycle Execution

### Phase 1: Risk Identification (The Vulnerable Baseline)
The initial cloud posture modeled three critical architectural defects flagged during a compliance audit:
1. **Data Layer (`s3.tf`):** Public access blocks disabled and global wildcard principals allowed.
2. **Identity Layer (`iam.tf`):** Broad administrative permissions (`"Action": "*"`, `"Resource": "*"`) assigned to development groups.
3. **Network Layer (`main.tf`):** Management boundaries completely bypassed by exposing SSH (Port 22) to the global public internet (`0.0.0.0/0`).

### Phase 2: Automated Compliance Auditing
A static analysis engine (`scan.py`, Python standard library only) parses the Terraform before deployment. It reads HCL structurally, so comments and strings are not mistaken for findings, and maps each finding to a NIST SP 800-53 Rev.5 control.

```bash
python3 scan.py                    # scans the repository; exits 1 on any HIGH or CRITICAL finding
python3 scan.py --fail-on MEDIUM   # stricter gate
python3 scan.py --sarif scan.sarif # also writes SARIF for GitHub code scanning
python3 -m unittest discover -s tests
```

Exit codes: `0` pass, `1` findings at or above `--fail-on`, `2` no `.tf` files found (a scan that saw nothing never passes).

### Phase 3: Technical Remediation & Mitigation
The infrastructure was systematically refactored to implement defensive, production-grade controls:
* **Storage Protection:** Enabled explicit AWS Public Access Blocks and restricted object actions to validated internal application roles.
* **Privilege Reduction:** Stripped all administrative wildcards from user groups, scoping access strictly to necessary operational operations (`Describe`, `Start`, `Stop`).
* **Network Segmentation:** Enforced a zero-trust perimeter by shutting down open public management paths and locking Port 22 to a single corporate static IP address.

### Phase 4: NIST RMF Assessment & Phase 0 Remediation
A full read-only assessment against 16 NIST SP 800-53 control families lives in [`nist-assessment/report.md`](nist-assessment/report.md). Its eight High-risk findings (Phase 0 of the roadmap) are remediated in code:

| Area | Change | Files |
|---|---|---|
| Identity | MFA required for every action except MFA setup; password policy; no direct human access to PII (MFA-gated, one-hour break-glass read role instead); Production instances excluded from developer start/stop | `iam.tf` |
| Transport | HTTPS-only Application Load Balancer (TLS 1.2+, HTTP redirects to HTTPS); instances reachable only from the load balancer; S3 bucket policies deny non-TLS and pre-TLS 1.2 requests | `alb.tf`, `main.tf`, `s3.tf` |
| Audit | Multi-region CloudTrail with log file validation and PII data events; VPC Flow Logs; S3 server access logs; KMS-encrypted audit bucket under Object Lock | `logging.tf`, `main.tf`, `s3.tf` |
| Recovery | Versioning and cross-region replication of the PII bucket; daily AWS Backup into a locked vault; Auto Scaling group across two AZs; remote encrypted Terraform state with locking | `s3.tf`, `backup.tf`, `main.tf`, `backend.tf` |
| Detection | GuardDuty with S3 protection, Security Hub NIST 800-53 standard, CloudTrail metric alarms and high-severity GuardDuty findings routed to an encrypted SNS topic | `detect.tf` |
| Assessment integrity | Dashboard no longer shows random CVE/CVSS/EPSS values or a fake audit hash; every evidence line is derived from the inputs and the record carries a real SHA-256 digest | `index.html` |
| Scanner | `scan.py` rebuilt as a pipeline gate (see Phase 2) | `scan.py`, `tests/` |

## Running Locally (LocalStack)

```bash
awslocal s3 mb s3://fintech-terraform-state          # one-time: bucket for remote state
terraform init -backend-config=backend.localstack.hcl
terraform plan
```

Use `terraform init -backend=false` for validation-only runs. Some services used by the Phase 0 controls (for example GuardDuty, Security Hub, AWS Backup and Elastic Load Balancing) may require LocalStack Pro or a real AWS account to `apply`. The load balancer certificate is issued only after the DNS records in the `acm_validation_records` output exist.
