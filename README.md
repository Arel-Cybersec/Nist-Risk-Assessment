# NIST Risk Assessment & Automated Cloud Infrastructure Hardening Pipeline

[![security](https://github.com/Arel-Cybersec/Nist-Risk-Assessment/actions/workflows/security.yml/badge.svg)](https://github.com/Arel-Cybersec/Nist-Risk-Assessment/actions/workflows/security.yml)

## Project Overview
This project bridges the gap between Governance, Risk, and Compliance (GRC) frameworks and hands-on technical execution. It runs a full DevSecOps lifecycle: a **NIST Cybersecurity Framework (CSF) 2.0** risk assessment of a deliberately misconfigured AWS environment, the infrastructure-as-code (IaC) that remediates it, and automated scans in CI that prove the fixes hold.

**Report:** open [`index.html`](index.html) for the interactive risk assessment report. It covers the risk register, the inherent → residual risk matrix, before/after Terraform, control mapping and scan evidence, and exports to CSV, JSON or PDF.

## The GRC & Cloud Security Scope
Risks are scored on a **5×5 likelihood × impact matrix** using the five qualitative levels of NIST SP 800-30 Rev. 1 (Very Low → Very High). Remediations are mapped to NIST CSF 2.0 subcategories and NIST SP 800-53 Rev. 5 controls.

### Technical Skills Demonstrated
* **Governance, Risk, and Compliance (GRC):** Risk identification, scoring, treatment and tracking aligned to NIST CSF 2.0 (`ID.RA-01`, `ID.RA-05`, `ID.RA-06`) with a stated risk tolerance (`GV.RM-02`).
* **Infrastructure as Code (IaC):** AWS data, identity, network, compute and logging layers in Terraform.
* **Policy as Code:** A dependency-free Python scanner (`scan.py`) for the register's findings, with unit tests, alongside [Checkov](https://github.com/bridgecrewio/checkov).
* **Defensive Hardening:** Least privilege, encryption with customer-managed keys, zero exposed management ports and centralised audit logging.
* **CI/CD security gates:** GitHub Actions blocks any change that reintroduces a finding.

---

## Risk register

| ID | Finding | Layer | Inherent | Residual | CSF 2.0 |
|----|---------|-------|----------|----------|---------|
| F-01 | Customer PII bucket publicly readable | Data | 25 Critical | 5 Low | PR.AA-05, PR.DS-01, PR.PS-01 |
| F-02 | Administrative wildcard granted to developers | Identity | 20 Critical | 3 Low | PR.AA-01, PR.AA-03, PR.AA-05 |
| F-03 | Sensitive data not encrypted at rest | Data | 12 High | 4 Low | PR.DS-01 |
| F-04 | No audit trail or network monitoring | Detection | 16 High | 4 Low | PR.PS-04, DE.CM-01, DE.CM-03, DE.CM-09 |
| F-05 | SSH exposed to the internet; plaintext HTTP | Network | 20 Critical | 4 Low | PR.IR-01, PR.DS-02, DE.CM-01 |
| F-06 | Instance metadata (IMDSv1) and host hardening | Compute | 12 High | 4 Low | PR.PS-01, PR.AA-05 |

Risk tolerance: residual risk must score below 6 (Low). The report records the scoring rationale, SP 800-53 controls and evidence for each finding.

## The DevSecOps Lifecycle Execution

### Phase 1: Risk Identification (the vulnerable baseline)
[`vulnerable/`](vulnerable/) preserves the original, insecure configuration so the before/after can be reproduced:
1. **Data (`s3.tf`):** Public access blocks disabled, a wildcard principal, and no encryption, versioning or logging.
2. **Identity (`iam.tf`):** `"Action": "*"`, `"Resource": "*"` granted to a developer group through a long-lived IAM user.
3. **Network & compute (`main.tf`):** SSH (22) and HTTP (80) open to `0.0.0.0/0`, IMDSv1, an unencrypted root volume, and no CloudTrail or flow logs.

### Phase 2: Automated Compliance Auditing
```sh
python3 scan.py vulnerable   # 15 findings (7 CRITICAL, 4 HIGH, 4 MEDIUM), exit 1
python3 scan.py .            # 0 findings, exit 0
python3 scan.py . --json     # machine-readable output
python3 -m unittest -v       # scanner tests
checkov -d . --framework terraform --skip-path vulnerable
```
`scan.py` reads Terraform block by block (resources, ingress rules, policy statements), so it doesn't flag `Deny` statements, public HTTPS or `Resource = "*"` on actions that can't be scoped. It also catches controls that are missing entirely, such as no CloudTrail. It exits non-zero on any HIGH or CRITICAL finding.

| Tool | Vulnerable baseline | Hardened |
|------|---------------------|----------|
| `scan.py` | 15 findings | 0 |
| Checkov 3.3.29 | 14 passed / **33 failed** | 123 passed / **0 failed** / 6 skipped* |

\* Each skip has a justification in source (`#checkov:skip=…`), e.g. cross-region replication is out of scope, and the log bucket can't log to itself.

### Phase 3: Technical Remediation & Mitigation
* **Storage protection:** All four Public Access Blocks enabled, ACLs disabled, SSE-KMS with a rotated customer-managed key, versioning and lifecycle rules, access logging, and a bucket policy limited to the application role that denies non-TLS requests.
* **Privilege reduction:** The IAM user and wildcard policy are removed. Developers assume an MFA-gated role with access to the data bucket only, and can start or stop only instances tagged `FinTech-Core-App`.
* **Network segmentation:** No management ports. Admin access uses SSM Session Manager. Inbound and outbound traffic is HTTPS only, the default security group is locked down and public IPs are not auto-assigned.
* **Instance hardening:** IMDSv2 is required (hop limit 1), the root volume is encrypted, and the instance has a least-privilege role and detailed monitoring.
* **Detection:** A multi-region CloudTrail with log file validation, KMS encryption, CloudWatch delivery and S3 object-level events, plus VPC flow logs with 365-day retention.

## Running it
The Terraform targets [LocalStack](https://github.com/localstack/localstack) on `localhost:4566`; no AWS account is needed. Credentials come from variables (`TF_VAR_localstack_access_key` / `TF_VAR_localstack_secret_key`), which LocalStack accepts with any value.
```sh
terraform init && terraform validate && terraform plan
```

## Continuous integration
[`.github/workflows/security.yml`](.github/workflows/security.yml) runs on every push and pull request:
1. `terraform fmt -check` and `terraform validate` for both the hardened and vulnerable configs
2. Scanner unit tests
3. `scan.py .` must pass, and `scan.py vulnerable` must fail (this proves the scanner still detects every finding)
4. Checkov on the hardened config

## Sources
* NIST, [The NIST Cybersecurity Framework (CSF) 2.0](https://doi.org/10.6028/NIST.CSWP.29). Subcategory text is quoted from NIST's OSCAL catalog in [usnistgov/oscal-content](https://github.com/usnistgov/oscal-content/tree/main/nist.gov/CSF/v2.0).
* NIST, [SP 800-53 Rev. 5](https://doi.org/10.6028/NIST.SP.800-53r5). Control titles are from the [official OSCAL catalog](https://github.com/usnistgov/oscal-content/tree/main/nist.gov/SP800-53/rev5).
* NIST, [SP 800-30 Rev. 1, Guide for Conducting Risk Assessments](https://doi.org/10.6028/NIST.SP.800-30r1)
* [Checkov](https://github.com/bridgecrewio/checkov). Check IDs in the report come from actual runs.
* HashiCorp, [Terraform AWS provider documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

> Educational simulation: account IDs, bucket names and the AMI are placeholders, and risk ratings reflect the assessor's judgment for this scenario.
