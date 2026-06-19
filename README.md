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
A lightweight static analysis engine (`scan.py`) parses the infrastructure definition code before deployment. The script automatically catches pattern violations, generating actionable audit alerts to guarantee zero-trust compliance standards.

### Phase 3: Technical Remediation & Mitigation
The infrastructure was systematically refactored to implement defensive, production-grade controls:
* **Storage Protection:** Enabled explicit AWS Public Access Blocks and restricted object actions to validated internal application roles.
* **Privilege Reduction:** Stripped all administrative wildcards from user groups, scoping access strictly to necessary operational operations (`Describe`, `Start`, `Stop`).
* **Network Segmentation:** Enforced a zero-trust perimeter by shutting down open public management paths and locking Port 22 to a single corporate static IP address.
