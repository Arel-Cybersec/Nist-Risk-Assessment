# NIST Risk Assessment & Automated Cloud Infrastructure Hardening Pipeline

[![security](https://github.com/Arel-Cybersec/Nist-Risk-Assessment/actions/workflows/security.yml/badge.svg)](https://github.com/Arel-Cybersec/Nist-Risk-Assessment/actions/workflows/security.yml)

## Project Overview
This project bridges the gap between Governance, Risk, and Compliance (GRC) frameworks and hands-on technical execution. It runs a full DevSecOps lifecycle: a **NIST Cybersecurity Framework (CSF) 2.0** risk assessment of a deliberately misconfigured AWS environment, the infrastructure-as-code (IaC) that remediates it, automated gates in CI that block unsafe changes, runtime monitoring for the live account, and the governance artefacts (supply chain, incident response) that CSF 2.0 expects alongside the technical controls.

**Report:** open [`index.html`](index.html) for the interactive risk assessment report. It covers the risk register, the inherent → residual risk matrix, before/after Terraform, control mapping and scan evidence, and exports to CSV, JSON or PDF.

## The GRC & Cloud Security Scope
Risks are scored on a **5×5 likelihood × impact matrix** using the five qualitative levels of NIST SP 800-30 Rev. 1 (Very Low → Very High). Remediations are mapped to NIST CSF 2.0 subcategories and NIST SP 800-53 Rev. 5 controls.

### Technical Skills Demonstrated
* **Governance, Risk, and Compliance (GRC):** Risk identification, scoring, treatment and tracking aligned to NIST CSF 2.0 (`ID.RA-01`, `ID.RA-05`, `ID.RA-06`) with a stated risk tolerance (`GV.RM-02`).
* **Infrastructure as Code (IaC):** AWS data, identity, network, compute and logging layers in Terraform.
* **Policy as Code:** OPA/Rego policies run by [conftest](https://github.com/open-policy-agent/conftest), a dependency-free Python scanner (`scan.py`) and [Checkov](https://github.com/bridgecrewio/checkov), each with tests.
* **Runtime monitoring:** GuardDuty, 28 AWS Config managed rules, EventBridge alerts, a daily drift check and weekly automated backup restore tests.
* **Organization guardrails:** Service Control Policies and a permissions boundary that cap what any principal can do.
* **Supply chain and response:** pinned and checksum-verified dependencies, Dependabot, a supplier register, an incident response playbook.
* **Defensive Hardening:** Least privilege, encryption with customer-managed keys, zero exposed management ports and centralised audit logging.
* **CI/CD security gates:** three independent gates fail the build on any change that reintroduces a finding.

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
| F-07 | No runtime threat detection or drift monitoring | Detection | 16 High | 4 Low | DE.CM-09, DE.AE-02, DE.AE-06, PR.PS-01 |
| F-08 | No preventive guardrails or enforced policy gate | Governance | 15 High | 4 Low | PR.AA-05, GV.PO-01, PR.PS-06 |
| F-09 | Unmanaged software supply chain | Governance | 12 High | 3 Low | GV.SC-04, GV.SC-07, GV.SC-10, PR.PS-02 |
| F-10 | No incident response plan | Response | 12 High | **6 Moderate (open)** | RS.MA-02, RS.MI-01, RS.AN-07, RC.RP-03, ID.IM-04 |
| F-11 | Backups never test-restored | Resilience | 12 High | 3 Very Low | PR.DS-11, RC.RP-03, RC.RP-05 |
| F-12 | Single-region deployment | Resilience | 8 Moderate | 4 Low | PR.IR-03, RC.RP-02, ID.AM-08 |
| F-13 | TLS certificate and edge not managed | Network | 12 High | 3 Very Low | PR.DS-02, PR.IR-01, PR.PS-01 |

Levels follow the five NIST SP 800-30 qualitative values on a tailored 5×5 score: Very Low 1–3, Low 4–5, Moderate 6–11, High 12–19, Very High 20–25. Risk tolerance: residual risk must be Low or Very Low (score below 6). **F-10 is still above tolerance**: the playbook exists but has not been exercised, so it stays open until a tabletop exercise has tested it. The report records the scoring rationale, SP 800-53 controls and evidence for each finding.

## The DevSecOps Lifecycle Execution

### Phase 1: Risk Identification (the vulnerable baseline)
[`vulnerable/`](vulnerable/) preserves the original, insecure configuration so the before/after can be reproduced:
1. **Data (`s3.tf`):** Public access blocks disabled, a wildcard principal, and no encryption, versioning or logging.
2. **Identity (`iam.tf`):** `"Action": "*"`, `"Resource": "*"` granted to a developer group through a long-lived IAM user.
3. **Network & compute (`main.tf`):** SSH (22) and HTTP (80) open to `0.0.0.0/0`, IMDSv1, an unencrypted root volume, and no CloudTrail or flow logs.
4. **Operations:** no runtime detection (GuardDuty, Config), no provider lock file and no incident response plan.

### Phase 2: Automated Compliance Auditing
```sh
python3 scan.py vulnerable   # 21 findings (7 CRITICAL, 7 HIGH, 7 MEDIUM), exit 1
python3 scan.py .            # 0 findings, exit 0
python3 scan.py . --json     # machine-readable output
python3 -m unittest -v       # scanner tests

conftest verify -p policy                               # 14 Rego unit tests
conftest test --parser hcl2 --combine *.tf              # OPA gate: 22 rules, 0 failures
(cd vulnerable && conftest test --parser hcl2 --combine -p ../policy *.tf)   # 16 failures, exit 1

checkov -d . --framework terraform --skip-path vulnerable
```
`scan.py` reads Terraform block by block (resources, ingress rules, policy statements), so it doesn't flag `Deny` statements, public HTTPS or `Resource = "*"` on actions that can't be scoped. It also catches controls that are missing entirely, such as no CloudTrail. It exits non-zero on any HIGH or CRITICAL finding.

| Tool | Vulnerable baseline | Hardened |
|------|---------------------|----------|
| `scan.py` | 21 findings | 0 |
| OPA / conftest 0.56.0 | **16 failures**, 3 warnings | 22 passed / **0 failures** |
| Checkov 3.3.29 | 14 passed / **33 failed** | 256 passed / **0 failed** / 10 skipped* |

\* Each skip has a justification in source (`#checkov:skip=…`), e.g. cross-region replication is out of scope, and the log bucket can't log to itself. Checkov only checks resources that exist, so it cannot see a control that is missing entirely (no GuardDuty, no lock file); `scan.py` and the OPA policies cover those.

### Phase 3: Technical Remediation & Mitigation
* **Storage protection:** All four Public Access Blocks enabled, ACLs disabled, SSE-KMS with a rotated customer-managed key, versioning and lifecycle rules, access logging, and a bucket policy limited to the application role that denies non-TLS requests.
* **Privilege reduction:** The IAM user and wildcard policy are removed. Developers assume an MFA-gated role with access to the data bucket only, and can start or stop only instances tagged `FinTech-Core-App`.
* **Network segmentation:** No management ports. Admin access uses SSM Session Manager. Inbound and outbound traffic is HTTPS only, the default security group is locked down and public IPs are not auto-assigned.
* **Instance hardening:** IMDSv2 is required (hop limit 1), the root volume is encrypted, and the instance has a least-privilege role and detailed monitoring.
* **Detection:** A multi-region CloudTrail with log file validation, KMS encryption, CloudWatch delivery and S3 object-level events, plus VPC flow logs with 365-day retention.
* **Runtime monitoring and drift (`detect.tf`, `.github/workflows/drift.yml`):** GuardDuty with S3 and EBS malware protection; an AWS Config recorder with 28 managed rules that mirror this register (identifiers taken from AWS's [NIST conformance packs](https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs)); EventBridge alerts for GuardDuty findings, Config non-compliance and attempts to disable CloudTrail, GuardDuty or Config; and a daily `terraform plan` against the live account that opens an issue on drift.
* **Preventive guardrails (`org/`, `policy/`):** SCPs that stop anyone in member accounts from disabling security tooling, using the root user, leaving the organization or using unapproved regions; org-wide GuardDuty delegated to a security account; a permissions boundary on the developer role; and an OPA policy gate in CI.
* **Supply chain (`governance/supply-chain.md`):** provider checksums for every platform in `.terraform.lock.hcl` (enforced with `-lockfile=readonly`), every GitHub Action pinned to a commit SHA, conftest verified against its published checksum, Dependabot, and a supplier register with criticality and exit plans.
* **Backups proven to restore (`backup.tf`, F-11):** daily AWS Backup recovery points in a KMS-encrypted vault with a governance-mode lock, copied to the DR region, and an AWS Backup restore testing plan that restores the latest point every week and alerts on the result.
* **Second region (`dr.tf`, F-12):** S3 cross-region replication of customer data to a replica bucket with its own KMS key, plus a DR backup vault; the stack can be rebuilt from Terraform in that region.
* **Managed TLS at the edge (`edge.tf`, F-13):** an Application Load Balancer with an auto-renewing ACM certificate (DNS-validated), a TLS 1.3-only listener, no port 80 and AWS WAF managed rules (Common, Known Bad Inputs/Log4j, Anonymous IP). The instance sits in a private subnet with no public IP; SSM and S3 are reached through VPC endpoints.
* **Incident response (`governance/incident-response.md`, `SECURITY.md`):** roles, severity levels, and playbooks for each alert this environment raises, plus a pre-built isolation security group.

## Running it
By default the Terraform targets [LocalStack](https://github.com/localstack/localstack) on `localhost:4566`; no AWS account is needed. Credentials come from variables (`TF_VAR_localstack_access_key` / `TF_VAR_localstack_secret_key`), which LocalStack accepts with any value. GuardDuty, AWS Config and Organizations are not in LocalStack's free edition, so those resources only fully work against real AWS.
```sh
terraform init && terraform validate && terraform plan
```

**Real AWS (sandbox account recommended):** this creates billable resources.
```sh
terraform apply -var use_localstack=false -var alert_email=you@example.com \
  -var domain_name=app.example.com -var route53_zone_id=Z0123456789ABC
```
`domain_name` and `route53_zone_id` create the TLS certificate and HTTPS listener; without them the load balancer has no listener. The second region defaults to `us-west-2` (`dr_region`). Before `terraform destroy`, apply once with `-var deletion_protection=false`.
Then enable drift detection: create an IAM role for GitHub OIDC with `ReadOnlyAccess` and read access to your state bucket, and set the repository variables `AWS_ROLE_ARN` and `TF_STATE_BUCKET` (optionally `TF_STATE_KEY`, `AWS_REGION`). The organization guardrails are a separate stack applied from the management account; see [`org/README.md`](org/README.md).

## Continuous integration
[`.github/workflows/security.yml`](.github/workflows/security.yml) runs on every push and pull request:
1. `terraform fmt -check` and `terraform validate` for the hardened, `org` and vulnerable configs (provider checksums enforced)
2. Scanner unit tests; `scan.py .` must pass and `scan.py vulnerable` must fail
3. Rego unit tests; the OPA gate must pass on the hardened code and fail on the baseline
4. Checkov on the hardened and `org` configs

**Making the gates blocking:** in **Settings → Rules → Rulesets → (rule for `main`)**, enable **Require status checks to pass** and add the `terraform`, `scan`, `opa` and `checkov` checks. A pull request then cannot merge while any gate is red.

[`.github/workflows/drift.yml`](.github/workflows/drift.yml) runs daily once a real deployment is connected (see above).

## Sources
* NIST, [The NIST Cybersecurity Framework (CSF) 2.0](https://doi.org/10.6028/NIST.CSWP.29). Subcategory text is quoted from NIST's OSCAL catalog in [usnistgov/oscal-content](https://github.com/usnistgov/oscal-content/tree/main/nist.gov/CSF/v2.0).
* NIST, [SP 800-53 Rev. 5](https://doi.org/10.6028/NIST.SP.800-53r5). Control titles are from the [official OSCAL catalog](https://github.com/usnistgov/oscal-content/tree/main/nist.gov/SP800-53/rev5).
* NIST, [SP 800-30 Rev. 1, Guide for Conducting Risk Assessments](https://doi.org/10.6028/NIST.SP.800-30r1)
* AWS, [Operational Best Practices conformance packs for NIST CSF and NIST 800-53 Rev. 5](https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs): source of the AWS Config rule identifiers.
* [Open Policy Agent / conftest](https://github.com/open-policy-agent/conftest)
* [Checkov](https://github.com/bridgecrewio/checkov). Check IDs in the report come from actual runs.
* HashiCorp, [Terraform AWS provider documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

> Educational simulation: account IDs, bucket names and the AMI are placeholders, and risk ratings reflect the assessor's judgment for this scenario.
