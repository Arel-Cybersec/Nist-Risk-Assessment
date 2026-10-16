# Cybersecurity supply chain risk management (C-SCRM)

Finding **F-09**. Covers NIST CSF 2.0 GV.SC-04 (suppliers known and prioritised), GV.SC-06
(due diligence), GV.SC-07 (risks recorded, assessed and monitored) and GV.SC-10 (exit
provisions), plus PR.PS-02 (software maintained commensurate with risk).

## Supplier register

| Supplier / component | What it does here | Criticality | Controls in this repo | Exit plan |
|---|---|---|---|---|
| **AWS** (cloud platform) | Hosts all workload, key, log and detection resources | Critical | Least-privilege IAM, KMS keys under our control, CloudTrail + GuardDuty + Config, SCPs in `org/` | Terraform describes every resource; data in S3 can be exported. Re-platforming would need new IaC |
| **HashiCorp** (Terraform CLI, `hashicorp/aws` provider) | Builds and changes the infrastructure | Critical | Provider version constrained (`~> 5.0`); exact checksums for all platforms in `.terraform.lock.hcl`, enforced in CI with `-lockfile=readonly`; Terraform CLI version pinned in CI | OpenTofu reads the same configuration and lock file format |
| **GitHub** (source, Actions CI) | Stores code; runs every security gate | Critical | Branch ruleset on `main`; required status checks; workflow token is read-only by default | `git` history is portable; gates are plain commands runnable in any CI |
| **GitHub Actions publishers** (`actions/*`, `hashicorp/setup-terraform`, `aws-actions/configure-aws-credentials`) | Code that runs inside CI with repository access | High | Every action pinned to a full commit SHA, not a movable tag; Dependabot proposes reviewed updates weekly | Each step can be replaced by a shell command |
| **Open Policy Agent / conftest** | OPA policy gate (`policy/`) | High | Version pinned; release archive verified against the published SHA-256 checksum before use | Policies are standard Rego; OPA CLI can run them directly |
| **Checkov** (Palo Alto Networks, via PyPI) | Static IaC analysis | Medium | Exact version pinned (`checkov==3.3.29`) | Overlaps with `scan.py` and the OPA policies, so the gate survives without it |
| **LocalStack** | Local AWS emulator for development | Low | Development only; never receives real data or credentials | Switch `use_localstack = false` and use a sandbox AWS account |
| **Google Fonts** | Web fonts for the report page | Low | Loaded over HTTPS; no credentials or user data involved | Page falls back to system fonts |

## Review

- **Weekly:** Dependabot pull requests are reviewed like any other change and must pass every security check before merge.
- **Per release of a critical supplier:** read the changelog for security-relevant changes before accepting the update.
- **Twice a year:** re-check this register (new suppliers, changed criticality, retired components).
