# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a security problem.

Include what you found, where (file and line, or a URL), how to reproduce it, and the impact you expect. You will get an acknowledgement within 5 business days and a status update at least every 14 days until the report is closed.

## Scope

- Terraform in this repository (`*.tf`)
- The policy scanner (`scan.py`) and its tests
- The risk assessment dashboard (`index.html` and its assets)

The infrastructure is a simulation that targets LocalStack by default. Findings that only apply to a real AWS deployment are still in scope.

## How changes are checked

Every pull request runs the `security` workflow: `terraform fmt` and `validate` against the committed lock file, the `scan.py` NIST SP 800-53 policy gate, Checkov, and a gitleaks scan of the full history. The full control assessment and remediation status are in [`nist-assessment/report.md`](nist-assessment/report.md).
