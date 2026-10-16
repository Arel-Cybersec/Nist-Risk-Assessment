# Incident response playbook

Finding **F-10**. Covers NIST CSF 2.0 Respond (RS.MA, RS.AN, RS.CO, RS.MI) and Recover (RC.RP)
outcomes for this environment. Each playbook starts from an alert that the Terraform in this
repository actually produces.

## Roles

| Role | Responsibility |
|---|---|
| **Incident lead** (Security Operations) | Declares the incident, owns the timeline, decides on containment |
| **Cloud Platform** | Executes containment and recovery in AWS |
| **Identity & Access** | Revokes sessions and credentials |
| **Comms / Legal** | Stakeholder and regulator notifications (PII/PHI is in scope) |

## Alert sources → severity

| Alert (all go to SNS topic `fintech-security-alerts`) | Default severity |
|---|---|
| GuardDuty finding, severity ≥ 7 | **SEV-1** |
| EventBridge `fintech-security-tampering` (CloudTrail/GuardDuty/Config stopped or deleted) | **SEV-1** |
| Config rule NON_COMPLIANT on `s3-public-read-prohibited`, `s3-public-write-prohibited` or `ssh-restricted` | **SEV-1** |
| GuardDuty finding, severity 4–6.9 | SEV-2 |
| AWS Backup restore test completed with a failed status (`RESTORE_JOB_COMPLETED` notification) | SEV-2 |
| Any other Config rule NON_COMPLIANT, or an "Infrastructure drift detected" issue | SEV-3 |

SEV-1: start within 15 minutes, notify the incident lead immediately.
SEV-2: same working day. SEV-3: next working day.

## Common steps (every incident)

1. **Triage** (RS.MA-02, RS.AN-01): confirm the alert is real; record the time, alert ID and the first responder.
2. **Preserve evidence** (RS.AN-06, RS.AN-07): CloudTrail log files are integrity-protected (log file validation) and versioned in the audit bucket. Note the relevant time window before changing anything.
3. **Communicate** (RS.CO-02, RS.CO-03): open an incident channel and keep a written timeline.
4. **Close** (RC.RP-06, RS.IM-01): write a short post-incident review. Add a new or updated risk to the register, and a policy rule in `policy/` if code could have prevented it.

## Playbook A: customer data bucket made public

Trigger: `s3-public-read-prohibited` / `s3-public-write-prohibited` NON_COMPLIANT, or a GuardDuty `Policy:S3/...` finding.

1. **Contain** (RS.MI-01): re-apply the public access block.
   ```sh
   aws s3api put-public-access-block --bucket simulated-fintech-customer-data-2026 \
     --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   ```
2. **Analyse** (RS.AN-03): find who changed it (`PutBucketPublicAccessBlock`, `PutBucketPolicy`, `PutBucketAcl` events in CloudTrail) and which objects were read (S3 data events and server access logs in the audit bucket).
3. **Eradicate** (RS.MI-02): run `terraform plan` to see every other manual change, then `terraform apply` to restore the reviewed configuration.
4. **Notify**: if objects were read by unknown principals, treat it as a personal-data breach and involve Comms / Legal.

## Playbook B: compromised application instance

Trigger: GuardDuty findings on the instance (e.g. `Backdoor:EC2/...`, `CryptoCurrency:EC2/...`, `UnauthorizedAccess:EC2/...`, `InstanceCredentialExfiltration`).

1. **Contain** (RS.MI-01): move the instance into the pre-built isolation security group, which has no rules.
   ```sh
   aws ec2 modify-instance-attribute --instance-id <id> --groups <isolation-sg-id>   # terraform output: isolation_sg_id
   ```
2. **Revoke the instance role's credentials**: deny every session token issued before now.
   ```sh
   aws iam put-role-policy --role-name FinTechCoreAppRole --policy-name RevokeOlderSessions --policy-document \
     '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"<now, ISO 8601 UTC>"}}}]}'
   ```
3. **Preserve** (RS.AN-07): snapshot the root volume before anything else touches it. GuardDuty Malware Protection also scans the volume.
   ```sh
   aws ec2 create-snapshot --volume-id <vol-id> --description "IR <incident-id>"
   ```
4. **Recover** (RC.RP-02, RC.RP-05): do not clean the instance; replace it. `terraform apply -replace=aws_instance.app_server` builds a fresh instance from the reviewed configuration. Remove the `RevokeOlderSessions` policy once the new instance is healthy.

## Playbook C: someone disables audit or detection

Trigger: EventBridge `fintech-security-tampering`. Treat as SEV-1. Disabling logging is a common step before a larger attack.

1. **Contain**: turn the tooling back on.
   ```sh
   aws cloudtrail start-logging --name fintech-audit-trail
   aws configservice start-configuration-recorder --configuration-recorder-name fintech-recorder
   ```
   GuardDuty: `terraform apply` recreates or re-enables the detector.
2. **Analyse**: the event identifies the principal (`userIdentity`). Revoke that principal's sessions as in Playbook B, step 2.
3. **Prevent recurrence**: confirm the SCP in `org/` (`ProtectDetectiveControls`) is attached to the account. With it attached, only the break-glass role can make these calls.

## Playbook D: infrastructure drift

Trigger: the daily `drift` workflow opens "Infrastructure drift detected", or a Config rule turns NON_COMPLIANT.

1. Check the listed resources against CloudTrail to see who changed them and why.
2. Either revert by running `terraform apply`, or make the change properly through a pull request (which passes every security gate).
3. If it was an emergency change, record it in the register as an accepted risk until the code catches up.

## Playbook E: data loss or failed restore test

Trigger: deleted or corrupted data, ransomware, or a weekly restore test that did not succeed.

1. **Stop the damage** (RS.MI-01): if data is being deleted or encrypted, follow Playbook B to contain the principal or instance first.
2. **Choose the restore source** (RC.RP-02): the most recent clean recovery point in `fintech-vault` (or `fintech-vault-dr` if the primary region is impaired); for S3 objects, the previous object version or the replica bucket in the DR region.
3. **Verify before use** (RC.RP-03): restore to a new volume first and check it, exactly as the weekly restore test does.
4. **Failed restore test**: treat backups as untrusted until the cause is fixed; record it in the register (F-11 residual risk rises until a test passes again).

## Recovery assets

- **S3 objects:** versioning on every bucket, plus a continuously replicated copy in the DR region (`dr.tf`).
- **Instance data:** daily AWS Backup recovery points (35 days) in a locked vault, copied to the DR region and test-restored weekly (`backup.tf`).
- **Infrastructure:** fully rebuilt from Terraform; the code itself is protected by the `main` branch ruleset.
- **Audit trail:** CloudTrail log file validation proves the logs have not been altered: `aws cloudtrail validate-logs --trail-arn <arn> --start-time <time>`.

## Exercise

Run one playbook as a tabletop exercise each quarter and record the improvements (ID.IM-02, ID.IM-04).
