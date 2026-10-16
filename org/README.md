# Organization guardrails (Service Control Policies)

A separate Terraform root, applied from the **AWS Organizations management account**, that
attaches preventive guardrails to the OU holding the workload account. SCPs cap what *any*
principal in member accounts can do, including account administrators, so the detective
controls in the main stack (CloudTrail, GuardDuty, Config) cannot be switched off from
inside the account. It also delegates GuardDuty administration to a dedicated security account.

```sh
cd org
terraform init
terraform apply -var 'target_id=ou-xxxx-xxxxxxxx' -var 'security_account_id=111111111111'
```

Not applied by the default LocalStack workflow: AWS Organizations needs a real management account.
