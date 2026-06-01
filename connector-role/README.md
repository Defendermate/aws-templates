# Defendermate cross-account IAM role

Templates for the **IAM Role** auth method (cross-account `sts:AssumeRole`).
Sibling of [`../connector/`](../connector/), which is the IAM-user (static credentials) flow.

Three flavors:

- **CloudFormation** — [`cloudformation/defendermate-role.yaml`](cloudformation/defendermate-role.yaml). Download the YAML and run `aws cloudformation create-stack` with the External ID and Defendermate Account ID as parameters. The wizard's CloudFormation Details panel shows the full command pre-substituted with your values.
- **Terraform** — [`terraform/main.tf`](terraform/main.tf). Required inputs: `external_id` and `defendermate_account_id`, both from the wizard. Pass via `-var` or a `.tfvars` file.
- **Pulumi** — [`pulumi/index.ts`](pulumi/index.ts). Edit the `externalId` and `defenderMateAccountId` constants at the top of the file before running `pulumi up`.

## Trust policy shape (v1)

All three templates produce the same trust policy:

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<DM_ACCOUNT_ID>:root" },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": { "sts:ExternalId": "<external-id>" }
  }
}
```

The per-connection `ExternalId` is the primary confused-deputy guard. We
deliberately omit an additional `aws:PrincipalArn` condition (which would
restrict *which* IAM principal inside the Defendermate account may
AssumeRole) for v1. It would require customers to know Defendermate's
internal IAM topology, which differs between on-prem static-keys
(`user/dm-core-*`) and SaaS workload-identity (`role/dm-core-*`)
deployments — no single pattern works for both.

In v2, dm-core gets a stable service-role identity (`dm-core-platform`)
that all bootstrap auth methods hop into first. Once that lands, the
trust policy re-adds:

```json
"ArnLike": {
  "aws:PrincipalArn": "arn:aws:iam::<DM_ACCOUNT_ID>:role/dm-core-platform"
}
```

…as defense-in-depth. Tracked separately.

## Per-environment Defendermate Account IDs

The wizard displays the correct account ID for the tenant you're connecting,
but for reference:

| Environment | Defendermate AWS account |
|---|---|
| dev (`dmate-dev`) | `304321522536` |
| staging (`dmate-staging`) | `063688338769` |
| prod (`dmate-prod`) | `092671054851` |

There is intentionally no default value baked into the templates — a
prod-tenant customer who downloaded a dev-defaulted template and ran it
unchanged would create a role that prod dm-core couldn't assume. Failure
modes are noisy ("missing variable" or wizard-side trust-policy mismatch)
rather than silently-wrong.

## Hosting

All three templates are **self-contained** — each file inlines the full
permission set so customers can download a single file and run it without
fetching anything else. The canonical permission list also lives in
[`../connector/readOnlyPolicy.json`](../connector/readOnlyPolicy.json) and
[`../connector/reachabilityPolicy.json`](../connector/reachabilityPolicy.json)
(used by the IAM-user flow) — keep all five copies in sync when updating
permissions. A `make verify-templates` check (TODO) should diff them at CI
time.

The templates are mirrored to [`Defendermate/aws-templates`](https://github.com/Defendermate/aws-templates)
on merge to main (see [`.github/workflows/mirror-aws-templates.yml`](../../../.github/workflows/mirror-aws-templates.yml)).
The dm-lens wizard fetches these via a same-origin Next.js API route
(`dm-lens/app/api/templates/aws/iam-role/[file]/route.ts`) that proxies
the GitHub raw URL — the proxy is needed because the wizard's CSP
`connect-src` doesn't include `raw.githubusercontent.com`, and because
the `<a download>` attribute is ignored for cross-origin targets.

> These are **illustrative samples**, not deployable modules. Adapt them
> to your organization's IAM naming policy, tagging conventions, and
> module layout before applying in production.
