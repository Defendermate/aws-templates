# Defendermate cross-account IAM role

Templates for the **IAM Role** auth method (cross-account `sts:AssumeRole`).
Sibling of [`../connector/`](../connector/), which is the IAM-user (static credentials) flow.

Three flavors:

- **CloudFormation** — [`cloudformation/defendermate-role.yaml`](cloudformation/defendermate-role.yaml). One-click via the wizard's "Launch CloudFormation Quick-Create" button (recommended), or upload directly via the AWS console (in which case `ExternalId` and `DefendermateAccountId` must be entered manually).
- **Terraform** — [`terraform/main.tf`](terraform/main.tf). Required inputs: `external_id` and `defendermate_account_id`, both from the wizard. Pass via `-var` or a `.tfvars` file.
- **Pulumi** — [`pulumi/index.ts`](pulumi/index.ts). Edit the `externalId` and `defenderMateAccountId` constants at the top of the file before running `pulumi up`.

### Per-environment Defendermate Account IDs

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

All three templates are **self-contained** — each file inlines the full
permission set so customers can download a single file and run it without
fetching anything else. The canonical permission list also lives in
[`../connector/readOnlyPolicy.json`](../connector/readOnlyPolicy.json) and
[`../connector/reachabilityPolicy.json`](../connector/reachabilityPolicy.json)
(used by the IAM-user flow) — keep all five copies in sync when updating
permissions. A `make verify-templates` check (TODO) should diff them at CI
time.

The templates are mirrored to [`Defendermate/aws-templates`](https://github.com/Defendermate/aws-templates)
on merge to main (see [`.github/workflows/mirror-aws-templates.yml`](../../../.github/workflows/mirror-aws-templates.yml))
so the dm-lens wizard's CloudFormation Quick-Create button and Terraform/Pulumi
download links can reference them at publicly-resolvable HTTPS URLs (required
by AWS — Quick-Create fetches `templateURL` from AWS's backend, not the
customer's browser).

> These are **illustrative samples**, not deployable modules. Adapt them to
> your organization's IAM naming policy, tagging conventions, and module layout
> before applying in production.
