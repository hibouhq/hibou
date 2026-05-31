## Infrastructure

This directory keeps infrastructure-as-code organized by provider so deployment automation stays cloud-agnostic. Each supported platform gets its own subfolder with provider-specific configuration, while shared documentation stays at the top level.

Currently supported providers:
- Hetzner Cloud in `infra/hetzner/`

To add a new provider, create a new subfolder such as `infra/aws/` or `infra/gcp/`, keep provider-specific state and variables inside that folder, and document its workflow here.

Prerequisites:
- OpenTofu or Terraform 1.5+
- A provider API token
- An SSH public key available on your workstation

Quick start:
1. Change into `infra/hetzner/`.
2. Copy `terraform.tfvars.example` to `terraform.tfvars` and fill in your values.
3. Run `make deploy`.
