# APC for GitHub — Free Release Candidate 1.0.0

APC (Aleph Policy Continuity) helps teams put a deterministic pre-flight gate in AI-agent workflows before proposed tool actions proceed. This free candidate is intentionally narrow: **read-only/reversible preflight checks are supported; consequential or irreversible actions are always denied**.

## Quick start

1. Copy `.apc/policy.json` (the example is `policies/policy.json`) and an action request JSON into your repository.
2. Add a workflow step using `uses: ./` after checkout, as shown in `.github/workflows/apc-preflight-example.yml`.
3. Inspect the `apc-decision-report.json` artifact. A denial fails the job (fail-closed).
4. Protect the workflow and policy with repository rulesets/CODEOWNERS and require reviews for production environment deployments.

## Supported request schema

```json
{
  "action_id": "agent-plan-001",
  "operation": "terraform.plan",
  "target": "sandbox-cluster",
  "risk_class": "read_only",
  "reversible": true,
  "environment": "development",
  "agent_id": "example-agent"
}
```

`risk_class` values `consequential`, `irreversible`, `critical`, `financial`, and `privileged`, or `reversible: false`, are hard-denied regardless of policy rules. Unknown actions default to deny.

## Product limits

- Pre-flight only; no provider adapter and no production-side effect interception.
- No OIDC/Okta integration, enterprise multi-tenant control plane, commercial entitlement, credential vault, or live effect finality.
- Do not use this free RC as the only control protecting a live payment, production deployment, data deletion, privilege change, or other irreversible effect.

## License and IP

This is a free evaluation candidate under the included APC Free Evaluation License. APC remains proprietary; no right to repackage or resell the product is granted. The private APC master specification, internal threat material, customer data, and production credentials are not included.

## Validation

Run `node --test tests/evaluate.test.js`. The included workflow is an example, not a Marketplace submission or a claim of vendor approval. Read `docs/SECURITY-BOUNDARY.md` and `RELEASE-STATUS.md` before use.
