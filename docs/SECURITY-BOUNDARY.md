# Security boundary — GitHub Free RC

This candidate is a **pre-flight CI gate**, not a production execution broker. It evaluates a proposed action manifest and fails closed on policy errors, unknown actions, consequential/irreversible risk classes, and non-reversible effects. It never calls the cloud provider or executes the described action.

## Threat boundaries
- Do not treat the JSON report as proof that an external effect was blocked.
- A repository writer can change workflow/policy files. Use protected branches, CODEOWNERS, rulesets, required reviews, and protected GitHub Environments for production workflows.
- This action cannot defend a provider operation that is executed outside a workflow path that invokes the gate.
- Never place API tokens, credentials, secrets, private keys, personal data, or full prompts in the request file.
- Keep the workflow permissions minimal; pin third-party actions to full commit SHAs before production use.
- This free RC hard-denies high-consequence/irreversible actions. It is not a production entitlement to execute them.

## Release status
Local deterministic unit tests cover the gate. No GitHub Marketplace review, external security assessment, or provider-side enforcement test is claimed.
