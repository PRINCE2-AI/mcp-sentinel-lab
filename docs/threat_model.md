# Threat Model

## Assets

- API keys and bearer tokens
- local workspace files
- private Windows paths and user documents
- agent memory
- tool-call traces
- network destinations

## Attacker Goals

- Make the agent ignore instructions.
- Poison a tool manifest so the agent trusts malicious behavior.
- Exfiltrate secrets through HTTP, email, or webhook tools.
- Escape the approved workspace.
- Persist malicious memory for future turns.
- Hide tool behavior from the user.

## Defenses Implemented

- Manifest scanner for hidden instructions and risky capabilities.
- Manifest hash pinning for tool drift detection.
- Runtime policy engine with allow, block, and approval decisions.
- Secret and private-path detection.
- External network destination checks.
- Decision traces with redacted arguments.
- Baseline vs protected attack simulation.

## Out of Scope for v1

- Running a full production MCP proxy.
- Sandboxing arbitrary subprocess execution.
- Cryptographic attestation of remote MCP servers.
- Formal verification of policies.
- Replacing human approval for high-risk workflows.
