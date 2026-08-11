# Architecture

## Decision

MCP Sentinel Lab uses a small pure-Python core with optional FastAPI,
Streamlit, and OpenRouter/OpenAI adapters.

## Reasoning

The project needs to be easy to run in three modes:

1. local test mode with no API key
2. portfolio demo mode with CLI/API/dashboard
3. live LLM mode for richer explanations

Keeping the core dependency-light makes security decisions deterministic and
testable. Optional adapters can fail gracefully without breaking the policy
engine or benchmark.

## Components

```text
ToolManifest
  -> ManifestScanner
  -> ToolPinStore
ToolCall
  -> PrivacyGuard
  -> PolicyEngine
  -> SentinelGateway
  -> TraceStore
AttackCase
  -> AttackEvaluator
  -> EvalSummary
```

## Trust Boundaries

- User prompt to agent: untrusted.
- Tool manifest from MCP server: untrusted until scanned and pinned.
- Tool output: untrusted unless validated by downstream policy.
- Tool arguments: sensitive because they may contain paths, tokens, emails, or
  private content.
- Network destinations: untrusted unless allowlisted.

## Consequences

- Tests can run without external services.
- LLM-generated explanations are optional, not a security dependency.
- The project can be extended into a real MCP proxy later.
- The current implementation simulates execution instead of running arbitrary
  external tools, which is safer for portfolio demonstration.
