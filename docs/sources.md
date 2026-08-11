# Research and Source Map

The project idea was triangulated from research papers, MCP security guidance,
and open-source agent security tools.

## Primary Sources

- AgentDojo: https://arxiv.org/abs/2406.13352
  - Used for prompt-injection evaluation framing in tool-using agents.
- AgentDojo GitHub: https://github.com/ethz-spylab/agentdojo
  - Used as evidence that realistic agent tasks and attacks are benchmarkable.
- MCPTox: https://arxiv.org/abs/2508.14925
  - Used for MCP tool-poisoning and malicious tool description motivation.
- AgentCanary / Agent3Sigma Canary: https://github.com/antgroup/Agent3Sigma-Canary
  - Used for executable environment and trajectory-style safety evaluation ideas.
- OWASP MCP Tool Poisoning: https://owasp.org/www-community/attacks/MCP_Tool_Poisoning
  - Used for trust-boundary and tool-response poisoning framing.
- SAFE-MCP: https://www.safemcp.org/
  - Used for MCP attack taxonomy inspiration.
- MCP client best practices: https://modelcontextprotocol.io/docs/develop/clients/client-best-practices
  - Used for sandboxing, authorization, and cross-server data-flow guidance.
- Invariant MCP-Scan: https://invariantlabs-ai.github.io/docs/mcp-scan/
  - Used to identify existing scanner/proxy work and differentiate this project
    with policy, evaluation, trace replay, and dashboard layers.

## Product Gap

Existing tools tend to cover scanning or proxying. MCP Sentinel Lab combines:

- static manifest scanning
- runtime policy decisions
- sensitive-data controls
- attack simulation
- measurable baseline vs protected evaluation
- recruiter-readable observability
