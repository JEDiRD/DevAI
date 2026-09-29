# Dev AI Platform

Provider-agnostic AI engineering orchestration platform.

Core flow:

User/API
  -> Admission & Policy
  -> Orchestrator / Planner
  -> Model Router
  -> Provider Gateway
  -> Worker
  -> Reviewer
  -> Result

Initial goals:
- No agent tied to one provider
- Automatic provider fallback
- Complexity-based model selection
- Authoritative cost/usage ledger
- Checkpoint/resume
- Human approval gates
- Isolated execution
- Zero idle LLM consumption

Worker Control API setup and credential lifecycle:
[docs/WORKER_CONTROL_API.md](docs/WORKER_CONTROL_API.md).

Private API service and Windows Worker agent:
[docs/NETWORK_WORKER.md](docs/NETWORK_WORKER.md).
