# Dev AI Platform Architecture

## Core components

1. API / Controller
2. Admission & Policy Gate
3. Orchestrator / Planner
4. Model Router
5. Provider Gateway
6. Authoritative Ledger
7. Worker Runtime
8. Reviewer / Verifier
9. Checkpoint / Resume

## Routing principle

The orchestrator determines what capability/tier a task or subtask requires.

The router decides which currently available provider/model satisfies that tier.

Agents never depend directly on a provider.

## Initial tiers

- free
- standard
- frontier

## Fundamental invariant

A provider quota, outage, or exhausted token allowance must not stop the project
when another approved provider can satisfy the requested capability.

## Retry authority

The Dev AI Controller is the single retry/fallback authority.

Provider SDKs and gateways must not independently create retry storms.

## Cost authority

Provider-reported cost is informational.

The Dev AI ledger is authoritative and records:
- job
- task
- attempt
- provider
- model
- tokens
- estimated cost
- final reconciled cost
- outcome
