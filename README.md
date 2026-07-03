# agentauth

Scoped, delegatable, revocable, auditable capability tokens for AI agents.

Built against a real, current gap: OAuth/RBAC/ABAC assume a human clicking "allow" once. Agents delegate tasks to other agents, recursively, across tool calls — and as of a May 2026 paper, *"no deployed protocol can cryptographically prove which human principal authorized which specific agent to perform which specific action at the third or fourth hop of a delegation chain."* A 2026 scan of ~2,000 live MCP servers found all of them lacked authentication entirely.

This maps directly to YC's Summer 2026 "Software for Agents" category: identity, permissions, and machine-native authorization for a world where the next trillion users are agents, not people.

## Why not just OAuth?

OAuth scopes are static and operator-granted once. Agent delegation needs three things OAuth doesn't have:

1. **Attenuation without a trust round-trip** — an agent delegating to a sub-agent shouldn't need to call back to the original issuer.
2. **Tamper-evident provenance** — a verifiable record of every hop, not just the current holder.
3. **Fast, execution-count-based revocation** — a compromised agent can burn through a time-based token faster than a TTL protects against.

## Design

Macaroon-family capability tokens: the signature is an HMAC chain.

```
sig_0 = HMAC(root_key, token_id)
sig_i = HMAC(sig_{i-1}, entry_i)
```

Delegation appends an entry and re-derives the signature — no root key needed, so agents can delegate to sub-agents without ever holding issuer credentials. But nobody can forge a valid chain without the root key, because that requires inverting HMAC. This is what makes "delegation can only narrow, never widen" actually enforceable, not just a convention.

Each chain entry is either a **caveat** (a restriction) or a **delegation record** (who handed the token to whom, when) — both are folded into the same HMAC chain, so the full provenance trail is cryptographically tamper-evident, not just the permissions.

## Quickstart

```bash
pip install -r requirements.txt
python -m pytest tests/ -v                    # 23 tests, fully offline
python examples/demo_delegation_chain.py       # in-process demo
python examples/demo_http_service.py           # real HTTP server + client, on localhost
python examples/demo_mcp_server.py             # enforcement on real MCP tool functions
```

```python
from agentauth import Issuer, Verifier, ActionCaveat, ResourceCaveat, AggregationBudgetCaveat

issuer = Issuer()
issuer.register_principal("alice")
verifier = Verifier(issuer)

# alice authorizes a planner agent
root = issuer.mint("alice", "planner_agent", [
    ActionCaveat(("read", "write")),
    ResourceCaveat(("orders/*",)),
    AggregationBudgetCaveat(budget_name="customers_touched", max_units=5, unit_field="customer_id"),
])

# planner_agent delegates a NARROWER token to a sub-agent -- no root key needed
sub_token = root.delegate("planner_agent", "sub_agent", [
    ActionCaveat(("read",)),
    ResourceCaveat(("orders/customer_42/*",)),
])

ok, reason = verifier.verify(sub_token, {"action": "read", "resource": "orders/customer_42/17"})
```

## HTTP verification service

The library above is in-process only. `agentauth.service` wraps it as a real FastAPI service so an agent runtime can call verification over the network at every tool-invocation boundary, not just inside one Python process.

```python
from agentauth.service import create_app
import uvicorn

uvicorn.run(create_app(), host="0.0.0.0", port=8811)
```

```python
from agentauth.service import AgentAuthClient
from agentauth import ActionCaveat, ResourceCaveat

client = AgentAuthClient("http://localhost:8811")
client.register_principal("alice")
token = client.mint("alice", "planner_agent", [ActionCaveat(("read",)), ResourceCaveat(("orders/*",))])
allowed, reason = client.verify(token, {"action": "read", "resource": "orders/42"})
```

Endpoints: `POST /principals/{id}/register`, `POST /tokens/mint`, `POST /tokens/delegate`, `POST /verify`, `POST /revoke`, `GET /audit/trace/{token_id}`, `GET /audit/who_authorized/{token_id}`.

**Security note:** `/principals/{id}/register` returns the raw root key over the response body — a dev/demo convenience only. A real deployment provisions root keys out-of-band (KMS, mTLS-authenticated admin channel) and never transmits them over a request/response API.

## MCP server enforcement

`agentauth.service.mcp_server` is a real MCP server (`mcp.server.fastmcp.FastMCP`) exposing two example tools, `get_order` and `update_order`, each requiring a capability token as an argument and verified **before** the tool body runs — the exact boundary a 2026 scan found ~2,000 live MCP servers leave completely unauthenticated.

```bash
python -m agentauth.service.mcp_server   # stdio transport, usable by any MCP client
```

```python
# any tool call now requires a valid, scoped token:
get_order(token=token_json, order_id="42")
# -> {"error": "authorization denied: ..."} if the token doesn't authorize it,
#    otherwise the actual tool result
```

See `examples/demo_mcp_server.py` for a full run: an authorized read succeeds, an out-of-scope read is denied, a write attempt on a read-only token is denied, and a tampered token (edited to grant itself broader access) is caught by the signature check before the tool body ever executes.

## The three sub-problems, and how each is handled

The May 2026 paper (Tallam, arXiv 2605.05440) names three sub-problems that classical access control doesn't solve for agent workflows. Each has a direct answer here:

| Sub-problem | What it means | Mechanism |
|---|---|---|
| **Transitive delegation** | Permissions silently widening as they pass down a chain | HMAC chain makes any widening cryptographically detectable at verify time |
| **Aggregation inference** | An agent legitimately allowed to see pieces of data infers something it was never allowed to know, by collecting many pieces | `AggregationBudgetCaveat` caps distinct units (e.g. distinct customers) touched per workflow, tracked in a shared ledger, independent of any single call being individually permitted |
| **Temporal validity** | A compromised agent can execute far more actions inside a TTL window than a human could | `MaxUsesCaveat` + explicit revocation, both checked synchronously against a shared ledger at every single `verify()` call — not wall-clock trust |

Every `verify()` call — allowed or denied — is written to `AuditLog`, which can answer "who authorized this token, hop by hop" after the fact (`audit_log.who_authorized(token_id)`).

## What's implemented

- Macaroon-style HMAC-chained capability tokens (mint, delegate, serialize/deserialize)
- 5 caveat types: action, resource (glob patterns), time window, max-uses, aggregation budget
- Cryptographic tamper detection on the full chain (caveats *and* delegation provenance)
- Execution-count-based revocation ledger (explicit revoke + max-uses), independent of wall clock
- Aggregation-inference budget tracking, scoped per workflow
- Full audit trail with hop-by-hop provenance queries
- **Real HTTP verification service** (FastAPI) + Python client SDK
- **Real MCP server** with two token-enforced tools, tested and runnable over stdio with any MCP client
- 23 passing tests, fully offline (FastAPI TestClient — no live server needed for the HTTP tests)

## Honest gap list

- **Single-process trust model, now partially addressed.** The HTTP service still holds root keys in the same process as the verifier — it's a real network service, but it's not yet a *separately trusted* issuer that a verifier calls out to without sharing keys. A proper split (issuer as a separate, more locked-down service; verifiers holding only what they need to check signatures) is the natural next step.
- **In-memory ledger and audit log**, both in the library and in the HTTP service. A restart loses all revocation/use-count/aggregation state and audit history. Real deployments need a shared store (Redis, Postgres, etc.) so multiple verifier processes/replicas agree on state.
- **No auth on the service itself.** The FastAPI service has no authentication on its own endpoints (anyone who can reach `/tokens/mint` can mint tokens, if they know a registered principal id). This needs to sit behind its own access control before it's production-usable — an intentionally out-of-scope MVP simplification, not an oversight.
- **MCP integration is single-server, not ecosystem-wide.** No interop yet with the competing 2026 proposals in this space (IBCTs, PAuth, PCAS, OIDC-A) — each has a different wire format and none has won yet.
- **No policy language.** Caveats are Python objects, not a declarative policy language (the paper's PCAS approach uses Datalog over a dependency graph, which handles some aggregation-inference cases this simple ledger can't — e.g. inference through *combinations* of different resource types, not just repeated access to the same type).
- **No key rotation / compromise recovery.** If a root key leaks, every token minted from it is compromised with no clean rotation path.
- **Caveat expressiveness.** No support for third-party caveats (macaroons' actual killer feature — a caveat that can only be discharged by proving something to a *different* service), which would let this integrate with external policy engines instead of only self-contained predicates.

## File map

```
agentauth/
  __init__.py     public API
  token.py        Capability — HMAC-chained token, mint/delegate/serialize
  caveats.py      ActionCaveat, ResourceCaveat, TimeWindowCaveat, MaxUsesCaveat, AggregationBudgetCaveat
  ledger.py       RevocationLedger — use-counts, explicit revocation, aggregation tracking
  issuer.py       Issuer — holds root keys, mints tokens
  verifier.py     Verifier — signature recomputation + caveat evaluation + audit logging
  audit.py        AuditLog — decision history + delegation-chain provenance queries
  service/
    api.py          FastAPI verification service (mint/delegate/verify/revoke/audit over HTTP)
    client.py        AgentAuthClient — httpx-based client SDK for the service
    mcp_server.py     real MCP server (FastMCP) with token-enforced tools
    mcp_tools.py      testable enforcement logic factored out of the MCP decorators

examples/
  demo_delegation_chain.py   3-hop in-process delegation: narrowing, forgery, revocation, aggregation guard
  demo_http_service.py        same flow, driven over a real running HTTP server
  demo_mcp_server.py          enforcement on real MCP tool functions (get_order/update_order)

tests/
  test_basic.py       12 tests — core library, fully offline
  test_service.py      5 tests — HTTP service via FastAPI TestClient, fully offline
  test_mcp_tools.py    6 tests — MCP tool enforcement logic, fully offline
```
