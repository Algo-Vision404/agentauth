# README updates (drop-in sections for 1.1.0)

Paste these over the matching sections of `README.md`.

---

## Quickstart

```bash
pip install -r requirements.txt
python -m pytest tests/ -v                     # 95 tests, fully offline
python examples/demo_delegation_chain.py       # in-process: narrowing, forgery, revocation, budgets
python examples/demo_third_party.py            # third-party caveat + discharge service
python examples/demo_key_rotation.py           # rotate a root key, then recover from a leak
python examples/demo_http_service.py           # real HTTP server (uvicorn) + client SDK
python examples/demo_mcp_server.py             # enforcement on real MCP tool functions
```

```python
from agentauth import (
    Issuer, Verifier, ActionCaveat, ResourceCaveat,
    AggregationBudgetCaveat, ThirdPartyCaveat, check_narrowing,
)

issuer = Issuer()
issuer.register_principal("alice")
verifier = Verifier(issuer)

root = issuer.mint("alice", "planner_agent", [
    ActionCaveat(("read", "write")),
    ResourceCaveat(("orders/*",)),
    AggregationBudgetCaveat(budget_name="customers_touched", max_units=5, unit_field="customer_id"),
])

# refuse widening *before* issuing, with a reason
report = check_narrowing(root.caveats(), [ResourceCaveat(("orders/*", "customers/*"))])
assert not report.ok
print(report.violations[0].detail)

# delegate a narrower token -- no root key needed
sub_token = root.delegate("planner_agent", "sub_agent", [
    ActionCaveat(("read",)),
    ResourceCaveat(("orders/customer_42/*",)),
])

decision = verifier.verify_detailed(sub_token, {"action": "read", "resource": "orders/customer_42/17"})
print(decision.allowed, decision.layer, decision.reason)   # True ok 'all caveats satisfied'

# tokens also carry a compact wire form for argv/headers/MCP arguments
compact = sub_token.to_compact()          # "agentauth1_..."
```

`Verifier.verify(token, context)` still returns `(allowed, reason)`.
`verify_detailed(...)` adds the deciding layer
(`cryptographic | ledger | discharge | caveat | policy`), token/holder ids,
caveats checked, discharges used and latency.

---

## Key rotation and compromise recovery

Root keys are versioned per principal, and each token records the generation that
seeded it, so rotating does not invalidate anything already issued:

```python
old = issuer.mint("alice", "planner_agent", [ActionCaveat(("read",)), ResourceCaveat(("orders/*",))])
record = issuer.rotate_key("alice", note="scheduled rotation")   # -> alice#gen2
new = issuer.mint("alice", "planner_agent", [ActionCaveat(("read",))])

verifier.verify(old, ctx)    # still valid: verified against alice#gen1
verifier.verify(new, ctx)    # valid: signed with alice#gen2

# a leaked generation is rejected wholesale, without taking the principal down
issuer.compromise_key("alice", "alice#gen1", note="key leaked")
verifier.verify(old, ctx)    # (False, "root key generation 'alice#gen1' ... marked compromised")
verifier.verify(new, ctx)    # unaffected
```

`Issuer.list_keys()` returns status + a key fingerprint; key material never
leaves the issuer.

---

## Third-party caveats

A caveat that only another service can satisfy — macaroons' original killer
feature, now implemented:

```python
from agentauth import ThirdPartyCaveat, mint_discharge

issuer.register_principal("hr-directory", note="discharge service")
hr_key = issuer.root_key_for("hr-directory")

token = issuer.mint("alice", "research_agent", [
    ActionCaveat(("read",)),
    ResourceCaveat(("customers/*",)),
    ThirdPartyCaveat("hr-directory", "the caller acts on behalf of employee alice", nonce="n1"),
])

# nobody can satisfy this locally
verifier.verify(token, {"action": "read", "resource": "customers/C-42/orders"})
#   -> (False, "third-party caveat requires a discharge from 'hr-directory' ...")

discharge = mint_discharge(
    service_root_key=hr_key, location="hr-directory",
    parent_token_id=token.token_id, nonce="n1",
    claims={"on_behalf_of": "alice"},
)
verifier.verify(
    token,
    {"action": "read", "resource": "customers/C-42/orders", "on_behalf_of": "alice"},
    discharges=[discharge],
)   # -> (True, "all caveats satisfied")
```

The discharge key is `HMAC(service_root_key, f"{token_id}:{nonce}")`, so a discharge
is bound to one token and one caveat instance: it cannot be replayed onto another
token, and a discharge obtained once cannot cover a different caveat.

---

## Policy: rules that travel with the resource

Caveats constrain a *token*; policy constrains a *resource*. Both are evaluated at
the same boundary and AND together, so a holder cannot negotiate a server rule
away, and an operator can tighten a fleet-wide rule without re-minting tokens.

```python
from agentauth import Policy

policy = Policy.from_dict({
    "op": "and",
    "args": [
        {"op": "in", "field": "status", "value": ["pending", "shipped", "cancelled"]},
        {"op": "or", "args": [
            {"op": "nin", "field": "status", "value": ["cancelled", "refunded"]},
            {"op": "exists", "field": "approval_id"}]},
        {"op": "lte", "field": "order.total", "value": 5000},
    ],
}, name="update_order")

verifier.verify_detailed(token, context, policy=policy)   # layer == "policy" when refused
verifier.set_policy(policy)                               # or attach it to the verifier
```

Operators: `and`, `or`, `not`, `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `nin`,
`matches`, `exists`. Unknown operators/fields are rejected at load time, and
missing values fail closed. `Policy.from_file()` lets you keep policies in the repo.

---

## HTTP verification service

```bash
AGENTAUTH_ADMIN_KEY=change-me uvicorn agentauth.service.api:create_app --factory --port 8811
```

```python
from agentauth.service import AgentAuthClient
from agentauth import ActionCaveat, ResourceCaveat

client = AgentAuthClient("http://localhost:8811", admin_key="change-me")
minted = client.mint("alice", "planner_agent", [ActionCaveat(("read",)), ResourceCaveat(("orders/*",))])
decision = client.verify_detailed(minted["serialized"], {"action": "read", "resource": "orders/42"})
print(decision["allowed"], decision["layer"])
```

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /verify` | public | reference-monitor check, returns the deciding layer |
| `POST /tools/{tool}` | public | run a registry tool through the full enforcement path |
| `GET /tools` | public | tool catalogue with required action/resource/policy |
| `POST /principals` | admin | register a principal (metadata only, never key material) |
| `POST /tokens/mint` | admin | issue a root token |
| `POST /tokens/delegate` | admin | narrowing hop; `409` + `narrowing.violations` if it would widen |
| `POST /tokens/revoke` | admin | explicit revocation, checked at every verify |
| `POST /keys/rotate`, `POST /keys/compromise`, `GET /keys` | admin / public | key generations (fingerprints only) |
| `POST /discharges`, `GET /discharges` | admin / public | third-party caveat discharges |
| `PUT /policy`, `PUT /policy/tools/{tool}`, `GET /policy` | admin / public | resource-side rules |
| `GET /audit/recent`, `/audit/trace/{id}`, `/audit/who_authorized/{id}` | public | decisions, provenance, denial breakdowns |
| `GET /ledger/usage`, `GET /health` | public | use counts, revocations, aggregation budgets |

**Security note.** The register endpoint no longer returns the raw root key
(`AGENTAUTH_ALLOW_KEY_EXPORT=1` restores that for local demos only), and mutating
endpoints require the admin key configured via `AGENTAUTH_ADMIN_KEY`. Verification
deliberately requires no admin credentials.

---

## MCP server enforcement

`agentauth.service.mcp_server` is a real MCP server (`mcp.server.fastmcp.FastMCP`)
exposing four tools — `get_order`, `update_order`, `get_customer_insights`,
`search_orders` — each requiring a capability token verified **before** the tool
body runs, plus a server-side policy evaluated after:

```bash
python -m agentauth.service.mcp_server      # stdio transport, usable by any MCP client
```

```python
get_order(token=token_json, order_id="42")
# -> {"allowed": false, "layer": "caveat", "reason": "..."} when the token doesn't authorize it
# -> {"allowed": true,  "result": {...}}          when it does
```

Tools ship with policies that no token can override: `update_order` refuses a
cancel/refund without an `approval_id` and refuses orders above 5000 at all;
`search_orders` refuses pages above 100 rows. `get_customer_insights` counts
toward the token's aggregation budget, so an agent cannot assemble a dataset one
legitimate request at a time. Denials name their layer, and every call (allowed or
denied) is recorded in the audit log.

---

## The three sub-problems, and how each is handled

| Sub-problem | What it means | Mechanism |
| --- | --- | --- |
| **Transitive delegation** | Permissions silently widening as they pass down a chain | HMAC chain makes any widening cryptographically detectable at verify time; `check_narrowing()` refuses it at issue time and records `widening_rejected` |
| **Aggregation inference** | An agent legitimately allowed to see pieces of data infers something it was never allowed to know | `AggregationBudgetCaveat` caps distinct units per workflow in the shared ledger, independent of any single call being permitted |
| **Temporal validity** | A compromised agent executes far more actions inside a TTL window than a human could | `MaxUsesCaveat` + explicit revocation, checked synchronously at every `verify()` call — never wall-clock trust |
| **Identity at hop 3+** *(new)* | Which human authorized this agent to do this, four hops down | Every entry — caveats *and* delegation records — is folded into the chain, and `audit_log.who_authorized(token_id)` returns the recomputed path |
| **External policy conditions** *(new)* | "Only while acting on behalf of alice" | `ThirdPartyCaveat` + discharges, and `ClaimCaveat` for context-bound claims |

---

## Updated honest gap list

- **Trust split is still incomplete.** Verification no longer needs the admin key
  and the ledger is shared, but the issuer and verifier still live in one process
  in this deployment. A separately-trusted, sign-only issuer service is the next step.
- **State is SQLite, single-node.** Durable across restarts (WAL files), but
  multi-replica deployments need Postgres/Redis. Everything goes through
  `RevocationLedger`, so the swap is one class.
- **No interop** with IBCTs, PAuth, PCAS or OIDC-A — different wire formats, none
  has won.
- **Policy expressiveness.** Budgets count distinct units of a single field;
  inference through combinations of different resource types (the PCAS Datalog
  case) is still not expressible.
- **Discharge verification is per-caveat** with no batching or caching.
- **MCP integration is single-server.** The HTTP/tool layer is protocol-shaped and
  the tool registry is data, but there is no ecosystem-wide federation.

---

## File map

```
agentauth/
  __init__.py     public API (v1.1.0)
  token.py        Capability — HMAC chain, mint/delegate, key_id, compact wire form
  caveats.py      action, resource, time_window, max_uses, agg_budget, claim, third_party
  attenuation.py  check_narrowing(), glob_is_subset()          [new]
  discharge.py    ThirdPartyCaveat discharges                  [new]
  policy.py       declarative JSON-AST policy language         [new]
  ledger.py       RevocationLedger — durable, configurable store
  issuer.py       Issuer — key generations, rotate/compromise
  verifier.py     Verifier — crypto → ledger → discharge → caveats → policy
  audit.py        AuditLog — decisions + events + provenance queries
  service/
    api.py          FastAPI service (admin auth, rotation, discharges, policy)
    client.py       AgentAuthClient SDK
    mcp_server.py   real MCP server, four token-enforced tools
    mcp_tools.py    enforcement logic + tool registry (testable without mcp)

examples/  demo_delegation_chain.py  demo_http_service.py  demo_mcp_server.py
           demo_third_party.py  demo_key_rotation.py            [2 new]

tests/     test_basic.py  test_attenuation.py  test_rotation.py  test_policy.py
           test_third_party.py  test_service.py  test_mcp_tools.py    (95 tests)

CHANGELOG.md  UPGRADE_NOTES.md  README_UPDATES.md  pyproject.toml
```
