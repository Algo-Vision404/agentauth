# Changelog

## 1.1.0 — tweaks, fixes and new features

Everything below is an update to the existing package: the macaroon core, the
caveat semantics and the public API keep working. Items marked **BREAKING** need
a one-line change in a caller (details in `UPGRADE_NOTES.md`).

### New: key rotation and compromise recovery
*Previously listed as a gap: "no key rotation / compromise recovery — if a root key leaks, every token minted from it is compromised with no clean rotation path."*

- Root keys are now **versioned generations** per principal (`alice#gen1`, `alice#gen2`, …), with exactly one active at a time.
- Tokens carry the `key_id` that seeded them, so **rotating a key does not invalidate tokens already in circulation** — a retired generation still verifies.
- `Issuer.rotate_key(principal_id)` retires the current generation and creates the next.
- `Issuer.compromise_key(principal_id, key_id=None)` marks a generation as leaked: every token seeded from it is rejected at the cryptographic layer, while the principal keeps operating on a newer generation.
- `Issuer.list_keys()` returns metadata + a key **fingerprint** only — key material never leaves the issuer.

### New: third-party caveats and discharge tokens (`agentauth/discharge.py`)
*Previously listed as a gap: "no support for third-party caveats (macaroons' actual killer feature — a caveat that can only be discharged by proving something to a different service)."*

- `ThirdPartyCaveat(location, predicate, nonce)` — a restriction no token holder can satisfy locally.
- `mint_discharge(...)` / `verify_discharge(...)` / `derive_discharge_key(...)`: the discharge key is `HMAC(service_root_key, f"{parent_token_id}:{nonce}")`, so a discharge is bound to **one token and one caveat instance** and cannot be replayed onto another token or caveat.
- A discharge can carry its own caveats — typically a `ClaimCaveat`, e.g. `on_behalf_of=alice`.
- The verifier registers discharge services explicitly (`Verifier.register_discharge_service`) or falls back to a principal registered on the issuer.

### New: claim caveat
- `ClaimCaveat(claim_field, allowed_values)` requires the **call context** to carry an expected value (`on_behalf_of`, `tenant`, `region`, …). This is the piece static OAuth scopes cannot express at all.

### New: declarative policy language (`agentauth/policy.py`)
*Previously listed as a gap: "no policy language — caveats are Python objects, not a declarative policy language."*

- Caveats travel with the **token**; policy travels with the **resource** (an MCP tool, an endpoint). Both are evaluated at the same boundary and AND together, so a token holder cannot negotiate a server rule away.
- Tiny JSON AST, no `eval`: `and`, `or`, `not`, `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `nin`, `matches`, `exists`.
- `Policy.validate_ast()` rejects unknown operators/fields at load time, so a bad policy is a 400 instead of a silent allow.
- Missing values **fail closed**: a numeric bound is never satisfied by `None`.
- Policies are versioned data (loadable from a file in the repo or from the service), so a fleet-wide rule can change without re-minting tokens.

### New: attenuation guard (`agentauth/attenuation.py`)
- The *security* guarantee is still the HMAC chain: appending a caveat cannot widen access, and edits are caught at verify time.
- What was missing was feedback and observability, so `check_narrowing(parent_caveats, added_caveats)` now reports exactly what would widen — extra verbs, resource patterns that escape the parent's globs, extended time windows, raised `max_uses` or aggregation budgets.
- The HTTP service uses it to refuse widening delegations with a `409` + `narrowing.violations`, and records a **`widening_rejected`** audit event so *attempts* are visible, not just denials.
- `glob_is_subset(child, parent)` handles Python `fnmatch` semantics (`*` crosses `/`) and is deliberately conservative.

### Fixed: tool arguments are now part of the verification context
- Tool-call arguments are merged into the context the token **and** the policy are evaluated against (`action`, `resource` and `tool` are written last and cannot be spoofed by an argument). Previously a policy that referenced an argument such as `status` or `limit` could never pass, and `AggregationBudgetCaveat.unit_field` could not read a tool argument.

### Fixed: numeric policy comparisons no longer pass on missing values
- `lte`/`gte`/`lt`/`gt` now return `False` when either side is missing or non-numeric instead of coercing to `-inf` (which made `total <= 5000` true for an unknown total).

### Durability: the ledger and audit log survive restarts
*Previously listed as a gap: "in-memory ledger and audit log — a restart loses all revocation/use-count/aggregation state and audit history."*

- Both stores default their path from `AGENTAUTH_LEDGER_DB` / `AGENTAUTH_AUDIT_DB`; the service now uses files (`agentauth-ledger.db`, `agentauth-audit.db`) instead of `:memory:`.
- Databases written by ≤ 1.0.0 are migrated in place on open (new columns are added if missing).
- New read helpers: `ledger.revocations()`, `ledger.use_counts()`, `ledger.budget_usage()`, `ledger.consumed_units()`, `ledger.stats()`.
- Note: this is still single-node SQLite with WAL. Multi-replica deployments need a shared store (Postgres/Redis) — see `UPGRADE_NOTES.md`.

### Security: authentication on the service itself
*Previously listed as a gap: "no auth on the service itself — anyone who can reach /tokens/mint can mint tokens."*

- **BREAKING**: every mutating endpoint now requires `X-AgentAuth-Admin-Key` (or `Authorization: Bearer …`), configured via `AGENTAUTH_ADMIN_KEY`.
- `POST /verify` and `POST /tools/{tool}` deliberately require **no** admin key: a verifier replica legitimately needs no administrative credentials.
- **BREAKING**: `POST /principals/{id}/register` no longer returns the raw root key in the response body. Set `AGENTAUTH_ALLOW_KEY_EXPORT=1` to restore the old demo behaviour locally.
- `POST /principals` (new) registers a principal and returns metadata only.

### Audit log: more than verify decisions
- Records `mint`, `delegate`, `revoke`, `widening_rejected`, `key_rotate` and `discharge_mint` events alongside `verify`.
- Every record now carries the deciding `layer`, whether the signature was valid, and the latency.
- New queries: `stats()`, `denials_by_reason()`, `denials_by_layer()`, `recent(limit, only_denied, event)`.
- Context values that are not JSON serialisable (sets of satisfied discharge nonces) are normalised instead of raising.

### Verifier: decisions now name the layer
- `Verifier.verify(token, context)` still returns `(allowed, reason)` — unchanged.
- `Verifier.verify_detailed(token, context, discharges=None, policy=None)` returns a `Decision` with `layer` (`cryptographic` | `ledger` | `discharge` | `caveat` | `policy` | `ok`), token/holder/key ids, caveats checked, discharges used and latency.
- The verifier resolves the key generation stamped in the token and rejects compromised generations before recomputing the chain.

### Tokens: compact wire form and richer introspection
- `Capability.to_compact()` / `from_compact()` / `parse()` add an `agentauth1_…` base64url form that survives argv, HTTP headers and MCP tool arguments.
- `to_dict()`/`from_dict()` include `key_id`; tokens minted by ≤ 1.0.0 parse with `key_id="gen1"` and still verify.
- `depth()`, `holders()`, `caveats_by_kind()` added; `TAG`-style entry order and the HMAC construction are unchanged, so chains remain cross-compatible.

### MCP: four tools, policy and discharges
- Tool table is now data (`TOOL_REGISTRY`): action, resource template, required arguments, parameters, policy, policy note.
- Tools: `get_order`, `update_order`, `get_customer_insights`, `search_orders` (was two).
- Server-side policies ship with the tools, so a compromised token cannot refund without an approval id, cancel, or write an order above the money ceiling — and searches cannot export unbounded pages.
- `update_order` accepts `approval_id`; every tool accepts discharge tokens.
- `mcp_server.create_server()` raises a clear error if `mcp` is not installed; the library, service and tests work without it.

### Tests, examples, packaging
- **95 tests**, fully offline (was 23): core chain/caveat semantics, key rotation & compromise, the attenuation guard, the policy language, third-party caveats, the HTTP service (admin auth, delegation, discharges, rotation, policy, tools, audit, ledger) and MCP tool enforcement.
- Examples: the original three updated, plus `demo_third_party.py` and `demo_key_rotation.py`. `demo_http_service.py` now starts a real uvicorn server on an ephemeral port.
- `pyproject.toml` added (`service`, `mcp`, `dev` extras); `requirements.txt` refreshed.
- `__version__ = "1.1.0"` and a full public `__all__`.

## 1.0.0
- Macaroon-style HMAC-chained capability tokens, five caveat kinds, revocation ledger, audit log, FastAPI verification service, MCP server with two token-enforced tools.
