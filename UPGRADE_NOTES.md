# Applying these changes to your clone

Nothing was rewritten from scratch: this is the same package with additions,
fixes and two breaking changes that are called out below. Copy the files over and
commit.

## Files touched

**Updated (drop-in replacements — same module paths):**

| File | What changed |
| --- | --- |
| `agentauth/__init__.py` | new exports (`Policy`, `DischargeToken`, `mint_discharge`, `check_narrowing`, `KeyRecord`, `KeyStatus`, …), `__version__ = "1.1.0"` |
| `agentauth/token.py` | `key_id` on the token, `to_compact()`/`from_compact()`/`parse()`, `depth()`, `holders()`, `caveats_by_kind()` |
| `agentauth/caveats.py` | `ClaimCaveat`, `ThirdPartyCaveat`, registry + validation in `from_dict` |
| `agentauth/issuer.py` | key generations: `rotate_key`, `compromise_key`, `active_key_id`, `list_keys` |
| `agentauth/verifier.py` | key-generation resolution, discharge verification, policy evaluation, `verify_detailed()` / `Decision` |
| `agentauth/ledger.py` | configurable/persistent path, in-place migration, read helpers |
| `agentauth/audit.py` | event types, layer/validity/latency columns, `stats()`, `denials_by_*()`, `recent()`, migration |
| `agentauth/service/api.py` | admin auth, rotation/compromise, discharges, policy, ledger and audit endpoints |
| `agentauth/service/client.py` | admin key support, `verify_detailed`, rotation, discharges, policy, audit, ledger |
| `agentauth/service/mcp_tools.py` | registry + policy enforcement, four tools |
| `agentauth/service/mcp_server.py` | four tools, discharge support, `who_authorized` tool |
| `tests/*`, `examples/*` | expanded / updated (see below) |

**New:**

```
agentauth/policy.py         declarative JSON-AST policy language
agentauth/discharge.py      third-party caveats, discharge tokens
agentauth/attenuation.py    narrowing guard + glob containment
tests/test_attenuation.py   guard and glob-subset semantics
tests/test_rotation.py      key generations, compromise recovery
tests/test_policy.py        policy language
tests/test_third_party.py   third-party caveats and discharges
examples/demo_third_party.py
examples/demo_key_rotation.py
CHANGELOG.md  UPGRADE_NOTES.md  README_UPDATES.md  pyproject.toml
```

```bash
# from your agentauth clone
cp -r /path/to/this/agentauth ./agentauth
cp -r /path/to/this/tests ./tests
cp -r /path/to/this/examples ./examples
cp CHANGELOG.md UPGRADE_NOTES.md README_UPDATES.md pyproject.toml requirements.txt .
pip install -r requirements.txt
python -m pytest tests/ -v          # 95 tests, fully offline
python examples/demo_delegation_chain.py
python examples/demo_third_party.py
python examples/demo_key_rotation.py
python examples/demo_mcp_server.py
python examples/demo_http_service.py
```

If you prefer a patch: `git diff --no-index` between your checkout and this
directory produces a reviewable unified diff per file.

## Breaking changes (two, both one-line fixes)

1. **Admin key required on mutating endpoints.** `POST /tokens/mint`,
   `/tokens/delegate`, `/tokens/revoke`, `/principals*`, `/keys/*`,
   `/discharges` and `PUT /policy*` now need the `X-AgentAuth-Admin-Key` header
   (or `Authorization: Bearer …`). Set `AGENTAUTH_ADMIN_KEY` on the service and
   pass `admin_key=` to `AgentAuthClient`. `/verify` and `/tools/{tool}` still
   need no key.

2. **`/principals/{id}/register` no longer returns the raw root key.** Provision
   keys out of band (KMS, mTLS admin channel, or `Issuer.register_principal`
   in-process). For local demos only, `AGENTAUTH_ALLOW_KEY_EXPORT=1` restores the
   old response body.

Everything else is additive. Specifically unchanged: the HMAC construction
(`sig₀ = HMAC(root_key, token_id)`, `sigᵢ = HMAC(sigᵢ₋₁, entryᵢ)`), the
canonical JSON encoding, chain entry shapes, the five original caveat kinds, and
`Verifier.verify(token, context) -> (allowed, reason)`.

## Migration notes

- **Existing tokens** keep working: they parse with `key_id="gen1"` and verify
  against the principal's first generation key. Calling
  `Issuer.register_principal(...)` twice is now idempotent (it returns the
  provisioned key instead of creating a new one); use `rotate_key()` to add a
  generation.
- **Existing SQLite state files** open and are migrated in place: missing
  `reason`/`revoked_by`/`ts` columns on `revoked_tokens`, and
  `event`/`layer`/`signature_valid`/`latency_ms` on `audit_records`.
- **Existing caveat dicts** serialise unchanged. `Caveat.from_dict` now raises
  `ValueError` on an unknown `kind` instead of `KeyError`; the service turns that
  into a `400`.

## Configuration

| Env var | Default | Purpose |
| --- | --- | --- |
| `AGENTAUTH_ADMIN_KEY` | `dev-admin-key` | admin key for mutating endpoints (`/health` reports when the dev default is in use) |
| `AGENTAUTH_LEDGER_DB` | `agentauth-ledger.db` (service), `:memory:` (library) | revocation, use-count and aggregation state |
| `AGENTAUTH_AUDIT_DB` | `agentauth-audit.db` (service), `:memory:` (library) | decisions and provenance |
| `AGENTAUTH_ALLOW_KEY_EXPORT` | unset | `1` re-enables raw key export from the legacy register route (demos only) |
| `AGENTAUTH_SEED_DEMO` | unset | `1` registers `alice`, `bob` and `hr-directory` on boot |

Run the service:

```bash
AGENTAUTH_ADMIN_KEY=change-me uvicorn agentauth.service.api:create_app --factory --port 8811
```

## Still honest about what is not done

- **Issuer and verifier are still not a split trust boundary.** Verification no
  longer needs the admin key and state is shared, but root keys still live beside
  the verifier in this deployment. The next step is a separately-trusted issuer
  service that only signs and never verifies.
- **SQLite is single-node.** Point both processes at the same file for local
  multi-process testing, but a real deployment wants the ledger in
  Postgres/Redis. Everything is behind `RevocationLedger`, so the swap is one
  class.
- **No interop with the competing 2026 proposals** (IBCTs, PAuth, PCAS, OIDC-A) —
  each has a different wire format and none has won.
- **Policy expressiveness is bounded.** Aggregation budgets still count distinct
  units of one field; inference through *combinations* of different resource
  types (the PCAS Datalog case) is still out of reach.
- **Multi-caveat discharges** are per-caveat (`location` + `nonce`); there is no
  batching or caching layer for discharge verification.
