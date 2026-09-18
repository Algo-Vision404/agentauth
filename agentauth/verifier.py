"""
Verifier: the reference monitor. Called at every tool-invocation boundary
(the paper's R3 requirement -- "authorization must be evaluated at every
interaction boundary", not just at the start of a workflow).

Layers of defense, checked in order. Any layer can deny, and the deciding
layer is reported (`verify_detailed`) and audited:
  1. cryptographic -- resolve the key generation named by the token, reject
     compromised generations, then recompute the HMAC chain from the root key.
     If any entry was forged, reordered, removed or edited, the recomputed
     signature will not match and the token is rejected outright. This is what
     makes "only narrowing, never widening" enforceable even though delegation
     itself needs no root secret.
  2. ledger -- explicit revocation, checked synchronously (never a TTL).
  3. discharge -- third-party caveats must be discharged by the named service.
  4. caveat -- every caveat in the (now-trusted) chain, AND-composed.
  5. policy -- optional resource-side rule set (agentauth.policy), ANDed with
     the token's caveats so a holder cannot negotiate a server rule away.

Every call -- allowed or denied -- is written to the audit log.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import json
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .audit import VERIFY, AuditLog
from .caveats import ThirdPartyCaveat
from .discharge import DischargeToken, verify_discharge
from .issuer import Issuer, KeyStatus, UnknownPrincipal
from .ledger import RevocationLedger
from .policy import Policy, policy_from
from .token import Capability


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac_module.new(key, msg, hashlib.sha256).digest()


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class Decision:
    """The full verdict, including which layer decided it."""
    allowed: bool
    reason: str
    layer: str = "ok"
    token_id: str = ""
    root_principal: str = ""
    holder: str = ""
    key_id: str = ""
    caveats_checked: int = 0
    discharges_used: list[str] = field(default_factory=list)
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "layer": self.layer,
            "token_id": self.token_id,
            "root_principal": self.root_principal,
            "holder": self.holder,
            "key_id": self.key_id,
            "caveats_checked": self.caveats_checked,
            "discharges_used": list(self.discharges_used),
            "latency_ms": self.latency_ms,
        }


class Verifier:
    def __init__(
        self,
        issuer: Issuer,
        ledger: Optional[RevocationLedger] = None,
        audit_log: Optional[AuditLog] = None,
        discharge_keys: Optional[dict[str, bytes]] = None,
        policy: Any = None,
    ):
        self.issuer = issuer
        self.ledger = ledger or RevocationLedger()
        self.audit_log = audit_log or AuditLog()
        # location -> root key of a discharge service. Services can also be
        # registered as principals on the issuer, in which case that key is used.
        self.discharge_keys: dict[str, bytes] = dict(discharge_keys or {})
        self.policy = policy_from(policy)

    # ---- configuration ----------------------------------------------------

    def register_discharge_service(self, location: str, root_key: bytes) -> None:
        self.discharge_keys[location] = root_key

    def set_policy(self, policy: Any) -> None:
        self.policy = policy_from(policy)

    def _discharge_key_for(self, location: str) -> Optional[bytes]:
        if location in self.discharge_keys:
            return self.discharge_keys[location]
        try:
            return self.issuer.root_key_for(location)
        except (UnknownPrincipal, ValueError):
            return None

    # ---- cryptographic layer ---------------------------------------------

    def _recompute_signature(self, token: Capability, root_key: bytes) -> bytes:
        sig = _hmac(root_key, token.token_id.encode())
        for entry in token.chain:
            sig = _hmac(sig, _canonical(entry))
        return sig

    def _resolve_key(self, token: Capability) -> tuple[Optional[bytes], Optional[str]]:
        """Returns (key, failure reason). Key generation aware."""
        try:
            record = self.issuer.key_record(token.root_principal, token.key_id)
        except UnknownPrincipal as exc:
            return None, str(exc)
        if record.status == KeyStatus.COMPROMISED:
            return None, (
                f"root key generation '{record.key_id}' for '{token.root_principal}' is marked "
                f"compromised -- every token seeded from it is rejected"
            )
        return record.key, None

    # ---- the reference monitor -------------------------------------------

    def verify(
        self,
        token: Capability,
        context: dict,
        discharges: Optional[Iterable[Any]] = None,
    ) -> tuple[bool, str]:
        """Backward-compatible API (<= 1.0.0): returns (allowed, reason)."""
        decision = self.verify_detailed(token, context, discharges=discharges)
        return decision.allowed, decision.reason

    def verify_detailed(
        self,
        token: Capability,
        context: dict,
        discharges: Optional[Iterable[Any]] = None,
        policy: Any = None,
    ) -> Decision:
        """
        context should include at least:
          action: str            e.g. "read"
          resource: str          e.g. "orders/12345"
        and optionally:
          workflow_id: str       for aggregation-budget scoping
          any fields referenced by AggregationBudgetCaveat.unit_field
          any fields referenced by ClaimCaveat.claim_field
          _now: float            override current time (for testing)

        discharges: discharge tokens for this token's third-party caveats
        policy:     Policy / AST dict / JSON string to AND with the caveats
        """
        started = time.perf_counter()
        ctx = dict(context)
        ctx.setdefault("_now", time.time())

        root_principal = token.root_principal
        token_id = token.token_id
        try:
            holder = token.holder()
        except (IndexError, KeyError):
            holder = root_principal

        def finish(allowed: bool, reason: str, layer: str = "ok", *, signature_valid: bool = True,
                   caveats_checked: int = 0, discharges_used: Optional[list[str]] = None,
                   audit_reason: Optional[str] = None) -> Decision:
            latency = (time.perf_counter() - started) * 1000
            decision = Decision(
                allowed=allowed,
                reason=reason,
                layer=layer,
                token_id=token_id,
                root_principal=root_principal,
                holder=holder,
                key_id=getattr(token, "key_id", ""),
                caveats_checked=caveats_checked,
                discharges_used=list(discharges_used or []),
                latency_ms=latency,
            )
            audit_context = dict(ctx)
            audit_context.pop("_discharged_nonces", None)
            self.audit_log.record(
                token_id=token_id,
                root_principal=root_principal,
                holder=holder,
                delegation_chain=token.delegation_chain(),
                context=audit_context,
                allowed=allowed,
                reason=audit_reason or reason,
                event=VERIFY,
                layer=layer,
                signature_valid=signature_valid,
                latency_ms=latency,
            )
            return decision

        # ---- layer 1: cryptographic integrity ---------------------------
        root_key, failure = self._resolve_key(token)
        if root_key is None:
            return finish(False, failure or "unknown root key", "cryptographic", signature_valid=False)

        expected_sig = self._recompute_signature(token, root_key)
        if not hmac_module.compare_digest(expected_sig, token.signature):
            return finish(
                False,
                "signature mismatch: token chain does not match issuer root key "
                "(forged, widened, reordered or truncated)",
                "cryptographic",
                signature_valid=False,
            )

        # ---- layer 2: revocation ledger ---------------------------------
        if self.ledger.is_revoked(token_id):
            return finish(False, "token explicitly revoked", "ledger")

        caveats = token.caveats()

        # ---- layer 3: third-party caveats (discharges) -------------------
        satisfied: set[str] = set()
        discharges_used: list[str] = []
        third_party = [c for c in caveats if isinstance(c, ThirdPartyCaveat)]
        if third_party:
            provided: list[Any] = []
            for raw in (discharges or []):
                try:
                    provided.append(DischargeToken.parse(raw))
                except Exception:
                    return finish(False, "malformed discharge token presented", "discharge", signature_valid=False)

            for caveat in third_party:
                candidate = next(
                    (d for d in provided if d.location == caveat.location and d.nonce == caveat.nonce),
                    None,
                )
                if candidate is None:
                    return finish(
                        False,
                        f"third-party caveat requires a discharge from '{caveat.location}' "
                        f"(predicate: {caveat.predicate})",
                        "discharge",
                    )
                service_key = self._discharge_key_for(caveat.location)
                if service_key is None:
                    return finish(
                        False,
                        f"no root key registered for discharge service '{caveat.location}'",
                        "discharge",
                    )
                ok, reason = verify_discharge(candidate, token_id, service_key, ctx, self.ledger)
                if not ok:
                    return finish(False, reason, "discharge", signature_valid=False)
                satisfied.add(caveat.nonce)
                discharges_used.append(candidate.discharge_id)

        ctx["_discharged_nonces"] = satisfied

        # ---- layer 4: caveat evaluation (all must pass) ------------------
        checked = 0
        for caveat in caveats:
            checked += 1
            ok, reason = caveat.check(ctx, self.ledger, token_id)
            if not ok:
                return finish(
                    False,
                    reason,
                    "caveat",
                    caveats_checked=checked,
                    discharges_used=discharges_used,
                    audit_reason=f"caveat '{caveat.kind}' failed: {reason}",
                )

        # ---- layer 5: optional resource-side policy ----------------------
        effective_policy = policy_from(policy) or self.policy
        if effective_policy is not None:
            ok, reason = effective_policy.evaluate(ctx)
            if not ok:
                return finish(
                    False,
                    reason,
                    "policy",
                    caveats_checked=checked,
                    discharges_used=discharges_used,
                )

        # ---- success: consume use-count and aggregation budget ------------
        self.ledger.record_use(token_id)
        for caveat in caveats:
            if caveat.kind != "agg_budget":
                continue
            unit_value = ctx.get(caveat.unit_field)
            if unit_value is not None:
                self.ledger.record_aggregation_use(
                    ctx.get("workflow_id", "default"), caveat.budget_name, unit_value
                )

        reason = "all caveats satisfied"
        return finish(
            True,
            reason,
            "ok",
            caveats_checked=checked,
            discharges_used=discharges_used,
        )
