"""
Verifier: the reference monitor. Called at every tool-invocation boundary
(the paper's R3 requirement -- "authorization must be evaluated at every
interaction boundary", not just at the start of a workflow).

Two independent layers of defense:
  1. Cryptographic: recompute the HMAC chain from the root key. If any
     entry in the token's chain was forged, reordered, or removed, the
     recomputed signature won't match and the token is rejected outright
     -- this is what makes "only narrowing, never widening" enforceable
     even though delegation itself needs no root secret.
  2. Policy: evaluate every caveat in the (now-trusted) chain against the
     call context. ALL caveats must pass (they compose with AND) -- this
     is what turns a token into an actual capability instead of just an
     identity assertion.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import time
from typing import Optional

from .audit import AuditLog
from .issuer import Issuer
from .ledger import RevocationLedger
from .token import Capability


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac_module.new(key, msg, hashlib.sha256).digest()


def _canonical(entry: dict) -> bytes:
    import json
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()


class Verifier:
    def __init__(self, issuer: Issuer, ledger: Optional[RevocationLedger] = None, audit_log: Optional[AuditLog] = None):
        self.issuer = issuer
        self.ledger = ledger or RevocationLedger()
        self.audit_log = audit_log or AuditLog()

    def _recompute_signature(self, token: Capability) -> bytes:
        root_key = self.issuer.root_key_for(token.root_principal)
        sig = _hmac(root_key, token.token_id.encode())
        for entry in token.chain:
            sig = _hmac(sig, _canonical(entry))
        return sig

    def verify(self, token: Capability, context: dict) -> tuple[bool, str]:
        """
        context should include at least:
          action: str            e.g. "read"
          resource: str          e.g. "orders/12345"
        and optionally:
          workflow_id: str       for aggregation-budget scoping
          any fields referenced by AggregationBudgetCaveat.unit_field
          _now: float            override current time (for testing)
        """
        context = dict(context)
        context.setdefault("_now", time.time())

        # layer 1: cryptographic integrity
        expected_sig = self._recompute_signature(token)
        if not hmac_module.compare_digest(expected_sig, token.signature):
            reason = "signature mismatch: token chain does not match issuer root key (forged or tampered)"
            self._log(token, context, False, reason)
            return False, reason

        # explicit revocation
        if self.ledger.is_revoked(token.token_id):
            reason = "token explicitly revoked"
            self._log(token, context, False, reason)
            return False, reason

        # layer 2: policy -- every caveat must pass
        for caveat in token.caveats():
            ok, reason = caveat.check(context, self.ledger, token.token_id)
            if not ok:
                self._log(token, context, False, f"caveat '{caveat.kind}' failed: {reason}")
                return False, reason

        # success: record use-count and aggregation-budget consumption
        self.ledger.record_use(token.token_id)
        for caveat in token.caveats():
            if caveat.kind == "agg_budget":
                unit_value = context.get(caveat.unit_field)
                if unit_value is not None:
                    self.ledger.record_aggregation_use(
                        context.get("workflow_id", "default"), caveat.budget_name, unit_value
                    )

        self._log(token, context, True, "all caveats satisfied")
        return True, "all caveats satisfied"

    def _log(self, token: Capability, context: dict, allowed: bool, reason: str) -> None:
        self.audit_log.record(
            token_id=token.token_id,
            root_principal=token.root_principal,
            holder=token.holder(),
            delegation_chain=token.delegation_chain(),
            context=context,
            allowed=allowed,
            reason=reason,
        )
