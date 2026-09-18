"""
discharge.py -- NEW in 1.1.0. Third-party caveats and the discharges that
satisfy them. This was the biggest missing macaroon feature in the previous
version, and it is the piece that makes the system usable with external policy
engines instead of only self-contained predicates.

A token carries `ThirdPartyCaveat(location="hr-directory", predicate=...)`.
Nobody can satisfy it locally. The named service mints a *discharge token*,
keyed by

    discharge_key = HMAC(service_root_key, f"{parent_token_id}:{nonce}")

so the discharge is cryptographically bound to exactly one parent token and one
caveat instance: it cannot be replayed onto a different token, and a second
caveat with a different nonce cannot reuse the first discharge.

A discharge can also carry its own caveats -- most usefully a ClaimCaveat, which
is how "yes, but only while acting on behalf of alice" is expressed:

    discharge = mint_discharge(
        service_root_key=hr_key,
        location="hr-directory",
        parent_token_id=token.token_id,
        nonce=caveat.nonce,
        predicate="the caller acts on behalf of employee alice",
        claims={"on_behalf_of": "alice"},
    )
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from .caveats import Caveat, ClaimCaveat, ThirdPartyCaveat


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()


def derive_discharge_key(service_root_key: bytes, parent_token_id: str, nonce: str) -> bytes:
    """The per-caveat key a discharge service must use.

    Deriving instead of reusing the service's root key means one leaked discharge
    cannot be repurposed, and it binds the discharge to a single token + caveat.
    """
    return _hmac(service_root_key, f"{parent_token_id}:{nonce}".encode())


@dataclass
class DischargeToken:
    discharge_id: str
    location: str
    parent_token_id: str
    nonce: str
    chain: list[dict]
    signature: bytes
    predicate: str = ""

    # ---- inspection ---------------------------------------------------

    def caveats(self) -> list[Caveat]:
        return [Caveat.from_dict(e) for e in self.chain if e["type"] == "caveat"]

    def claims(self) -> dict[str, tuple[str, ...]]:
        """Claims this discharge attests, e.g. {"on_behalf_of": ("alice",)}."""
        return {
            c.claim_field: c.allowed_values
            for c in self.caveats()
            if isinstance(c, ClaimCaveat)
        }

    # ---- (de)serialization ---------------------------------------------

    def to_dict(self) -> dict:
        return {
            "discharge_id": self.discharge_id,
            "location": self.location,
            "parent_token_id": self.parent_token_id,
            "nonce": self.nonce,
            "predicate": self.predicate,
            "chain": self.chain,
            "signature": self.signature.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DischargeToken":
        return cls(
            discharge_id=d["discharge_id"],
            location=d["location"],
            parent_token_id=d["parent_token_id"],
            nonce=d["nonce"],
            chain=d["chain"],
            signature=bytes.fromhex(d["signature"]),
            predicate=d.get("predicate", ""),
        )

    def serialize(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def deserialize(cls, s: str) -> "DischargeToken":
        return cls.from_dict(json.loads(s))

    @classmethod
    def parse(cls, value: "DischargeToken | dict | str") -> "DischargeToken":
        if isinstance(value, DischargeToken):
            return value
        if isinstance(value, dict):
            return cls.from_dict(value)
        return cls.deserialize(value)


def mint_discharge(
    service_root_key: bytes,
    location: str,
    parent_token_id: str,
    nonce: str,
    predicate: str = "",
    claims: Optional[dict[str, str]] = None,
    caveats: Optional[list[Caveat]] = None,
    ts: Optional[float] = None,
) -> DischargeToken:
    """Issue a discharge for one caveat instance of one parent token."""
    discharge_id = str(uuid.uuid4())
    key = derive_discharge_key(service_root_key, parent_token_id, nonce)
    sig = _hmac(key, discharge_id.encode())
    chain: list[dict] = []

    issued = {"type": "claim", "kind": "claim", "claim_field": "_discharged_for",
              "allowed_values": [parent_token_id]}
    sig = _hmac(sig, _canonical(issued))
    chain.append(issued)

    for claim_field, claim_value in (claims or {}).items():
        entry = {
            "type": "caveat",
            "kind": "claim",
            "claim_field": claim_field,
            "allowed_values": [str(claim_value)],
        }
        sig = _hmac(sig, _canonical(entry))
        chain.append(entry)

    for caveat in (caveats or []):
        if isinstance(caveat, ThirdPartyCaveat):
            raise ValueError("a discharge cannot itself require another discharge")
        entry = {"type": "caveat", **caveat.to_dict()}
        sig = _hmac(sig, _canonical(entry))
        chain.append(entry)

    return DischargeToken(
        discharge_id=discharge_id,
        location=location,
        parent_token_id=parent_token_id,
        nonce=nonce,
        chain=chain,
        signature=sig,
        predicate=predicate,
    )


def verify_discharge(
    discharge: "DischargeToken | dict | str",
    parent_token_id: str,
    service_root_key: bytes,
    context: Optional[dict] = None,
    ledger: Any = None,
    now: Optional[float] = None,
) -> tuple[bool, str]:
    """Check a discharge: bound to this token, correctly signed, conditions met.

    Returns (ok, reason) with an empty reason on success, matching the
    verify(token, context) convention used elsewhere in the library.
    """
    try:
        token = DischargeToken.parse(discharge)
    except Exception as exc:  # malformed payloads must not raise at the boundary
        return False, f"malformed discharge: {exc}"

    if token.parent_token_id != parent_token_id:
        return False, (
            f"discharge {token.discharge_id} was issued for a different token "
            f"({token.parent_token_id})"
        )

    key = derive_discharge_key(service_root_key, token.parent_token_id, token.nonce)
    sig = _hmac(key, token.discharge_id.encode())
    for entry in token.chain:
        sig = _hmac(sig, _canonical(entry))
    if not hmac.compare_digest(sig, token.signature):
        return False, f"discharge {token.discharge_id} signature invalid (forged or tampered)"

    if ledger is None:
        from .ledger import RevocationLedger as _Ledger  # local import avoids a cycle
        ledger = _Ledger()

    check_context = dict(context or {})
    if now is not None:
        check_context["_now"] = now

    for caveat in token.caveats():
        ok, reason = caveat.check(check_context, ledger, token.discharge_id)
        if not ok:
            return False, f"discharge condition failed: {reason}"

    return True, ""


def discharge_summary(discharge: "DischargeToken | dict | str") -> dict:
    token = DischargeToken.parse(discharge)
    return {
        "discharge_id": token.discharge_id,
        "location": token.location,
        "parent_token_id": token.parent_token_id,
        "nonce": token.nonce,
        "predicate": token.predicate,
        "claims": {k: list(v) for k, v in token.claims().items() if not k.startswith("_")},
    }
