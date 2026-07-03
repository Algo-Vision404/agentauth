"""
Capability tokens.

Design (macaroon-family): the token's signature is an HMAC chain --
sig_0 = HMAC(root_key, token_id); sig_i = HMAC(sig_{i-1}, entry_i_bytes).
Anyone holding sig_{i-1} can compute sig_i by appending an entry -- so
delegation needs no access to the root secret -- but nobody can compute a
*valid* chain for an entry they didn't actually append, because that would
require inverting the HMAC. This is what makes attenuation-only-narrowing
enforceable: a verifier who recomputes the chain from the root key will
get a signature mismatch if any entry was removed, reordered, or forged.

Each chain entry is either a caveat (a restriction) or a delegation record
(who handed this token to whom, and when) -- both are folded into the same
HMAC chain, so the full provenance trail is tamper-evident, not just the
restrictions. This directly targets the gap named in Tallam 2026: "no
deployed protocol can cryptographically prove which principal authorized
which agent to perform which action at the third or fourth hop."
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from .caveats import Caveat


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class Capability:
    token_id: str
    root_principal: str          # the principal whose root_key seeded this chain (the ultimate issuer)
    chain: list[dict]            # ordered list of {"type": "delegation"|"caveat", ...}
    signature: bytes             # current HMAC chain value

    # ---- construction -------------------------------------------------

    @classmethod
    def mint(cls, root_key: bytes, root_principal: str, to_principal: str, caveats: list[Caveat]) -> "Capability":
        """Issue a brand-new token. Requires the root secret key."""
        token_id = str(uuid.uuid4())
        sig = _hmac(root_key, token_id.encode())
        chain: list[dict] = []

        delegation_entry = {"type": "delegation", "from": root_principal, "to": to_principal, "ts": time.time()}
        sig = _hmac(sig, _canonical(delegation_entry))
        chain.append(delegation_entry)

        for caveat in caveats:
            entry = {"type": "caveat", **caveat.to_dict()}
            sig = _hmac(sig, _canonical(entry))
            chain.append(entry)

        return cls(token_id=token_id, root_principal=root_principal, chain=chain, signature=sig)

    def delegate(self, from_principal: str, to_principal: str, additional_caveats: list[Caveat] | None = None) -> "Capability":
        """
        Attenuate: append a delegation record and zero or more NEW caveats.
        Requires no root secret -- just the current signature, which is
        exactly the property that lets agents delegate to sub-agents
        without ever holding issuer credentials.
        """
        sig = self.signature
        chain = list(self.chain)

        delegation_entry = {"type": "delegation", "from": from_principal, "to": to_principal, "ts": time.time()}
        sig = _hmac(sig, _canonical(delegation_entry))
        chain.append(delegation_entry)

        for caveat in (additional_caveats or []):
            entry = {"type": "caveat", **caveat.to_dict()}
            sig = _hmac(sig, _canonical(entry))
            chain.append(entry)

        return Capability(token_id=self.token_id, root_principal=self.root_principal, chain=chain, signature=sig)

    # ---- inspection -----------------------------------------------------

    def caveats(self) -> list[Caveat]:
        return [Caveat.from_dict(e) for e in self.chain if e["type"] == "caveat"]

    def delegation_chain(self) -> list[dict]:
        return [e for e in self.chain if e["type"] == "delegation"]

    def holder(self) -> str:
        """The principal currently holding this token (last delegatee)."""
        return self.delegation_chain()[-1]["to"]

    # ---- (de)serialization ------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "token_id": self.token_id,
            "root_principal": self.root_principal,
            "chain": self.chain,
            "signature": self.signature.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Capability":
        return cls(
            token_id=d["token_id"],
            root_principal=d["root_principal"],
            chain=d["chain"],
            signature=bytes.fromhex(d["signature"]),
        )

    def serialize(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def deserialize(cls, s: str) -> "Capability":
        return cls.from_dict(json.loads(s))
