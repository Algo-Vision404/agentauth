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
restrictions.

Changed in 1.1.0:
  * `key_id` travels with the token, so a root key can be rotated or marked
    compromised without invalidating chains already in circulation.
  * `to_compact()` / `from_compact()` add a base64url wire form
    (`agentauth1_...`) that survives being passed through argv, HTTP headers
    and MCP tool arguments without JSON escaping damage.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from .caveats import Caveat

DEFAULT_KEY_ID = "gen1"
COMPACT_PREFIX = "agentauth1_"


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
    key_id: str = DEFAULT_KEY_ID  # which generation of the root key seeded this chain

    # ---- construction -------------------------------------------------

    @classmethod
    def mint(
        cls,
        root_key: bytes,
        root_principal: str,
        to_principal: str,
        caveats: list[Caveat],
        key_id: str = DEFAULT_KEY_ID,
        ts: Optional[float] = None,
    ) -> "Capability":
        """Issue a brand-new token. Requires the root secret key."""
        token_id = str(uuid.uuid4())
        sig = _hmac(root_key, token_id.encode())
        chain: list[dict] = []

        delegation_entry = {
            "type": "delegation",
            "from": root_principal,
            "to": to_principal,
            "ts": time.time() if ts is None else ts,
        }
        sig = _hmac(sig, _canonical(delegation_entry))
        chain.append(delegation_entry)

        for caveat in caveats:
            entry = {"type": "caveat", **caveat.to_dict()}
            sig = _hmac(sig, _canonical(entry))
            chain.append(entry)

        return cls(
            token_id=token_id,
            root_principal=root_principal,
            chain=chain,
            signature=sig,
            key_id=key_id,
        )

    def delegate(
        self,
        from_principal: str,
        to_principal: str,
        additional_caveats: list[Caveat] | None = None,
        ts: Optional[float] = None,
    ) -> "Capability":
        """
        Attenuate: append a delegation record and zero or more NEW caveats.
        Requires no root secret -- just the current signature, which is
        exactly the property that lets agents delegate to sub-agents
        without ever holding issuer credentials.

        Note: this method is pure crypto and always succeeds. The *narrowing*
        guarantee comes from two other places: the attenuation guard
        (`agentauth.check_narrowing`) which refuses to issue a widening token
        in the first place, and the verifier, which recomputes the chain and
        rejects anything edited after the fact.
        """
        sig = self.signature
        chain = list(self.chain)

        delegation_entry = {
            "type": "delegation",
            "from": from_principal,
            "to": to_principal,
            "ts": time.time() if ts is None else ts,
        }
        sig = _hmac(sig, _canonical(delegation_entry))
        chain.append(delegation_entry)

        for caveat in (additional_caveats or []):
            entry = {"type": "caveat", **caveat.to_dict()}
            sig = _hmac(sig, _canonical(entry))
            chain.append(entry)

        return Capability(
            token_id=self.token_id,
            root_principal=self.root_principal,
            chain=chain,
            signature=sig,
            key_id=self.key_id,
        )

    # ---- inspection -----------------------------------------------------

    def caveats(self) -> list[Caveat]:
        return [Caveat.from_dict(e) for e in self.chain if e["type"] == "caveat"]

    def delegation_chain(self) -> list[dict]:
        return [e for e in self.chain if e["type"] == "delegation"]

    def holder(self) -> str:
        """The principal currently holding this token (last delegatee)."""
        return self.delegation_chain()[-1]["to"]

    def depth(self) -> int:
        """Number of delegation hops from the root principal (1 == first issue)."""
        return len(self.delegation_chain())

    def holders(self) -> list[str]:
        """root -> ... -> holder, the full authorization path."""
        chain = self.delegation_chain()
        return [chain[0]["from"], *[entry["to"] for entry in chain]]

    def caveats_by_kind(self, kind: str) -> list[Caveat]:
        return [c for c in self.caveats() if c.kind == kind]

    # ---- (de)serialization ------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "token_id": self.token_id,
            "root_principal": self.root_principal,
            "key_id": self.key_id,
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
            # tokens minted by <=1.0.0 have no key_id; they were always seeded
            # from the principal's first generation key.
            key_id=d.get("key_id", DEFAULT_KEY_ID),
        )

    def serialize(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def deserialize(cls, s: str) -> "Capability":
        return cls.from_dict(json.loads(s))

    # ---- compact wire form (new in 1.1.0) ---------------------------------

    def to_compact(self) -> str:
        """Base64url form, safe to move through argv/headers/MCP arguments."""
        payload = base64.urlsafe_b64encode(self.serialize().encode()).decode().rstrip("=")
        return f"{COMPACT_PREFIX}{payload}"

    @classmethod
    def from_compact(cls, s: str) -> "Capability":
        payload = s[len(COMPACT_PREFIX):]
        padded = payload + "=" * (-len(payload) % 4)
        return cls.deserialize(base64.urlsafe_b64decode(padded.encode()).decode())

    @classmethod
    def parse(cls, token: str | dict) -> "Capability":
        """Accept either wire form (JSON string, dict, or agentauth1_ compact)."""
        if isinstance(token, dict):
            return cls.from_dict(token)
        text = token.strip()
        if text.startswith(COMPACT_PREFIX):
            return cls.from_compact(text)
        return cls.deserialize(text)
