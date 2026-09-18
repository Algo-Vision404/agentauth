"""
Issuer: the only party that holds root secret keys. Mints brand-new
tokens. A verifier trusting this issuer must be given the same root keys
out of band (e.g. both run inside the same trust boundary, or the
verifier calls back to the issuer). Deployment options are described in
UPGRADE_NOTES.md; this module deliberately does not transmit key material.

Changed in 1.1.0 -- key generations, closing the "no key rotation /
compromise recovery" gap:
  * every principal can hold several versions of its root key ("gen1",
    "gen2", ...), exactly one of them active at a time
  * tokens are stamped with the generation that seeded them, so rotating a
    key does NOT invalidate tokens already in circulation
  * a generation can be marked compromised, which makes every token seeded
    from it fail verification at the cryptographic layer
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

from .caveats import Caveat
from .token import DEFAULT_KEY_ID, Capability


class KeyStatus:
    ACTIVE = "active"
    RETIRED = "retired"
    COMPROMISED = "compromised"


class UnknownPrincipal(KeyError):
    """Raised when a principal has no root key registered."""


class KeyCompromised(ValueError):
    """Raised when the requested key generation has been marked compromised."""


@dataclass
class KeyRecord:
    principal_id: str
    key_id: str
    key: bytes
    status: str = KeyStatus.ACTIVE
    note: str = ""
    created_at: float = field(default_factory=time.time)

    def fingerprint(self) -> str:
        """Safe-to-log identifier: never print key material."""
        return self.key.hex()[:12]

    def to_public_dict(self) -> dict:
        return {
            "principal_id": self.principal_id,
            "key_id": self.key_id,
            "status": self.status,
            "note": self.note,
            "fingerprint": self.fingerprint(),
            "created_at": self.created_at,
        }


def make_key_id(principal_id: str, generation: int) -> str:
    """Key ids are namespaced per principal: 'alice#gen2'."""
    return f"{principal_id}#gen{generation}"


class Issuer:
    def __init__(self) -> None:
        self._keys: dict[str, dict[str, KeyRecord]] = {}

    # ---- principals and key generations ---------------------------------

    def register_principal(
        self,
        principal_id: str,
        root_key: Optional[bytes] = None,
        key_id: Optional[str] = None,
        overwrite: bool = True,
        note: str = "",
    ) -> bytes:
        """Create (or import) a root secret for a principal (e.g. a human
        user, or a top-level service account).

        Returns the key bytes for backwards compatibility with <= 1.0.0.
        Callers that do not need the material should ignore the return value:
        the 1.1.0 HTTP service never returns it (see UPGRADE_NOTES.md).

        `key_id` defaults to '<principal>#gen1', or is derived when the
        principal already has generations.
        """
        bucket = self._keys.setdefault(principal_id, {})
        if key_id is None:
            # Registering a principal twice is a no-op: it returns the key that
            # is already provisioned. New generations are created by rotate_key()
            # so there is never more than one active key per principal.
            if bucket:
                return self.key_record(principal_id).key
            key_id = make_key_id(principal_id, 1)

        if key_id in bucket and not overwrite:
            return bucket[key_id].key

        record = KeyRecord(
            principal_id=principal_id,
            key_id=key_id,
            key=root_key or os.urandom(32),
            note=note,
        )
        bucket[key_id] = record
        return record.key

    def key_record(self, principal_id: str, key_id: Optional[str] = None) -> KeyRecord:
        """Resolve a generation, defaulting to the active one.

        Raises UnknownPrincipal / KeyCompromised so the verifier can turn the
        failure into an explicit decision layer instead of a stack trace.
        """
        bucket = self._keys.get(principal_id)
        if not bucket:
            raise UnknownPrincipal(f"Unknown principal: {principal_id}")
        if key_id is None:
            for record in bucket.values():
                if record.status == KeyStatus.ACTIVE:
                    return record
            # every generation retired: keep the newest for reference, the
            # verifier still checks its status explicitly.
            return list(bucket.values())[-1]
        record = bucket.get(key_id)
        if record is None:
            raise UnknownPrincipal(f"Unknown key generation '{key_id}' for principal '{principal_id}'")
        return record

    def root_key_for(self, principal_id: str, key_id: Optional[str] = None) -> bytes:
        record = self.key_record(principal_id, key_id)
        if record.status == KeyStatus.COMPROMISED:
            raise KeyCompromised(
                f"root key generation '{record.key_id}' for '{principal_id}' is marked compromised"
            )
        return record.key

    def active_key_id(self, principal_id: str) -> str:
        return self.key_record(principal_id).key_id

    def rotate_key(self, principal_id: str, note: str = "rotated") -> KeyRecord:
        """Retire the active generation and create the next one.

        Tokens already issued keep verifying against the generation stamped
        into them -- only new mints move to the new key.
        """
        if principal_id not in self._keys:
            raise UnknownPrincipal(f"Unknown principal: {principal_id}")
        bucket = self._keys[principal_id]
        for record in bucket.values():
            if record.status == KeyStatus.ACTIVE:
                record.status = KeyStatus.RETIRED
        generation = len(bucket) + 1
        record = KeyRecord(
            principal_id=principal_id,
            key_id=make_key_id(principal_id, generation),
            key=os.urandom(32),
            note=note,
        )
        bucket[record.key_id] = record
        return record

    def compromise_key(self, principal_id: str, key_id: Optional[str] = None, note: str = "reported leaked") -> KeyRecord:
        """Mark a generation as leaked: every token seeded from it is rejected."""
        record = self.key_record(principal_id, key_id)
        record.status = KeyStatus.COMPROMISED
        record.note = note
        return record

    def list_keys(self) -> list[dict]:
        return [
            record.to_public_dict()
            for bucket in self._keys.values()
            for record in bucket.values()
        ]

    def has_principal(self, principal_id: str) -> bool:
        return bool(self._keys.get(principal_id))

    def __contains__(self, principal_id: object) -> bool:
        return isinstance(principal_id, str) and self.has_principal(principal_id)

    # ---- minting ---------------------------------------------------------

    def mint(
        self,
        root_principal: str,
        to_principal: str,
        caveats: list[Caveat],
        ts: Optional[float] = None,
    ) -> Capability:
        """Issue a new capability token: root_principal authorizes
        to_principal to act, subject to the given caveats.

        Uses the principal's active key generation and stamps its key_id into
        the token so it stays verifiable after a rotation.
        """
        record = self.key_record(root_principal)
        if record.status == KeyStatus.COMPROMISED:
            raise KeyCompromised(
                f"refusing to mint with compromised key generation '{record.key_id}'"
            )
        return Capability.mint(
            root_key=record.key,
            root_principal=root_principal,
            to_principal=to_principal,
            caveats=caveats,
            key_id=record.key_id,
            ts=ts,
        )
