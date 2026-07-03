"""
Issuer: the only party that holds root secret keys. Mints brand-new
tokens. A verifier trusting this issuer must be given the same root keys
out of band (e.g. both run inside the same trust boundary, or the
verifier calls back to the issuer -- this MVP keeps them in the same
process for simplicity; seeROADMAP in README for a real multi-party split).
"""

from __future__ import annotations

import os
from typing import Optional

from .caveats import Caveat
from .token import Capability


class Issuer:
    def __init__(self):
        self._root_keys: dict[str, bytes] = {}

    def register_principal(self, principal_id: str, root_key: Optional[bytes] = None) -> bytes:
        """Create (or import) a root secret for a principal (e.g. a human
        user, or a top-level service account). Returns the key so it can
        be shared with a trusted, out-of-process verifier if needed."""
        key = root_key or os.urandom(32)
        self._root_keys[principal_id] = key
        return key

    def root_key_for(self, principal_id: str) -> bytes:
        if principal_id not in self._root_keys:
            raise KeyError(f"Unknown principal: {principal_id}")
        return self._root_keys[principal_id]

    def mint(self, root_principal: str, to_principal: str, caveats: list[Caveat]) -> Capability:
        """Issue a new capability token: root_principal authorizes
        to_principal to act, subject to the given caveats."""
        root_key = self.root_key_for(root_principal)
        return Capability.mint(root_key, root_principal, to_principal, caveats)
