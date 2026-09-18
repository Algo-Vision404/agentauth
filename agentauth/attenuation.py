"""
attenuation.py -- NEW in 1.1.0. The proactive half of the "delegation can only
narrow" guarantee.

The *enforcement* is cryptographic and lives in the chain itself: because every
caveat in a token is evaluated, appending a caveat can never widen access, and
any attempt to delete or edit one is caught when the verifier recomputes the
chain. What was missing is feedback and accountability:

  * a delegating agent should be told "that would widen, here is what and why"
    at issue time instead of getting a puzzling 403 three hops later;
  * an operator should see *attempts*, not just denials. Every refusal can be
    written to the audit log as `widening_rejected`.

So this module is a convenience + observability layer, not the security
boundary. If it is bypassed, the HMAC chain still protects the resource.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from itertools import islice
from typing import Any, Iterable, Iterator, Optional

from .caveats import (
    ActionCaveat,
    AggregationBudgetCaveat,
    Caveat,
    MaxUsesCaveat,
    ResourceCaveat,
    TimeWindowCaveat,
)

# Strings used to sample what a glob pattern can generate. Python's fnmatch
# `*` crosses "/", so sampling has to include multi-segment values too.
_PROBES = ("", "a", "ab", "9", "customer_42", "orders/customer_42/17", "xx/yy", "zz")


class WideningError(ValueError):
    """Raised when a delegation would broaden the parent token's authority."""


@dataclass
class Violation:
    caveat: str
    detail: str

    def to_dict(self) -> dict:
        return {"caveat": self.caveat, "detail": self.detail}


@dataclass
class NarrowingReport:
    violations: list[Violation] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations

    def raise_if_widening(self) -> None:
        if self.violations:
            raise WideningError("; ".join(v.detail for v in self.violations))

    def to_dict(self) -> dict:
        return {"ok": self.ok, "violations": [v.to_dict() for v in self.violations]}

    def __bool__(self) -> bool:  # truthy when the delegation is a valid narrowing
        return self.ok


def glob_is_subset(child: str, parent: str, limit: int = 400) -> bool:
    """True when every string the child pattern can generate is also matched
    by the parent pattern.

    Sampling-based and therefore conservative-in-practice rather than complete
    (a true glob-language containment check is overkill for this use), which is
    the right trade: false negatives are caught by the HMAC chain at verify time
    and false positives would only reject a legitimate narrow delegation.
    """
    child, parent = child.strip(), parent.strip()
    if child == parent:
        return True
    # a child that can generate anything outside the parent's literal prefix
    # cannot be contained unless the parent is at least as permissive
    if "*" not in parent and "*" in child:
        return False
    for sample in islice(_expansions(child), limit):
        if not fnmatch.fnmatch(sample, parent):
            return False
    return True


def _expansions(pattern: str) -> Iterator[str]:
    """Generate sample strings for a glob pattern."""
    parts = _split_pattern(pattern)
    yield from _expand(parts)


def _split_pattern(pattern: str) -> list[str]:
    out: list[str] = []
    buffer = ""
    for char in pattern:
        if char in "*?":
            if buffer:
                out.append(buffer)
                buffer = ""
            out.append(char)
        else:
            buffer += char
    if buffer:
        out.append(buffer)
    return out


def _expand(parts: list[str]) -> Iterator[str]:
    if not parts:
        yield ""
        return
    head, rest = parts[0], parts[1:]
    if head == "*":
        for probe in _PROBES:
            for tail in _expand(rest):
                yield probe + tail
    elif head == "?":
        for probe in ("a", "9"):
            for tail in _expand(rest):
                yield probe + tail
    else:
        for tail in _expand(rest):
            yield head + tail


def check_narrowing(parent_caveats: Iterable[Caveat], added_caveats: Iterable[Caveat]) -> NarrowingReport:
    """Compare a delegation's added caveats against the parent token's caveats.

    Semantics mirrored from the verifier: patterns/verbs *inside* one caveat are
    OR-ed, separate caveats of the same kind are AND-ed. So each added caveat is
    checked against every same-kind parent caveat.
    """
    parents = list(parent_caveats)
    report = NarrowingReport()

    for added in added_caveats:
        if isinstance(added, ActionCaveat):
            for parent in _of_kind(parents, ActionCaveat):
                extra = [a for a in added.allowed_actions if a not in parent.allowed_actions]
                if extra:
                    report.violations.append(Violation(
                        "action",
                        f"adds action(s) {extra} that the parent token never held "
                        f"(parent allows {list(parent.allowed_actions)})",
                    ))

        elif isinstance(added, ResourceCaveat):
            for parent in _of_kind(parents, ResourceCaveat):
                outside = [
                    pattern for pattern in added.allowed_patterns
                    if not any(glob_is_subset(pattern, allowed) for allowed in parent.allowed_patterns)
                ]
                if outside:
                    report.violations.append(Violation(
                        "resource",
                        f"patterns {outside} are not covered by the parent patterns "
                        f"{list(parent.allowed_patterns)}",
                    ))

        elif isinstance(added, TimeWindowCaveat):
            for parent in _of_kind(parents, TimeWindowCaveat):
                if added.not_before < parent.not_before or added.not_after > parent.not_after:
                    report.violations.append(Violation(
                        "time_window",
                        f"window [{added.not_before}, {added.not_after}] extends the parent window "
                        f"[{parent.not_before}, {parent.not_after}]",
                    ))

        elif isinstance(added, MaxUsesCaveat):
            for parent in _of_kind(parents, MaxUsesCaveat):
                if added.max_uses > parent.max_uses:
                    report.violations.append(Violation(
                        "max_uses",
                        f"max_uses {added.max_uses} exceeds the parent cap {parent.max_uses}",
                    ))

        elif isinstance(added, AggregationBudgetCaveat):
            for parent in _of_kind(parents, AggregationBudgetCaveat):
                if parent.budget_name == added.budget_name and added.max_units > parent.max_units:
                    report.violations.append(Violation(
                        "agg_budget",
                        f"budget '{added.budget_name}' raised from {parent.max_units} to {added.max_units}",
                    ))

        # claim / third_party caveats can only ever restrict, so they are always
        # a valid narrowing.

    return report


def _of_kind(caveats: list[Caveat], kind: type) -> list[Any]:
    return [c for c in caveats if isinstance(c, kind)]
