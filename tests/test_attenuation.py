"""The attenuation guard: refuse widening at issue time, and prove the chain
still protects the resource if someone bypasses it.
"""

from __future__ import annotations

import pytest

from agentauth import (
    ActionCaveat,
    AggregationBudgetCaveat,
    MaxUsesCaveat,
    ResourceCaveat,
    ThirdPartyCaveat,
    TimeWindowCaveat,
    Violation,
    WideningError,
    check_narrowing,
    glob_is_subset,
)
from agentauth.attenuation import NarrowingReport


def test_glob_subset_accepts_narrower_patterns():
    assert glob_is_subset("orders/42", "orders/*")
    assert glob_is_subset("orders/customer_42/17", "orders/*")
    assert glob_is_subset("orders/42", "orders/4?")
    assert glob_is_subset("orders/42", "orders/42")  # identical is a subset of itself


def test_glob_subset_rejects_widening_patterns():
    assert glob_is_subset("orders/*", "orders/customer_42/*") is False
    assert glob_is_subset("*", "orders/*") is False
    assert glob_is_subset("orders/*", "orders/42") is False


def test_glob_subset_is_conservative_for_partial_wildcards():
    # `?` is sampled with concrete characters, so a one-character wildcard that
    # *could* stand for something outside the parent is rejected rather than
    # silently allowed. Conservative by design: the HMAC chain is the real guard.
    assert glob_is_subset("orders/4?", "orders/4?") is True
    assert glob_is_subset("orders/4?", "orders/42") is False


def test_narrowing_report_is_truthy_when_valid():
    report = check_narrowing([ActionCaveat(("read", "write"))], [ActionCaveat(("read",))])
    assert report.ok is True
    assert bool(report) is True
    assert report.to_dict() == {"ok": True, "violations": []}
    report.raise_if_widening()  # must not raise


def test_added_verb_is_a_violation():
    report = check_narrowing([ActionCaveat(("read",))], [ActionCaveat(("read", "delete"))])
    assert report.ok is False
    assert report.violations[0].caveat == "action"
    assert "delete" in report.violations[0].detail


def test_widened_resource_pattern_is_a_violation():
    report = check_narrowing(
        [ResourceCaveat(("orders/customer_42/*",))], [ResourceCaveat(("orders/*",))]
    )
    assert report.ok is False
    assert report.violations[0].caveat == "resource"


def test_patterns_within_one_caveat_are_or_ed_but_separate_caveats_are_and_ed():
    # one parent caveat listing two patterns: the child may use either
    or_report = check_narrowing(
        [ResourceCaveat(("orders/42", "orders/43"))], [ResourceCaveat(("orders/43",))]
    )
    assert or_report.ok is True

    # two separate parent caveats: the child must fit inside both
    and_report = check_narrowing(
        [ResourceCaveat(("orders/*",)), ResourceCaveat(("orders/customer_42/*",))],
        [ResourceCaveat(("orders/customer_42/17",))],
    )
    assert and_report.ok is True
    widened = check_narrowing(
        [ResourceCaveat(("orders/*",)), ResourceCaveat(("orders/customer_42/*",))],
        [ResourceCaveat(("orders/43",))],
    )
    assert widened.ok is False


def test_raised_max_uses_and_budget_are_violations():
    uses = check_narrowing([MaxUsesCaveat(5)], [MaxUsesCaveat(50)])
    assert uses.ok is False and uses.violations[0].caveat == "max_uses"

    budget = check_narrowing(
        [AggregationBudgetCaveat("touched", 2, "customer_id")],
        [AggregationBudgetCaveat("touched", 10, "customer_id")],
    )
    assert budget.ok is False and budget.violations[0].caveat == "agg_budget"

    # lowering a budget is a legitimate narrowing
    assert check_narrowing(
        [AggregationBudgetCaveat("touched", 10, "customer_id")],
        [AggregationBudgetCaveat("touched", 2, "customer_id")],
    ).ok


def test_extended_time_window_is_a_violation():
    report = check_narrowing(
        [TimeWindowCaveat(100.0, 200.0)], [TimeWindowCaveat(0.0, 500.0)]
    )
    assert report.ok is False
    assert report.violations[0].caveat == "time_window"
    assert check_narrowing(
        [TimeWindowCaveat(100.0, 200.0)], [TimeWindowCaveat(120.0, 180.0)]
    ).ok


def test_claim_and_third_party_caveats_are_always_a_narrowing():
    report = check_narrowing(
        [ActionCaveat(("read",))],
        [
            ThirdPartyCaveat("hr-directory", "employee alice", "n1"),
        ],
    )
    assert report.ok is True


def test_raise_if_widening_gives_the_details():
    report = check_narrowing([ActionCaveat(("read",))], [ActionCaveat(("read", "delete"))])
    with pytest.raises(WideningError) as excinfo:
        report.raise_if_widening()
    assert "delete" in str(excinfo.value)


def test_violation_serializes_for_api_responses():
    violation = Violation("action", "adds action(s) ['delete']")
    assert violation.to_dict() == {"caveat": "action", "detail": "adds action(s) ['delete']"}
    assert NarrowingReport([violation]).to_dict()["violations"][0]["caveat"] == "action"
