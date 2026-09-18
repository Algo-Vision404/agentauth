"""
policy.py -- NEW in 1.1.0. Closes the "no policy language" gap: caveats are
Python objects attached to a token, which is fine for what a *token* may say,
but resource owners need rules that travel with the *resource* (an MCP tool, a
service endpoint) and are versioned independently of any token.

Both halves are evaluated at the same boundary and AND together, so a token
holder cannot negotiate away a server-side rule, and an operator can tighten a
fleet-wide rule without re-minting anything.

The AST is deliberately tiny JSON -- no eval, no parser:

    {"op": "and", "args": [
        {"op": "in", "field": "status", "value": ["pending", "shipped"]},
        {"op": "or", "args": [
            {"op": "nin", "field": "status", "value": ["cancelled", "refunded"]},
            {"op": "exists", "field": "approval_id"}]},
        {"op": "lte", "field": "order.total", "value": 5000}]}

Operators
    logical     and, or, not
    comparison  eq, ne, gt, gte, lt, lte, in, nin, matches (glob), exists

`field` is a dotted path into the call context, e.g. "order.customer_id".
"""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional

LOGICAL_OPS = frozenset({"and", "or", "not"})
COMPARISON_OPS = frozenset({"eq", "ne", "gt", "gte", "lt", "lte", "in", "nin", "matches", "exists"})
ALL_OPS = LOGICAL_OPS | COMPARISON_OPS


class PolicyError(ValueError):
    """Malformed or unsupported policy AST."""


def resolve_field(context: dict, path: str) -> Any:
    """Dotted lookup: resolve_field(ctx, "order.customer_id")."""
    current: Any = context
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def compare(op: str, left: Any, right: Any) -> bool:
    if op == "eq":
        return left is not None and str(left) == str(right)
    if op == "ne":
        return left is not None and str(left) != str(right)
    if op in ("gt", "gte", "lt", "lte"):
        left_number = _numeric(left)
        right_number = _numeric(right)
        # a bound must never be satisfied by a missing or non-numeric value:
        # fail closed, since these guards exist to cap things.
        if left_number is None or right_number is None:
            return False
        if op == "gt":
            return left_number > right_number
        if op == "gte":
            return left_number >= right_number
        if op == "lt":
            return left_number < right_number
        return left_number <= right_number
    if op == "in":
        return isinstance(right, (list, tuple, set)) and str(left) in {str(v) for v in right}
    if op == "nin":
        return isinstance(right, (list, tuple, set)) and str(left) not in {str(v) for v in right}
    if op == "matches":
        return fnmatch.fnmatch(str(left), str(right))
    raise PolicyError(f"unsupported comparison operator: {op!r}")


def _numeric(value: Any) -> Optional[float]:
    """None for missing/non-numeric values -- never coerced to 0."""
    if isinstance(value, bool) or value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def validate_ast(node: Any, path: str = "$") -> None:
    """Reject unknown operators/fields at load time instead of at decision time."""
    if not isinstance(node, dict):
        raise PolicyError(f"policy node at {path} must be an object, got {type(node).__name__}")
    op = node.get("op")
    if op not in ALL_OPS:
        raise PolicyError(f"unknown policy operator {op!r} at {path} (allowed: {sorted(ALL_OPS)})")

    if op in LOGICAL_OPS:
        args = node.get("args")
        if not isinstance(args, list) or not args:
            raise PolicyError(f"'{op}' at {path} requires a non-empty 'args' list")
        for index, child in enumerate(args):
            validate_ast(child, f"{path}.args[{index}]")
        return

    if op == "exists":
        if not isinstance(node.get("field"), str):
            raise PolicyError(f"'exists' at {path} requires a string 'field'")
        return

    if not isinstance(node.get("field"), str):
        raise PolicyError(f"'{op}' at {path} requires a string 'field'")
    if op in {"in", "nin"} and not isinstance(node.get("value"), (list, tuple, set)):
        raise PolicyError(f"'{op}' at {path} requires a list 'value'")
    if op in {"gt", "gte", "lt", "lte"} and not isinstance(node.get("value"), (int, float)):
        raise PolicyError(f"'{op}' at {path} requires a numeric 'value'")


def eval_ast(node: dict, context: dict) -> bool:
    op = node["op"]
    if op == "and":
        return all(eval_ast(child, context) for child in node["args"])
    if op == "or":
        return any(eval_ast(child, context) for child in node["args"])
    if op == "not":
        return not any(eval_ast(child, context) for child in node["args"])
    if op == "exists":
        value = resolve_field(context, node["field"])
        return value is not None and value != ""
    return compare(op, resolve_field(context, node["field"]), node.get("value"))


def render_ast(node: dict) -> str:
    """Human-readable form, used in denial reasons and dashboards."""
    op = node["op"]
    if op == "and":
        return "(" + " AND ".join(render_ast(c) for c in node["args"]) + ")"
    if op == "or":
        return "(" + " OR ".join(render_ast(c) for c in node["args"]) + ")"
    if op == "not":
        return "NOT (" + " AND ".join(render_ast(c) for c in node["args"]) + ")"
    if op == "exists":
        return f"{node['field']} IS PRESENT"
    if op in {"in", "nin"}:
        values = ", ".join(str(v) for v in node["value"])
        keyword = "IN" if op == "in" else "NOT IN"
        return f"{node['field']} {keyword} [{values}]"
    return f"{node['field']} {op.upper()} {json.dumps(node.get('value'))}"


@dataclass
class Policy:
    """A declarative rule set evaluated against the call context."""
    ast: dict
    name: str = ""

    def __post_init__(self) -> None:
        validate_ast(self.ast)

    # ---- constructors -----------------------------------------------------

    @classmethod
    def from_dict(cls, ast: dict, name: str = "") -> "Policy":
        return cls(ast=ast, name=name)

    @classmethod
    def from_json(cls, text: str, name: str = "") -> "Policy":
        return cls(ast=json.loads(text), name=name)

    @classmethod
    def from_file(cls, path: str) -> "Policy":
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if isinstance(payload, dict) and "ast" in payload:
            return cls(ast=payload["ast"], name=payload.get("name", os.path.basename(path)))
        return cls(ast=payload, name=os.path.basename(path))

    # ---- evaluation -------------------------------------------------------

    def evaluate(self, context: dict) -> tuple[bool, str]:
        """Returns (allowed, reason). Reason is empty when allowed."""
        if eval_ast(self.ast, context):
            return True, ""
        label = f"{self.name}: " if self.name else ""
        return False, f"policy denied: {label}{render_ast(self.ast)} was not satisfied by the call context"

    def allows(self, context: dict) -> bool:
        return self.evaluate(context)[0]

    def __call__(self, context: dict) -> bool:
        return self.allows(context)

    # ---- introspection ----------------------------------------------------

    def render(self) -> str:
        return render_ast(self.ast)

    def to_dict(self) -> dict:
        return {"name": self.name, "ast": self.ast, "rendered": self.render()}


def policy_from(value: "Policy | dict | str | None") -> Optional[Policy]:
    """Accept a Policy, an AST dict, a JSON string, or None."""
    if value is None:
        return None
    if isinstance(value, Policy):
        return value
    if isinstance(value, dict):
        return Policy.from_dict(value)
    if isinstance(value, str):
        text = value.strip()
        return Policy.from_file(text) if os.path.exists(text) else Policy.from_json(text)
    raise PolicyError(f"cannot build a Policy from {type(value).__name__}")
