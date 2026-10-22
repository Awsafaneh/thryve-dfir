from __future__ import annotations

import re
from typing import Any, Iterable


def _value_at(event: dict[str, Any], field: str) -> Any:
    if field in event:
        return event[field]
    return event.get("data", {}).get(field)


def _matches(actual: Any, operator: str, expected: Any) -> bool:
    if actual is None:
        return False
    if operator == "equals":
        return str(actual).casefold() == str(expected).casefold()
    if operator == "contains":
        return str(expected).casefold() in str(actual).casefold()
    if operator == "in":
        candidates = expected if isinstance(expected, list) else [expected]
        return str(actual).casefold() in {str(item).casefold() for item in candidates}
    if operator == "regex":
        try:
            return bool(re.search(str(expected), str(actual)))
        except re.error:
            return False
    return False


def evaluate(events: Iterable[dict[str, Any]], rules: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    rule_list = list(rules)
    for event in events:
        for rule in rule_list:
            if rule.get("source") not in {event.get("source"), event.get("event_type")}:
                continue
            if not _matches(_value_at(event, str(rule.get("field", ""))), str(rule.get("operator", "equals")), rule.get("value")):
                continue
            alerts.append({
                "event_id": event.get("id"),
                "rule_id": rule["id"],
                "title": rule["title"],
                "severity": rule.get("severity", "medium"),
                "mitre": rule.get("mitre"),
                "source": event.get("source", "unknown"),
                "evidence": {
                    "timestamp": event.get("timestamp"),
                    "message": event.get("message"),
                    "host": event.get("host"),
                    "data": event.get("data", {}),
                },
            })
    return alerts
