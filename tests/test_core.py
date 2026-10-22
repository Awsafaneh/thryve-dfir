from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aegis.database import Database
from aegis.detectors import evaluate
from app import forensic_tools


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "test.db")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_event_deduplication_and_search(self) -> None:
        event = {
            "timestamp": "2026-10-22T10:00:00+00:00",
            "source": "process",
            "event_type": "process",
            "severity": "info",
            "host": "test-host",
            "message": "powershell.exe (PID 42)",
            "data": {"name": "powershell.exe", "pid": 42, "command_line": "powershell -enc AAA"},
        }
        self.assertEqual(len(self.db.insert_events([event, event])), 1)
        result = self.db.list_events(query="powershell")
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["data"]["pid"], 42)

    def test_rule_seed_toggle(self) -> None:
        rule = {
            "id": "TEST-1", "title": "Test", "description": "", "severity": "high",
            "source": "process", "field": "command_line", "operator": "contains", "value": "-enc",
            "mitre": "T1059.001", "enabled": True,
        }
        self.db.seed_rules([rule])
        self.assertEqual(len(self.db.enabled_rules()), 1)
        self.assertTrue(self.db.toggle_rule("TEST-1", False))
        self.assertEqual(self.db.enabled_rules(), [])

    def test_case_round_trip(self) -> None:
        case = self.db.create_case("Case 1", "Description", "high")
        self.assertTrue(self.db.add_case_item(case["id"], "note", None, "Initial note"))
        loaded = self.db.get_case(case["id"])
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["items"][0]["note"], "Initial note")


class DetectorTests(unittest.TestCase):
    def test_regex_detection(self) -> None:
        events = [{
            "id": 9,
            "timestamp": "2026-10-22T10:00:00+00:00",
            "source": "process",
            "event_type": "process",
            "message": "PowerShell",
            "data": {"command_line": "powershell.exe -EncodedCommand AAA"},
        }]
        rules = [{
            "id": "P1", "title": "Encoded PowerShell", "severity": "high", "source": "process",
            "field": "command_line", "operator": "regex", "value": "(?i)powershell.*encodedcommand", "mitre": "T1059.001",
        }]
        alerts = evaluate(events, rules)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["event_id"], 9)

    def test_source_mismatch_does_not_alert(self) -> None:
        events = [{"source": "network", "event_type": "network", "data": {"remote_port": 22}}]
        rules = [{"id": "P1", "title": "X", "severity": "high", "source": "process", "field": "remote_port", "operator": "equals", "value": 22}]
        self.assertEqual(evaluate(events, rules), [])


class ForensicRegistryTests(unittest.TestCase):
    def test_requested_tool_registry_is_complete(self) -> None:
        expected = {
            "Velociraptor", "Volatility 3", "Autopsy", "The Sleuth Kit", "Hayabusa",
            "Chainsaw", "Plaso", "Timesketch", "Zeek", "Wireshark", "Suricata", "Arkime",
            "capa", "FLOSS", "Ghidra", "CyberChef", "osquery", "Sigma", "ALEAPP", "MVT",
        }
        items = forensic_tools()
        names = {item["name"] for item in items}
        self.assertTrue(expected.issubset(names))
        for item in items:
            self.assertIn(item["integration"], {"local", "embedded", "external"})
            self.assertIsInstance(item["available"], bool)


if __name__ == "__main__":
    unittest.main()
