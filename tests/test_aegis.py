"""Tests for Creox Aegis v1 — all on fictional sample logs, zero dependencies."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from creox_aegis.correlation import correlate
from creox_aegis.detectors import run_detectors
from creox_aegis.parser import parse_file

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "sample_logs", "sample.log")


class TestAegis(unittest.TestCase):
    def setUp(self):
        self.events = parse_file(SAMPLE)
        self.findings = run_detectors(self.events)
        self.incidents = correlate(self.findings)

    def test_parses_all_sample_lines(self):
        self.assertEqual(len(self.events), 22)

    def test_brute_force_detected(self):
        self.assertTrue(any(f.detector == "brute_force" for f in self.findings))

    def test_port_scan_detected(self):
        self.assertTrue(any(f.detector == "port_scan" for f in self.findings))

    def test_sqli_probe_detected(self):
        self.assertTrue(any(f.detector == "web_probe_sqli_pattern" for f in self.findings))

    def test_one_incident_per_attacker_ip(self):
        # Attacker IP correlated into ONE incident, normal user IP has none.
        self.assertEqual(len(self.incidents), 1)
        self.assertEqual(self.incidents[0].ip, "192.168.1.50")
        self.assertIn("brute_force", self.incidents[0].detectors)
        self.assertIn("port_scan", self.incidents[0].detectors)

    def test_every_finding_is_explainable(self):
        for f in self.findings:
            self.assertTrue(f.reason)
            self.assertTrue(f.evidence)

    def test_response_is_suggestion_not_auto_action(self):
        self.assertIn("SUGGESTED", self.incidents[0].suggested_response)
        self.assertIn("human approval", self.incidents[0].suggested_response)


if __name__ == "__main__":
    unittest.main()
