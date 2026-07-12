import unittest

from src.analyzer import (
    analyze_failed_logins,
    analyze_targeted_users,
    classify_risk,
    extract_ip_address,
    extract_username,
    parse_log_entry,
)

class TestSecurityLogAnalyzer(unittest.TestCase):
    
    def test_analyze_failed_logins(self):
        parsed_events = [
            {
                "event_type": "FAILED_LOGIN",
                "ip_address": "192.168.1.50",
                "username": "admin",
            },
            {
                "event_type": "FAILED_LOGIN",
                "ip_address": "192.168.1.50",
                "username": "root",
            },
            {
                "event_type": "SUCCESSFUL_LOGIN",
                "ip_address": "10.0.0.15",
                "username": "danish",
            },
        ]

        result = analyze_failed_logins(parsed_events)

        self.assertEqual(result["192.168.1.50"], 2)
        self.assertNotIn("10.0.0.15", result)
        
    def test_analyze_targeted_users(self):
        parsed_events = [
            {
                "event_type": "FAILED_LOGIN",
                "ip_address": "192.168.1.50",
                "username": "admin",
            },
            {
                "event_type": "FAILED_LOGIN",
                "ip_address": "192.168.1.50",
                "username": "root",
            },
            {
                "event_type": "FAILED_LOGIN",
                "ip_address": "192.168.1.50",
                "username": "admin",
            },
        ]

        result = analyze_targeted_users(parsed_events)

        self.assertEqual(
            result["192.168.1.50"],
            {"admin", "root"},
        )
    
    def test_extract_ip_address(self):
        log_line = (
            "Failed password for root from "
            "192.168.1.50 port 49154 ssh2"
        )

        result = extract_ip_address(log_line)

        self.assertEqual(result, "192.168.1.50")
        
    def test_extract_ip_address_when_missing(self):
        log_line = "Authentication service unavailable"

        result = extract_ip_address(log_line)

        self.assertIsNone(result)
        
    def test_reject_invalid_ip_address(self):
        log_line = (
            "Failed password for root from "
            "999.999.999.999 port 44121 ssh2"
        )

        result = extract_ip_address(log_line)

        self.assertIsNone(result) 
        
    def test_extract_valid_username(self):
        log_line = (
            "Failed password for root from "
            "10.0.0.15 port 44121 ssh2"
        )

        result = extract_username(log_line)

        self.assertEqual(result, "root")
        
    def test_extract_invalid_username(self):
        log_line = (
            "Failed password for invalid user admin from "
            "192.168.1.50 port 49152 ssh2"
        )

        result = extract_username(log_line)

        self.assertEqual(result, "admin")
        
    def test_parse_failed_login(self):
        log_line = (
            "Failed password for root from "
            "10.0.0.15 port 44121 ssh2"
        )

        result = parse_log_entry(log_line)

        self.assertEqual(result["event_type"], "FAILED_LOGIN")
        self.assertEqual(result["ip_address"], "10.0.0.15")
        self.assertEqual(result["username"], "root")

    def test_parse_unknown_event(self):
        log_line = (
            "Connection closed by "
            "192.168.1.99 port 50100"
        )

        result = parse_log_entry(log_line)

        self.assertEqual(result["event_type"], "UNKNOWN")
        self.assertEqual(result["ip_address"], "192.168.1.99")
        self.assertIsNone(result["username"])
        
    def test_low_risk_classification(self):
        self.assertEqual(classify_risk(2), "LOW")
        
    def test_medium_risk_classification(self):
        self.assertEqual(classify_risk(4), "MEDIUM")
        
    def test_high_risk_classification(self):
        self.assertEqual(classify_risk(6), "HIGH")
        
    def test_low_to_medium_risk_boundary(self):
        self.assertEqual(classify_risk(2), "LOW")
        self.assertEqual(classify_risk(3), "MEDIUM")
        
    def test_medium_to_high_risk_boundary(self):
        self.assertEqual(classify_risk(4), "MEDIUM")
        self.assertEqual(classify_risk(5), "HIGH")
        
    def test_failed_login_without_ip_is_ignored(self):
        parsed_events = [
            {
                "event_type": "FAILED_LOGIN",
                "ip_address": None,
                "username": "root",
            }
        ]

        result = analyze_failed_logins(parsed_events)

        self.assertEqual(len(result), 0)
        
if __name__ == "__main__":
    unittest.main()