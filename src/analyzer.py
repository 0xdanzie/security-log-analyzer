import json
import re
from collections import Counter
from ipaddress import ip_address
from pathlib import Path


LOG_FILE = Path("logs/sample_auth.log")
REPORT_FILE = Path("reports/security_report.txt")
JSON_REPORT_FILE = Path("reports/security_report.json")

FAILED_LOGIN_THRESHOLD = 3


def read_log_file(file_path):
    """Read all lines from a log file."""

    with open(file_path, "r", encoding="utf-8") as log_file:
        return log_file.readlines()


def extract_ip_address(log_line):
    """Extract and validate an IPv4 address from a log entry."""

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(ip_pattern, log_line)

    if not match:
        return None

    ip_string = match.group()

    try:
        validated_ip = ip_address(ip_string)
    except ValueError:
        return None

    if validated_ip.version == 4:
        return str(validated_ip)

    return None


def extract_username(log_line):
    """Extract the targeted username from an SSH authentication log."""

    invalid_user_match = re.search(
        r"Failed password for invalid user (\S+)",
        log_line,
    )
    if invalid_user_match:
        return invalid_user_match.group(1)

    login_match = re.search(r"(?:Failed|Accepted) password for (\S+)", log_line)
    if login_match:
        return login_match.group(1)

    return None


def parse_log_entry(log_line):
    """Parse a log entry and identify its authentication event type."""

    extracted_ip = extract_ip_address(log_line)
    username = extract_username(log_line)

    if "Failed password" in log_line:
        event_type = "FAILED_LOGIN"
    elif "Accepted password" in log_line:
        event_type = "SUCCESSFUL_LOGIN"
    else:
        event_type = "UNKNOWN"

    return {
        "event_type": event_type,
        "ip_address": extracted_ip,
        "username": username,
        "raw_log": log_line.strip(),
    }


def analyze_failed_logins(parsed_events):
    """Count failed login attempts for each IP address."""

    failed_ip_addresses = []

    for event in parsed_events:
        if event["event_type"] == "FAILED_LOGIN" and event["ip_address"]:
            failed_ip_addresses.append(event["ip_address"])

    return Counter(failed_ip_addresses)


def analyze_targeted_users(parsed_events):
    """Group targeted usernames by source IP address."""

    targeted_users = {}

    for event in parsed_events:
        if event["event_type"] == "FAILED_LOGIN" and event["ip_address"]:
            extracted_ip = event["ip_address"]
            username = event["username"]

            if extracted_ip not in targeted_users:
                targeted_users[extracted_ip] = set()

            if username:
                targeted_users[extracted_ip].add(username)

    return targeted_users


def classify_risk(attempt_count):
    """Assign a risk level based on failed login attempts."""

    if attempt_count >= 5:
        return "HIGH"
    if attempt_count >= 3:
        return "MEDIUM"
    return "LOW"


def generate_security_report(
    parsed_events,
    failed_login_counts,
    targeted_users,
    report_file,
):
    """Generate and save a text security report."""

    total_events = len(parsed_events)
    failed_events = sum(
        1 for event in parsed_events if event["event_type"] == "FAILED_LOGIN"
    )
    successful_events = sum(
        1 for event in parsed_events if event["event_type"] == "SUCCESSFUL_LOGIN"
    )
    unknown_events = sum(
        1 for event in parsed_events if event["event_type"] == "UNKNOWN"
    )

    report_lines = [
        "=" * 60,
        "SECURITY LOG ANALYSIS REPORT",
        "=" * 60,
        f"Total Events: {total_events}",
        f"Failed Login Events: {failed_events}",
        f"Successful Login Events: {successful_events}",
        f"Unknown Events: {unknown_events}",
        "",
        "FAILED LOGIN ANALYSIS",
        "-" * 60,
    ]

    for extracted_ip, attempt_count in failed_login_counts.items():
        risk_level = classify_risk(attempt_count)
        users = sorted(targeted_users.get(extracted_ip, set()))
        users_text = ", ".join(users)

        report_lines.extend(
            [
                f"IP Address: {extracted_ip}",
                f"Failed Attempts: {attempt_count}",
                f"Targeted Users: {users_text}",
                f"Risk Level: {risk_level}",
                "-" * 60,
            ]
        )

    report_lines.extend(
        [
            "",
            "SUSPICIOUS ACTIVITY ALERTS",
            "-" * 60,
        ]
    )

    alert_found = False

    for extracted_ip, attempt_count in failed_login_counts.items():
        if attempt_count >= FAILED_LOGIN_THRESHOLD:
            alert_found = True
            risk_level = classify_risk(attempt_count)

            report_lines.append(
                f"Suspicious IP: {extracted_ip} | "
                f"Failed Attempts: {attempt_count} | "
                f"Risk: {risk_level}"
            )

    if not alert_found:
        report_lines.append("No suspicious activity detected.")

    with open(report_file, "w", encoding="utf-8") as file:
        file.write("\n".join(report_lines))


def generate_json_report(
    parsed_events,
    failed_login_counts,
    targeted_users,
    report_file,
):
    """Generate and save a structured JSON security report."""

    failed_events = sum(
        1 for event in parsed_events if event["event_type"] == "FAILED_LOGIN"
    )
    successful_events = sum(
        1 for event in parsed_events if event["event_type"] == "SUCCESSFUL_LOGIN"
    )
    unknown_events = sum(
        1 for event in parsed_events if event["event_type"] == "UNKNOWN"
    )

    ip_analysis = []

    for extracted_ip, attempt_count in failed_login_counts.items():
        risk_level = classify_risk(attempt_count)
        users = sorted(targeted_users.get(extracted_ip, set()))

        ip_analysis.append(
            {
                "ip_address": extracted_ip,
                "failed_attempts": attempt_count,
                "targeted_users": users,
                "risk_level": risk_level,
                "suspicious": attempt_count >= FAILED_LOGIN_THRESHOLD,
            }
        )

    report_data = {
        "summary": {
            "total_events": len(parsed_events),
            "failed_login_events": failed_events,
            "successful_login_events": successful_events,
            "unknown_events": unknown_events,
        },
        "ip_analysis": ip_analysis,
    }

    with open(report_file, "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)


def main():
    print("=" * 50)
    print("SECURITY LOG ANALYZER")
    print("=" * 50)

    log_lines = read_log_file(LOG_FILE)

    print(f"\nTotal log entries loaded: {len(log_lines)}")
    print("\nPARSED SECURITY EVENTS")
    print("-" * 50)

    parsed_events = []

    for log_line in log_lines:
        parsed_event = parse_log_entry(log_line)
        parsed_events.append(parsed_event)

        print(
            f"Event: {parsed_event['event_type']} | "
            f"IP: {parsed_event['ip_address']}  | "
            f"User: {parsed_event['username']}"
        )

    failed_login_counts = analyze_failed_logins(parsed_events)
    targeted_users = analyze_targeted_users(parsed_events)

    print("\nFAILED LOGIN SUMMARY")
    print("-" * 50)

    for extracted_ip, attempt_count in failed_login_counts.items():
        risk_level = classify_risk(attempt_count)
        users = sorted(targeted_users.get(extracted_ip, set()))
        users_text = ", ".join(users)

        print(
            f"IP: {extracted_ip} | "
            f"Failed Attempts: {attempt_count} | "
            f"Targeted Users: {users_text} | "
            f"Risk: {risk_level}"
        )

    print("\nSUSPICIOUS ACTIVITY DETECTION")
    print("-" * 50)

    for extracted_ip, attempt_count in failed_login_counts.items():
        if attempt_count >= FAILED_LOGIN_THRESHOLD:
            risk_level = classify_risk(attempt_count)

            print(
                f"[ALERT] Suspicious IP detected: {extracted_ip} | "
                f"Failed Attempts: {attempt_count} | "
                f"Risk: {risk_level}"
            )

    generate_security_report(
        parsed_events,
        failed_login_counts,
        targeted_users,
        REPORT_FILE,
    )
    print(f"\nSecurity report generated: {REPORT_FILE}")

    generate_json_report(
        parsed_events,
        failed_login_counts,
        targeted_users,
        JSON_REPORT_FILE,
    )
    print(f"JSON report generated: {JSON_REPORT_FILE}")


if __name__ == "__main__":
    main()