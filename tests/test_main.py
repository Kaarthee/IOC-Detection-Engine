import datetime
import unittest

from src.main import (
    BRUTE_FORCE_THRESHOLD,
    classify_activity,
    count_events,
    create_incident_windows,
    parse_log_timestamp,
)


class TestTimestampParsing(unittest.TestCase):
    def test_valid_ubuntu_timestamp(self):
        log = (
            "Apr 28 10:35:11 ubuntu sshd[1234]: "
            "Failed password for root from 192.168.56.101 port 44322 ssh2"
        )

        result = parse_log_timestamp(log)

        self.assertIsNotNone(result)
        self.assertEqual(result.month, 4)
        self.assertEqual(result.day, 28)
        self.assertEqual(result.hour, 10)
        self.assertEqual(result.minute, 35)
        self.assertEqual(result.second, 11)

    def test_invalid_timestamp_returns_none(self):
        log = (
            "INVALID-TIME ubuntu sshd[5001]: "
            "Failed password for root from 10.10.10.80 port 43001 ssh2"
        )

        result = parse_log_timestamp(log)

        self.assertIsNone(result)


class TestEventCounting(unittest.TestCase):
    def test_count_failed_and_successful_events(self):
        logs = [
            "Apr 28 10:00:00 ubuntu sshd[1]: Failed password",
            "Apr 28 10:00:01 ubuntu sshd[2]: Failed password",
            "Apr 28 10:00:02 ubuntu sshd[3]: Accepted password",
        ]

        failed, successful = count_events(logs)

        self.assertEqual(failed, 2)
        self.assertEqual(successful, 1)

    def test_repeated_message_count(self):
        logs = [
            "Apr 28 10:00:00 ubuntu sshd[1]: "
            "Failed password message repeated 4 times"
        ]

        failed, successful = count_events(logs)

        self.assertEqual(failed, 4)
        self.assertEqual(successful, 0)


class TestIncidentCorrelation(unittest.TestCase):
    def test_events_within_five_minutes_share_window(self):
        logs = [
            "Apr 28 12:00:00 ubuntu sshd[1]: Failed password",
            "Apr 28 12:05:00 ubuntu sshd[2]: Failed password",
        ]

        incidents = create_incident_windows(logs)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(len(incidents[0]), 2)

    def test_event_after_five_minutes_starts_new_window(self):
        logs = [
            "Apr 28 12:00:00 ubuntu sshd[1]: Failed password",
            "Apr 28 12:05:01 ubuntu sshd[2]: Failed password",
        ]

        incidents = create_incident_windows(logs)

        self.assertEqual(len(incidents), 2)

    def test_out_of_order_logs_are_sorted(self):
        logs = [
            "Apr 28 13:04:00 ubuntu sshd[2]: Failed password",
            "Apr 28 13:00:00 ubuntu sshd[1]: Failed password",
        ]

        incidents = create_incident_windows(logs)

        self.assertEqual(len(incidents), 1)
        self.assertIn("13:00:00", incidents[0][0])
        self.assertIn("13:04:00", incidents[0][1])

    def test_malformed_log_becomes_separate_incident(self):
        logs = [
            "Apr 28 14:00:00 ubuntu sshd[1]: Failed password",
            "INVALID-TIME ubuntu sshd[2]: Failed password",
            "Apr 28 14:02:00 ubuntu sshd[3]: Failed password",
        ]

        incidents = create_incident_windows(logs)

        self.assertEqual(len(incidents), 2)
        self.assertEqual(len(incidents[0]), 2)
        self.assertEqual(len(incidents[1]), 1)
        self.assertIn("INVALID-TIME", incidents[1][0])


class TestClassification(unittest.TestCase):
    def test_brute_force_classification(self):
        severity, classification, mitre, _ = classify_activity(
            BRUTE_FORCE_THRESHOLD,
            0,
            False,
        )

        self.assertEqual(severity, "HIGH")
        self.assertEqual(classification, "SSH Brute Force")
        self.assertEqual(mitre, "T1110")

    def test_success_after_failures_is_critical(self):
        severity, classification, mitre, _ = classify_activity(
            3,
            1,
            False,
        )

        self.assertEqual(severity, "CRITICAL")
        self.assertEqual(
            classification,
            "Brute Force → Successful Login",
        )
        self.assertEqual(mitre, "T1110, T1078")


if __name__ == "__main__":
    unittest.main()
