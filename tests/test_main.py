import datetime
import unittest

from src.main import (
    BRUTE_FORCE_THRESHOLD,
    build_incident_record,
    classify_activity,
    count_events,
    create_incident_fingerprint,
    create_incident_windows,
    get_incident_time_range,
    is_duplicate_incident,
    parse_log_timestamp,
)


class TestTimestampParsing(unittest.TestCase):
    def test_valid_ubuntu_timestamp(self):
        log = (
            "Apr 28 10:35:11 ubuntu sshd[1234]: "
            "Failed password for root from "
            "192.168.56.101 port 44322 ssh2"
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
            "Failed password for root from "
            "10.10.10.80 port 43001 ssh2"
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
            (
                "Apr 28 10:00:00 ubuntu sshd[1]: "
                "Failed password message repeated 4 times"
            )
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


class TestIncidentJsonModel(unittest.TestCase):
    def test_incident_time_range(self):
        logs = [
            "Apr 28 14:02:00 ubuntu sshd[2]: Failed password",
            "Apr 28 14:00:00 ubuntu sshd[1]: Failed password",
        ]

        start_time, end_time = get_incident_time_range(logs)
        current_year = datetime.datetime.now().year

        self.assertEqual(
            start_time,
            f"{current_year}-04-28T14:00:00",
        )
        self.assertEqual(
            end_time,
            f"{current_year}-04-28T14:02:00",
        )

    def test_invalid_timestamps_return_null_range(self):
        logs = [
            "INVALID-TIME ubuntu sshd[1]: Failed password",
        ]

        start_time, end_time = get_incident_time_range(logs)

        self.assertIsNone(start_time)
        self.assertIsNone(end_time)

    def test_build_incident_record(self):
        logs = [
            "Apr 28 10:00:00 ubuntu sshd[1]: Failed password",
            "Apr 28 10:01:00 ubuntu sshd[2]: Accepted password",
        ]

        incident = build_incident_record(
            alert_id=1,
            generated_at="2026-07-11 14:30:00",
            ip="192.168.1.50",
            is_ioc_match=True,
            failed=1,
            successful=1,
            severity="CRITICAL",
            classification="Brute Force → Successful Login",
            mitre="T1110, T1078",
            logs=logs,
        )

        self.assertEqual(incident["incident_id"], "INC-0001")
        self.assertEqual(
            incident["source_ip"],
            "192.168.1.50",
        )
        self.assertTrue(incident["ioc"]["matched"])
        self.assertEqual(
            incident["event_counts"]["total_events"],
            2,
        )
        self.assertEqual(
            incident["mitre_attack"],
            ["T1110", "T1078"],
        )
        self.assertEqual(
            incident["severity"],
            "CRITICAL",
        )


class TestDeduplication(unittest.TestCase):
    def test_fingerprint_is_stable(self):
        incident = {
            "source_ip": "192.168.1.50",
            "classification": "SSH Brute Force",
            "time_window": {
                "start": "2026-04-28T10:00:00",
                "end": "2026-04-28T10:02:00",
                "window_minutes": 5,
            },
            "evidence": [
                "Apr 28 10:00:00 Failed password",
                "Apr 28 10:02:00 Failed password",
            ],
        }

        first = create_incident_fingerprint(incident)
        second = create_incident_fingerprint(incident)

        self.assertEqual(first, second)

    def test_first_incident_is_not_duplicate(self):
        state = {}

        current_time = datetime.datetime(
            2026,
            7,
            11,
            15,
            0,
            0,
        )

        result = is_duplicate_incident(
            "fingerprint-1",
            state,
            current_time,
        )

        self.assertFalse(result)
        self.assertIn("fingerprint-1", state)
        self.assertEqual(
            state["fingerprint-1"]["repeat_count"],
            1,
        )

    def test_repeated_incident_inside_cooldown_is_duplicate(self):
        state = {}

        first_time = datetime.datetime(
            2026,
            7,
            11,
            15,
            0,
            0,
        )

        second_time = datetime.datetime(
            2026,
            7,
            11,
            15,
            10,
            0,
        )

        is_duplicate_incident(
            "fingerprint-1",
            state,
            first_time,
        )

        result = is_duplicate_incident(
            "fingerprint-1",
            state,
            second_time,
        )

        self.assertTrue(result)
        self.assertEqual(
            state["fingerprint-1"]["repeat_count"],
            2,
        )

    def test_incident_after_cooldown_is_not_duplicate(self):
        state = {}

        first_time = datetime.datetime(
            2026,
            7,
            11,
            15,
            0,
            0,
        )

        later_time = datetime.datetime(
            2026,
            7,
            11,
            15,
            31,
            0,
        )

        is_duplicate_incident(
            "fingerprint-1",
            state,
            first_time,
        )

        result = is_duplicate_incident(
            "fingerprint-1",
            state,
            later_time,
        )

        self.assertFalse(result)
        self.assertEqual(
            state["fingerprint-1"]["repeat_count"],
            2,
        )
        self.assertEqual(
            state["fingerprint-1"]["last_seen"],
            later_time.isoformat(),
        )


if __name__ == "__main__":
    unittest.main()
