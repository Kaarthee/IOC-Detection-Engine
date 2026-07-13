import datetime
import unittest

from src.normalization import (
    SecurityEvent,
    normalize_ubuntu_auth_log,
    normalize_ubuntu_auth_logs,
    parse_ubuntu_timestamp,
)


class TestUbuntuTimestampNormalization(unittest.TestCase):
    def test_valid_timestamp_becomes_iso_format(self):
        log = (
            "Apr 28 10:35:11 ubuntu sshd[1234]: "
            "Failed password for root from "
            "192.168.56.101 port 44322 ssh2"
        )

        result = parse_ubuntu_timestamp(log)
        current_year = datetime.datetime.now().year

        self.assertEqual(
            result,
            f"{current_year}-04-28T10:35:11",
        )

    def test_invalid_timestamp_returns_none(self):
        log = (
            "INVALID-TIME ubuntu sshd[1234]: "
            "Failed password for root from "
            "192.168.56.101 port 44322 ssh2"
        )

        result = parse_ubuntu_timestamp(log)

        self.assertIsNone(result)


class TestUbuntuAuthNormalization(unittest.TestCase):
    def test_failed_login_is_normalized(self):
        log = (
            "Apr 28 10:35:11 ubuntu sshd[1234]: "
            "Failed password for root from "
            "192.168.56.101 port 44322 ssh2"
        )

        event = normalize_ubuntu_auth_log(log)

        self.assertIsInstance(
            event,
            SecurityEvent,
        )
        self.assertEqual(
            event.source_ip,
            "192.168.56.101",
        )
        self.assertEqual(
            event.event_type,
            "authentication_failure",
        )
        self.assertEqual(
            event.username,
            "root",
        )
        self.assertEqual(
            event.destination_port,
            44322,
        )
        self.assertEqual(
            event.source,
            "ubuntu_auth",
        )
        self.assertEqual(
            event.protocol,
            "ssh",
        )

    def test_successful_login_is_normalized(self):
        log = (
            "Apr 28 10:36:45 ubuntu sshd[1237]: "
            "Accepted password for user from "
            "192.168.56.101 port 53421 ssh2"
        )

        event = normalize_ubuntu_auth_log(log)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.event_type,
            "authentication_success",
        )
        self.assertEqual(
            event.username,
            "user",
        )
        self.assertEqual(
            event.destination_port,
            53421,
        )

    def test_invalid_user_login_is_normalized(self):
        log = (
            "Apr 28 10:40:00 ubuntu sshd[2000]: "
            "Failed password for invalid user admin from "
            "203.0.113.50 port 60000 ssh2"
        )

        event = normalize_ubuntu_auth_log(log)

        self.assertIsNotNone(event)
        self.assertEqual(
            event.username,
            "admin",
        )
        self.assertEqual(
            event.event_type,
            "authentication_failure",
        )

    def test_unrelated_log_returns_none(self):
        log = (
            "Apr 28 10:45:00 ubuntu systemd[1]: "
            "Started Daily Cleanup."
        )

        event = normalize_ubuntu_auth_log(log)

        self.assertIsNone(event)

    def test_malformed_timestamp_preserves_event(self):
        log = (
            "INVALID-TIME ubuntu sshd[3000]: "
            "Failed password for root from "
            "198.51.100.10 port 50000 ssh2"
        )

        event = normalize_ubuntu_auth_log(log)

        self.assertIsNotNone(event)
        self.assertIsNone(
            event.timestamp
        )
        self.assertEqual(
            event.source_ip,
            "198.51.100.10",
        )

    def test_multiple_logs_only_return_supported_events(self):
        logs = [
            (
                "Apr 28 10:35:11 ubuntu sshd[1234]: "
                "Failed password for root from "
                "192.168.56.101 port 44322 ssh2"
            ),
            (
                "Apr 28 10:36:45 ubuntu sshd[1237]: "
                "Accepted password for user from "
                "192.168.56.101 port 53421 ssh2"
            ),
            (
                "Apr 28 10:45:00 ubuntu systemd[1]: "
                "Started Daily Cleanup."
            ),
        ]

        events = normalize_ubuntu_auth_logs(
            logs
        )

        self.assertEqual(
            len(events),
            2,
        )
        self.assertEqual(
            events[0].event_type,
            "authentication_failure",
        )
        self.assertEqual(
            events[1].event_type,
            "authentication_success",
        )

    def test_event_converts_to_dictionary(self):
        log = (
            "Apr 28 10:35:11 ubuntu sshd[1234]: "
            "Failed password for root from "
            "192.168.56.101 port 44322 ssh2"
        )

        event = normalize_ubuntu_auth_log(log)
        event_dict = event.to_dict()

        self.assertEqual(
            event_dict["source_ip"],
            "192.168.56.101",
        )
        self.assertEqual(
            event_dict["event_type"],
            "authentication_failure",
        )
        self.assertIn(
            "raw_log",
            event_dict,
        )


if __name__ == "__main__":
    unittest.main()
