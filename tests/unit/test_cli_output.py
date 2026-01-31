"""Tests for sshmgr.cli.output module."""

from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest.mock import patch

import pytest
from rich.text import Text

from sshmgr.cli.output import (
    OutputFormat,
    confirm,
    create_table,
    format_datetime,
    format_fingerprint,
    format_timedelta,
    format_validity,
    print_error,
    print_info,
    print_json,
    print_key_value,
    print_section,
    print_success,
    print_warning,
)


class TestOutputFormat:
    """Tests for OutputFormat enum."""

    def test_text_format(self):
        """Test TEXT format value."""
        assert OutputFormat.TEXT.value == "text"

    def test_json_format(self):
        """Test JSON format value."""
        assert OutputFormat.JSON.value == "json"

    def test_table_format(self):
        """Test TABLE format value."""
        assert OutputFormat.TABLE.value == "table"

    def test_format_from_string(self):
        """Test creating format from string."""
        assert OutputFormat("text") == OutputFormat.TEXT
        assert OutputFormat("json") == OutputFormat.JSON
        assert OutputFormat("table") == OutputFormat.TABLE


class TestPrintFunctions:
    """Tests for print helper functions."""

    def test_print_success(self, capsys):
        """Test print_success outputs to console."""
        # Just verify it doesn't raise - output goes through rich
        print_success("Test message")

    def test_print_error(self, capsys):
        """Test print_error outputs to stderr."""
        # Just verify it doesn't raise - output goes through rich
        print_error("Error message")

    def test_print_warning(self, capsys):
        """Test print_warning outputs to console."""
        print_warning("Warning message")

    def test_print_info(self, capsys):
        """Test print_info outputs to console."""
        print_info("Info message")

    def test_print_key_value(self, capsys):
        """Test print_key_value outputs formatted pair."""
        print_key_value("Key", "Value")

    def test_print_section(self, capsys):
        """Test print_section outputs header."""
        print_section("Section Title")


class TestPrintJson:
    """Tests for print_json function."""

    def test_print_json_dict(self):
        """Test printing a dictionary as JSON."""
        data = {"name": "test", "value": 42}
        # Should not raise
        print_json(data)

    def test_print_json_with_datetime(self):
        """Test printing JSON with datetime objects."""
        data = {"timestamp": datetime(2024, 1, 15, 10, 30, 0)}
        # Should serialize datetime to ISO format
        print_json(data)

    def test_print_json_with_timedelta(self):
        """Test printing JSON with timedelta objects."""
        data = {"duration": timedelta(hours=8)}
        print_json(data)

    def test_print_json_with_enum(self):
        """Test printing JSON with enum objects."""
        data = {"format": OutputFormat.JSON}
        print_json(data)

    def test_print_json_with_to_dict_method(self):
        """Test printing object with to_dict method."""

        class MockObj:
            def to_dict(self):
                return {"key": "value"}

        print_json(MockObj())

    def test_print_json_with_object(self):
        """Test printing object without to_dict."""

        class MockObj:
            def __init__(self):
                self.name = "test"

        print_json(MockObj())


class TestFormatDatetime:
    """Tests for format_datetime function."""

    def test_format_datetime_with_value(self):
        """Test formatting a datetime value."""
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        result = format_datetime(dt)

        assert "2024-01-15" in result
        assert "10:30:00" in result

    def test_format_datetime_none(self):
        """Test formatting None returns dash."""
        result = format_datetime(None)
        assert result == "—"


class TestFormatTimedelta:
    """Tests for format_timedelta function."""

    def test_format_seconds(self):
        """Test formatting seconds."""
        td = timedelta(seconds=45)
        result = format_timedelta(td)
        assert result == "45s"

    def test_format_minutes(self):
        """Test formatting minutes."""
        td = timedelta(minutes=30)
        result = format_timedelta(td)
        assert result == "30m"

    def test_format_hours(self):
        """Test formatting hours."""
        td = timedelta(hours=8)
        result = format_timedelta(td)
        assert result == "8h"

    def test_format_hours_and_minutes(self):
        """Test formatting hours and minutes."""
        td = timedelta(hours=2, minutes=30)
        result = format_timedelta(td)
        assert result == "2h 30m"

    def test_format_days(self):
        """Test formatting days."""
        td = timedelta(days=7)
        result = format_timedelta(td)
        assert result == "7d"

    def test_format_days_and_hours(self):
        """Test formatting days and hours."""
        td = timedelta(days=2, hours=12)
        result = format_timedelta(td)
        assert result == "2d 12h"

    def test_format_none(self):
        """Test formatting None returns dash."""
        result = format_timedelta(None)
        assert result == "—"


class TestFormatValidity:
    """Tests for format_validity function."""

    def test_expired_certificate(self):
        """Test formatting expired certificate."""
        valid_before = datetime.now(timezone.utc) - timedelta(hours=1)
        result = format_validity(valid_before)

        assert isinstance(result, Text)
        assert "Expired" in str(result)

    def test_expiring_soon(self):
        """Test formatting certificate expiring within 1 hour."""
        valid_before = datetime.now(timezone.utc) + timedelta(minutes=30)
        result = format_validity(valid_before)

        assert isinstance(result, Text)
        assert "remaining" in str(result)

    def test_valid_certificate(self):
        """Test formatting valid certificate with time remaining."""
        valid_before = datetime.now(timezone.utc) + timedelta(hours=8)
        result = format_validity(valid_before)

        assert isinstance(result, Text)
        assert "remaining" in str(result)


class TestFormatFingerprint:
    """Tests for format_fingerprint function."""

    def test_short_fingerprint(self):
        """Test formatting short fingerprint (no truncation)."""
        fp = "SHA256:abcd1234"
        result = format_fingerprint(fp)
        assert result == fp

    def test_long_fingerprint_truncate(self):
        """Test formatting long fingerprint with truncation."""
        fp = "SHA256:abcdefghijklmnopqrstuvwxyz123456789"
        result = format_fingerprint(fp, truncate=True)

        assert len(result) < len(fp)
        assert result.endswith("...")

    def test_long_fingerprint_no_truncate(self):
        """Test formatting long fingerprint without truncation."""
        fp = "SHA256:abcdefghijklmnopqrstuvwxyz123456789"
        result = format_fingerprint(fp, truncate=False)

        assert result == fp


class TestCreateTable:
    """Tests for create_table function."""

    def test_create_table_no_args(self):
        """Test creating table with no arguments."""
        table = create_table()

        assert table is not None

    def test_create_table_with_title(self):
        """Test creating table with title."""
        table = create_table(title="Test Table")

        assert table.title == "Test Table"

    def test_create_table_with_columns(self):
        """Test creating table with columns."""
        columns = [
            ("Name", "cyan"),
            ("Value", "green"),
        ]
        table = create_table(columns=columns)

        assert len(table.columns) == 2


class TestConfirm:
    """Tests for confirm function."""

    def test_confirm_yes(self):
        """Test confirming with 'y'."""
        with patch("sshmgr.cli.output.console") as mock_console:
            mock_console.input.return_value = "y"
            result = confirm("Continue?")

        assert result is True

    def test_confirm_yes_full(self):
        """Test confirming with 'yes'."""
        with patch("sshmgr.cli.output.console") as mock_console:
            mock_console.input.return_value = "yes"
            result = confirm("Continue?")

        assert result is True

    def test_confirm_no(self):
        """Test declining with 'n'."""
        with patch("sshmgr.cli.output.console") as mock_console:
            mock_console.input.return_value = "n"
            result = confirm("Continue?")

        assert result is False

    def test_confirm_empty_default_false(self):
        """Test empty input with default=False."""
        with patch("sshmgr.cli.output.console") as mock_console:
            mock_console.input.return_value = ""
            result = confirm("Continue?", default=False)

        assert result is False

    def test_confirm_empty_default_true(self):
        """Test empty input with default=True."""
        with patch("sshmgr.cli.output.console") as mock_console:
            mock_console.input.return_value = ""
            result = confirm("Continue?", default=True)

        assert result is True

    def test_confirm_case_insensitive(self):
        """Test confirmation is case insensitive."""
        with patch("sshmgr.cli.output.console") as mock_console:
            mock_console.input.return_value = "Y"
            result = confirm("Continue?")

        assert result is True


class TestPrintEnvironmentDetails:
    """Tests for print_environment_details function."""

    def test_print_environment_details(self):
        """Test printing environment details."""
        from sshmgr.cli.output import print_environment_details

        env = {
            "id": "test-id",
            "name": "production",
            "created_at": datetime.now(timezone.utc),
            "user_ca_fingerprint": "SHA256:abc123",
            "default_user_cert_validity": timedelta(hours=8),
            "host_ca_fingerprint": "SHA256:def456",
            "default_host_cert_validity": timedelta(days=90),
        }

        # Should not raise
        print_environment_details(env)

    def test_print_environment_details_missing_fields(self):
        """Test printing environment with missing fields."""
        from sshmgr.cli.output import print_environment_details

        env = {"name": "test"}

        # Should not raise even with missing fields
        print_environment_details(env)


class TestPrintCertificateDetails:
    """Tests for print_certificate_details function."""

    def test_print_certificate_details(self):
        """Test printing certificate details."""
        from sshmgr.cli.output import print_certificate_details

        cert = {
            "cert_type": "user",
            "key_id": "alice@example.com",
            "serial": 12345,
            "principals": ["alice", "admin"],
            "valid_after": datetime.now(timezone.utc),
            "valid_before": datetime.now(timezone.utc) + timedelta(hours=8),
        }

        # Should not raise
        print_certificate_details(cert)

    def test_print_certificate_details_revoked(self):
        """Test printing revoked certificate details."""
        from sshmgr.cli.output import print_certificate_details

        cert = {
            "cert_type": "user",
            "key_id": "alice@example.com",
            "serial": 12345,
            "principals": ["alice"],
            "valid_after": datetime.now(timezone.utc) - timedelta(days=1),
            "valid_before": datetime.now(timezone.utc) + timedelta(hours=8),
            "revoked_at": datetime.now(timezone.utc),
            "revoked_by": "admin",
        }

        # Should not raise
        print_certificate_details(cert)


class TestPrintLoginInstructions:
    """Tests for print_login_instructions function."""

    def test_print_login_instructions_basic(self):
        """Test printing basic login instructions."""
        from sshmgr.cli.output import print_login_instructions

        # Should not raise
        print_login_instructions(
            verification_uri="https://example.com/device",
            user_code="ABCD-1234",
        )

    def test_print_login_instructions_with_complete_uri(self):
        """Test printing login instructions with complete URI."""
        from sshmgr.cli.output import print_login_instructions

        # Should not raise
        print_login_instructions(
            verification_uri="https://example.com/device",
            user_code="ABCD-1234",
            verification_uri_complete="https://example.com/device?code=ABCD-1234",
        )


class TestPrintLoginSuccess:
    """Tests for print_login_success function."""

    def test_print_login_success(self):
        """Test printing login success message."""
        from sshmgr.cli.output import print_login_success

        # Should not raise
        print_login_success("alice")


class TestSpinnerContext:
    """Tests for spinner_context function."""

    def test_spinner_context(self):
        """Test creating spinner context."""
        from sshmgr.cli.output import spinner_context

        ctx = spinner_context("Loading...")
        assert ctx is not None
