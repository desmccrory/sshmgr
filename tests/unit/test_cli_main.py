"""Tests for sshmgr.cli.main module."""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from sshmgr.cli.main import (
    Context,
    async_command,
    cli,
    handle_errors,
)
from sshmgr.cli.output import OutputFormat


class TestContext:
    """Tests for CLI Context class."""

    def test_context_initialization(self):
        """Test context initializes with defaults."""
        with patch("sshmgr.cli.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                api_host="localhost",
                api_port=8000,
            )
            ctx = Context()

        assert ctx.output_format == OutputFormat.TEXT
        assert ctx.verbose is False
        assert ctx.environment is None

    def test_get_api_url(self):
        """Test get_api_url returns correct URL."""
        with patch("sshmgr.cli.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                api_host="localhost",
                api_port=8000,
            )
            ctx = Context()

        url = ctx.get_api_url()
        assert url == "http://localhost:8000"

    def test_get_api_url_custom_host(self):
        """Test get_api_url with custom host and port."""
        with patch("sshmgr.cli.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                api_host="api.example.com",
                api_port=443,
            )
            ctx = Context()

        url = ctx.get_api_url()
        assert url == "http://api.example.com:443"


class TestAsyncCommand:
    """Tests for async_command decorator."""

    def test_async_command_runs_coroutine(self):
        """Test that async_command runs async functions."""

        @async_command
        async def test_func():
            return "result"

        result = test_func()
        assert result == "result"

    def test_async_command_passes_args(self):
        """Test that async_command passes arguments correctly."""

        @async_command
        async def test_func(a, b, c=None):
            return (a, b, c)

        result = test_func(1, 2, c=3)
        assert result == (1, 2, 3)


class TestHandleErrors:
    """Tests for handle_errors decorator."""

    def test_handle_errors_passes_through(self):
        """Test that handle_errors passes through normal execution."""

        @handle_errors
        def test_func():
            return "success"

        result = test_func()
        assert result == "success"

    def test_handle_errors_catches_exception(self):
        """Test that handle_errors catches generic exceptions."""

        @handle_errors
        def test_func():
            raise ValueError("test error")

        with pytest.raises(SystemExit) as exc_info:
            test_func()

        assert exc_info.value.code == 1

    def test_handle_errors_keyboard_interrupt(self):
        """Test that handle_errors handles KeyboardInterrupt."""

        @handle_errors
        def test_func():
            raise KeyboardInterrupt()

        with pytest.raises(SystemExit) as exc_info:
            test_func()

        assert exc_info.value.code == 130


class TestCLIGroup:
    """Tests for the main CLI group."""

    @pytest.fixture
    def runner(self):
        """Create a CLI runner."""
        return CliRunner()

    def test_cli_version(self, runner):
        """Test --version flag."""
        result = runner.invoke(cli, ["--version"])

        assert result.exit_code == 0
        assert "sshmgr" in result.output

    def test_cli_help(self, runner):
        """Test --help flag."""
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "SSH Certificate Management System" in result.output

    def test_cli_format_option(self, runner):
        """Test --format option is recognized."""
        result = runner.invoke(cli, ["--format", "json", "--help"])

        assert result.exit_code == 0

    def test_cli_env_option(self, runner):
        """Test --env option is recognized."""
        result = runner.invoke(cli, ["--env", "test", "--help"])

        assert result.exit_code == 0

    def test_cli_verbose_option(self, runner):
        """Test --verbose flag is recognized."""
        result = runner.invoke(cli, ["--verbose", "--help"])

        assert result.exit_code == 0


class TestAuthCommands:
    """Tests for auth command group."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_auth_group_exists(self, runner):
        """Test auth command group exists."""
        result = runner.invoke(cli, ["auth", "--help"])

        assert result.exit_code == 0
        assert "login" in result.output
        assert "logout" in result.output

    def test_auth_status_help(self, runner):
        """Test auth status command exists."""
        result = runner.invoke(cli, ["auth", "status", "--help"])

        assert result.exit_code == 0


class TestEnvCommands:
    """Tests for env command group."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_env_group_exists(self, runner):
        """Test env command group exists."""
        result = runner.invoke(cli, ["env", "--help"])

        assert result.exit_code == 0
        assert "list" in result.output
        assert "init" in result.output

    def test_env_list_help(self, runner):
        """Test env list command exists."""
        result = runner.invoke(cli, ["env", "list", "--help"])

        assert result.exit_code == 0


class TestCertCommands:
    """Tests for cert command group."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_cert_group_exists(self, runner):
        """Test cert command group exists."""
        result = runner.invoke(cli, ["cert", "--help"])

        assert result.exit_code == 0
        assert "sign-user" in result.output or "list" in result.output

    def test_cert_list_help(self, runner):
        """Test cert list command exists."""
        result = runner.invoke(cli, ["cert", "list", "--help"])

        assert result.exit_code == 0


class TestRotateCommands:
    """Tests for rotate command group."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_rotate_group_exists(self, runner):
        """Test rotate command group exists."""
        result = runner.invoke(cli, ["rotate", "--help"])

        assert result.exit_code == 0


class TestShortcuts:
    """Tests for command shortcuts."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_login_shortcut_exists(self, runner):
        """Test login shortcut exists."""
        result = runner.invoke(cli, ["login", "--help"])

        assert result.exit_code == 0
        assert "shortcut" in result.output.lower() or "login" in result.output.lower()

    def test_logout_shortcut_exists(self, runner):
        """Test logout shortcut exists."""
        result = runner.invoke(cli, ["logout", "--help"])

        assert result.exit_code == 0

    def test_init_env_shortcut_exists(self, runner):
        """Test init-env shortcut exists."""
        result = runner.invoke(cli, ["init-env", "--help"])

        assert result.exit_code == 0
        assert "NAME" in result.output

    def test_sign_user_cert_shortcut_exists(self, runner):
        """Test sign-user-cert shortcut exists."""
        result = runner.invoke(cli, ["sign-user-cert", "--help"])

        assert result.exit_code == 0
        assert "--public-key" in result.output
        assert "--principals" in result.output
        assert "--key-id" in result.output

    def test_sign_host_cert_shortcut_exists(self, runner):
        """Test sign-host-cert shortcut exists."""
        result = runner.invoke(cli, ["sign-host-cert", "--help"])

        assert result.exit_code == 0
        assert "--public-key" in result.output
        assert "--principals" in result.output


class TestMain:
    """Tests for main entry point."""

    def test_main_function_exists(self):
        """Test main function can be imported."""
        from sshmgr.cli.main import main

        assert callable(main)

    def test_cli_can_be_called(self):
        """Test CLI can be invoked without args."""
        runner = CliRunner()
        result = runner.invoke(cli, [])

        # CLI without args shows usage/help (exit code 0 or 2 depending on Click config)
        assert result.exit_code in (0, 2)
        # Should have some output
        assert "sshmgr" in result.output.lower() or "usage" in result.output.lower()
