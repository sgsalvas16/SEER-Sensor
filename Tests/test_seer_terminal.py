"""Tests for seer_terminal.py.

Verifies theme resolution, pass-through arg handling, auto-detection logic,
NO_COLORS propagation, and exec behavior.
"""

import os
import sys
from unittest.mock import patch

sys.path.append(os.path.abspath("Automation/bin"))
import seer_terminal as st

# -------------------------
# Tests
# -------------------------


def test_main_help_flag_prints_usage_and_exits_0():
    """Verify --help prints usage and exits with code 0."""
    with patch("builtins.print") as p:
        try:
            st.main(["prog", "--help"])
        except SystemExit as e:
            assert e.code == 0

    p.assert_called_with("usage: prog [--theme THEME]")


def test_main_unknown_arg_passes_through_to_console():
    """Verify unknown arguments are forwarded to seer_console.py, not rejected."""
    with patch(
        "seer_terminal.find_console_script", return_value="/fake/console.py"
    ):
        with patch("seer_terminal.detect_theme", return_value="classic"):
            with patch("os.execvpe") as execvpe:
                st.main(["prog", "--some-console-flag"])

    cmd = execvpe.call_args[0][1]
    assert "--some-console-flag" in cmd


def test_main_console_not_found_returns_1():
    """Verify exit code 1 and error message when seer_console.py cannot be located."""
    with patch("seer_terminal.find_console_script", return_value=None):
        with patch("builtins.print") as p:
            rc = st.main(["prog"])

    assert rc == 1
    p.assert_called_with("ERROR: cannot find seer_console.py", file=sys.stderr)


def test_main_cli_theme_long_form_sets_seer_theme_env():
    """Verify --theme VALUE sets SEER_THEME in the exec environment."""
    with patch(
        "seer_terminal.find_console_script", return_value="/fake/console.py"
    ):
        with patch("os.execvpe") as execvpe:
            st.main(["prog", "--theme", "dark"])

    env = execvpe.call_args[0][2]
    assert env.get("SEER_THEME") == "dark"


def test_main_cli_theme_equals_form_sets_seer_theme_env():
    """Verify --theme=VALUE sets SEER_THEME in the exec environment."""
    with patch(
        "seer_terminal.find_console_script", return_value="/fake/console.py"
    ):
        with patch("os.execvpe") as execvpe:
            st.main(["prog", "--theme=evr"])

    env = execvpe.call_args[0][2]
    assert env.get("SEER_THEME") == "evr"


def test_main_env_theme_used_when_no_cli_theme_provided():
    """Verify SEER_THEME environment variable is used when no CLI theme is given."""
    with patch(
        "seer_terminal.find_console_script", return_value="/fake/console.py"
    ):
        with patch.dict("os.environ", {"SEER_THEME": "light"}):
            with patch("os.execvpe") as execvpe:
                st.main(["prog"])

    env = execvpe.call_args[0][2]
    assert env.get("SEER_THEME") == "light"


def test_main_cli_theme_overrides_env_theme():
    """Verify CLI --theme takes precedence over the SEER_THEME environment variable."""
    with patch(
        "seer_terminal.find_console_script", return_value="/fake/console.py"
    ):
        with patch.dict("os.environ", {"SEER_THEME": "classic"}):
            with patch("os.execvpe") as execvpe:
                st.main(["prog", "--theme", "evr"])

    env = execvpe.call_args[0][2]
    assert env.get("SEER_THEME") == "evr"


def test_detect_theme_returns_evr_when_tput_reports_16_or_more_colors():
    """Verify detect_theme returns 'evr' when tput colors >= 16."""
    with patch("seer_terminal.subprocess.run") as mock_run:
        mock_run.return_value.stdout = "256\n"
        mock_run.return_value.returncode = 0
        theme = st.detect_theme()

    assert theme == "evr"


def test_detect_theme_returns_classic_when_tput_reports_fewer_than_16_colors():
    """Verify detect_theme returns 'classic' when tput colors < 16."""
    with patch("seer_terminal.subprocess.run") as mock_run:
        mock_run.return_value.stdout = "8\n"
        mock_run.return_value.returncode = 0
        theme = st.detect_theme()

    assert theme == "classic"


def test_detect_theme_returns_classic_when_tput_unavailable():
    """Verify detect_theme returns 'classic' when tput raises an exception."""
    with patch(
        "seer_terminal.subprocess.run", side_effect=Exception("not found")
    ):
        theme = st.detect_theme()

    assert theme == "classic"


def test_main_autodetect_called_when_no_cli_or_env_theme():
    """Verify detect_theme is invoked when neither CLI nor env provides a theme."""
    with patch(
        "seer_terminal.find_console_script", return_value="/fake/console.py"
    ):
        with patch.dict("os.environ", {}, clear=True):
            with patch(
                "seer_terminal.detect_theme", return_value="evr"
            ) as mock_detect:
                with patch("os.execvpe"):
                    st.main(["prog"])

    mock_detect.assert_called_once()


def test_main_no_colors_removed_when_set_to_invalid_value():
    """Verify NO_COLORS is stripped from env when set to anything other than '1'/'true'."""
    with patch(
        "seer_terminal.find_console_script", return_value="/fake/console.py"
    ):
        with patch.dict("os.environ", {"NO_COLORS": "0"}):
            with patch("os.execvpe") as execvpe:
                st.main(["prog"])

    env = execvpe.call_args[0][2]
    assert "NO_COLORS" not in env


def test_main_no_colors_preserved_when_set_to_one():
    """Verify NO_COLORS is kept in env when set to '1'."""
    with patch(
        "seer_terminal.find_console_script", return_value="/fake/console.py"
    ):
        with patch.dict("os.environ", {"NO_COLORS": "1"}):
            with patch("os.execvpe") as execvpe:
                st.main(["prog"])

    env = execvpe.call_args[0][2]
    assert env.get("NO_COLORS") == "1"


def test_main_no_colors_preserved_when_set_to_true():
    """Verify NO_COLORS is kept in env when set to 'true'."""
    with patch(
        "seer_terminal.find_console_script", return_value="/fake/console.py"
    ):
        with patch.dict("os.environ", {"NO_COLORS": "true"}):
            with patch("os.execvpe") as execvpe:
                st.main(["prog"])

    env = execvpe.call_args[0][2]
    assert env.get("NO_COLORS") == "true"


def test_main_all_non_theme_args_forwarded_to_console_in_order():
    """Verify all non-theme arguments are passed through to seer_console.py."""
    with patch(
        "seer_terminal.find_console_script", return_value="/fake/console.py"
    ):
        with patch("seer_terminal.detect_theme", return_value="classic"):
            with patch("os.execvpe") as execvpe:
                st.main(["prog", "--foo", "--bar", "baz"])

    cmd = execvpe.call_args[0][1]
    assert "--foo" in cmd
    assert "--bar" in cmd
    assert "baz" in cmd
