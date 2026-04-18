"""Tests for seer_capture.py.

Verifies tcpdump launch behavior, config key resolution, flag correctness,
directory setup, and exit code handling.
"""

import os
import sys
from unittest.mock import patch

sys.path.append(os.path.abspath("Automation/bin"))
import seer_capture as sc

# -------------------------
# Tests
# -------------------------


def test_main_missing_iface_prints_usage_and_returns_2():
    """Verify missing interface argument prints usage to stderr and exits 2."""
    with patch("builtins.print") as p:
        rc = sc.main(["prog"])

    assert rc == 2
    p.assert_called_with("usage: seer-capture.sh <iface>", file=sys.stderr)


def test_main_no_config_uses_default_rotate_and_snaplen():
    """Verify tcpdump is called with default rotate=20 and snaplen=128 when config missing."""
    with patch("seer_capture.load_config", return_value={}):
        with patch("seer_capture.shutil.which", return_value="/usr/sbin/tcpdump"):
            with patch("os.execvp") as execvp:
                with patch("os.makedirs"):
                    with patch("subprocess.run"):
                        sc.main(["prog", "eth0"])

    execvp.assert_called_once()
    cmd = execvp.call_args[0][1]

    assert "-i" in cmd and "eth0" in cmd
    assert "-s" in cmd and "128" in cmd
    assert "-G" in cmd and "20" in cmd


def test_main_capture_block_config_passes_values_to_tcpdump():
    """Verify tcpdump uses rotate and snaplen from the nested 'capture:' config block."""
    cfg = {"capture": {"rotate_seconds": "30", "snaplen": "256"}}

    with patch("seer_capture.load_config", return_value=cfg):
        with patch("seer_capture.shutil.which", return_value="/usr/sbin/tcpdump"):
            with patch("os.execvp") as execvp:
                with patch("os.makedirs"):
                    with patch("subprocess.run"):
                        sc.main(["prog", "eth0"])

    cmd = execvp.call_args[0][1]

    assert "-G" in cmd and "30" in cmd
    assert "-s" in cmd and "256" in cmd


def test_main_flat_top_level_config_keys_are_ignored():
    """Verify flat top-level config keys are not used; only 'capture:' block is read."""
    cfg = {
        # These must be ignored — they are not nested under 'capture:'.
        "rotate_seconds": "999",
        "snaplen": "999",
    }

    with patch("seer_capture.load_config", return_value=cfg):
        with patch("seer_capture.shutil.which", return_value="/usr/sbin/tcpdump"):
            with patch("os.execvp") as execvp:
                with patch("os.makedirs"):
                    with patch("subprocess.run"):
                        sc.main(["prog", "eth0"])

    cmd = execvp.call_args[0][1]
    assert "999" not in cmd


def test_main_invalid_config_values_pass_through_without_coercion():
    """Verify non-numeric config values are forwarded to tcpdump without type casting."""
    cfg = {"capture": {"rotate_seconds": "notanint", "snaplen": "weird"}}

    with patch("seer_capture.load_config", return_value=cfg):
        with patch("seer_capture.shutil.which", return_value="/usr/sbin/tcpdump"):
            with patch("os.execvp") as execvp:
                with patch("os.makedirs"):
                    with patch("subprocess.run"):
                        sc.main(["prog", "eth0"])

    cmd = execvp.call_args[0][1]
    assert "notanint" in cmd
    assert "weird" in cmd


def test_main_ring_dir_created():
    """Verify os.makedirs is called to create the PCAP ring directory."""
    with patch("seer_capture.load_config", return_value={}):
        with patch("seer_capture.shutil.which", return_value="/usr/sbin/tcpdump"):
            with patch("os.makedirs") as makedirs:
                with patch("os.execvp"):
                    with patch("subprocess.run"):
                        sc.main(["prog", "eth0"])

    makedirs.assert_called_once()


def test_main_chown_attempted_on_ring_dir():
    """Verify chown is attempted on the ring directory after creation."""
    calls = []

    def run_mock(cmd, *args, **kwargs):
        calls.append(cmd)

    with patch("seer_capture.load_config", return_value={}):
        with patch("seer_capture.shutil.which", return_value="/usr/sbin/tcpdump"):
            with patch("subprocess.run", side_effect=run_mock):
                with patch("os.execvp"):
                    with patch("os.makedirs"):
                        sc.main(["prog", "eth0"])

    assert any("chown" in c for c in calls)


def test_main_tcpdump_exec_replaces_process():
    """Verify os.execvp is used for tcpdump — not subprocess.run."""
    with patch("seer_capture.load_config", return_value={}):
        with patch("seer_capture.shutil.which", return_value="/usr/sbin/tcpdump"):
            with patch("os.execvp") as execvp:
                with patch("subprocess.run") as run:
                    with patch("os.makedirs"):
                        sc.main(["prog", "eth0"])

    execvp.assert_called_once()
    assert not any("tcpdump" in str(c) for c in run.call_args_list)


def test_main_tcpdump_not_found_returns_127():
    """Verify exit code 127 and error message when tcpdump is absent from PATH."""
    with patch("seer_capture.load_config", return_value={}):
        with patch("seer_capture.shutil.which", return_value=None):
            with patch("os.makedirs"):
                with patch("subprocess.run"):
                    with patch("builtins.print") as p:
                        rc = sc.main(["prog", "eth0"])

    assert rc == 127
    p.assert_called_with("tcpdump not found in PATH", file=sys.stderr)


def test_main_output_file_uses_seer_timestamp_format():
    """Verify tcpdump -w argument uses SEER-%Y%m%d-%H%M%S.pcap format."""
    with patch("seer_capture.load_config", return_value={}):
        with patch("seer_capture.shutil.which", return_value="/usr/sbin/tcpdump"):
            with patch("os.execvp") as execvp:
                with patch("os.makedirs"):
                    with patch("subprocess.run"):
                        sc.main(["prog", "eth0"])

    cmd = execvp.call_args[0][1]
    assert any("SEER-%Y%m%d-%H%M%S.pcap" in c for c in cmd)


def test_main_no_dns_flag_passed_to_tcpdump():
    """Verify -n flag (disable DNS resolution) is present in tcpdump command."""
    with patch("seer_capture.load_config", return_value={}):
        with patch("seer_capture.shutil.which", return_value="/usr/sbin/tcpdump"):
            with patch("os.execvp") as execvp:
                with patch("os.makedirs"):
                    with patch("subprocess.run"):
                        sc.main(["prog", "eth0"])

    cmd = execvp.call_args[0][1]
    assert "-n" in cmd


def test_main_packet_buffered_flag_passed_to_tcpdump():
    """Verify -U flag (packet-buffered output) is present in tcpdump command."""
    with patch("seer_capture.load_config", return_value={}):
        with patch("seer_capture.shutil.which", return_value="/usr/sbin/tcpdump"):
            with patch("os.execvp") as execvp:
                with patch("os.makedirs"):
                    with patch("subprocess.run"):
                        sc.main(["prog", "eth0"])

    cmd = execvp.call_args[0][1]
    assert "-U" in cmd


def test_main_privilege_drop_flag_passed_to_tcpdump():
    """Verify -Z seer flag (privilege drop) is present and correctly valued."""
    with patch("seer_capture.load_config", return_value={}):
        with patch("seer_capture.shutil.which", return_value="/usr/sbin/tcpdump"):
            with patch("os.execvp") as execvp:
                with patch("os.makedirs"):
                    with patch("subprocess.run"):
                        sc.main(["prog", "eth0"])

    cmd = execvp.call_args[0][1]
    assert "-Z" in cmd
    assert cmd[cmd.index("-Z") + 1] == "seer"
