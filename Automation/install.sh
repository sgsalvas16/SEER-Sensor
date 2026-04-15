#!/usr/bin/env bash
set -euo pipefail

# Ensure non-interactive apt in all contexts
export DEBIAN_FRONTEND=noninteractive

# CLI args
ASSUME_YES=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) echo "Usage: $0 [--yes]"; exit 0 ;;
    *) echo "Unknown arg: $1"; exit 2 ;;
  esac
done

# deps we expect
APT_UPDATED=0
for pkg in python3-yaml python3-venv python3-pip; do
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    if [[ $APT_UPDATED -eq 0 ]]; then
      echo "Updating apt cache..."
      sudo -E apt-get update -qq || true
      APT_UPDATED=1
    fi
    echo "Installing $pkg..."
    sudo -E apt-get install -y -qq "$pkg"
  fi
done
if ! command -v tcpdump >/dev/null 2>&1; then
  if [[ $APT_UPDATED -eq 0 ]]; then
    sudo -E apt-get update -qq || true
  fi
  echo "Installing tcpdump..."
  sudo -E apt-get install -y -qq tcpdump
fi

# Resolve repository root (so script can be run from any cwd)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Create /opt/seer/etc directory and copy example config if no config exists
sudo mkdir -p /opt/seer/etc
if [[ ! -f /opt/seer/etc/seer.yml ]]; then
  if [[ -f "$REPO_ROOT/Automation/etc/seer.yml.example" ]]; then
    echo "Installing example configuration to /opt/seer/etc/seer.yml"
    sudo install -m 0644 "$REPO_ROOT/Automation/etc/seer.yml.example" /opt/seer/etc/seer.yml
  fi
fi

# install wrapper (standardize to /usr/local/bin)
echo "Installing /usr/local/bin/seer_capture.py"
sudo install -m 0755 "$REPO_ROOT/Automation/bin/seer_capture.py" /usr/local/bin/seer_capture.py

# install unit
echo "Installing systemd unit"
sudo install -m 0644 "$REPO_ROOT/Automation/systemd/seer-capture@.service" /etc/systemd/system/seer-capture@.service

# reload units
sudo systemctl daemon-reload
if [[ $ASSUME_YES -eq 1 ]]; then
  echo "Running setup wizard (non-interactive defaults with timeout)"
  if ! timeout "${WIZ_TIMEOUT:-60s}" sudo -E "$REPO_ROOT/Automation/SEER/setup_wizard.py" --yes; then
    echo "WARNING: setup wizard --yes timed out or failed; continuing with defaults." >&2
  fi
else
  echo "Running setup wizard (interactive)"
  sudo -E "$REPO_ROOT/Automation/SEER/setup_wizard.py" || true
fi

# Install mover script and units if present
if [[ -f "$REPO_ROOT/Automation/SEER/move_oldest.py" ]]; then
  echo "Installing mover script to /usr/local/bin/seer-move-oldest.py"
  sudo install -m 0755 "$REPO_ROOT/Automation/SEER/move_oldest.py" /usr/local/bin/seer-move-oldest.py
fi

# Install console (TUI) to /usr/local/bin
if [[ -f "$REPO_ROOT/Automation/bin/seer_console.py" ]]; then
  echo "Installing seer-console to /usr/local/bin/seer-console"
  sudo install -m 0755 "$REPO_ROOT/Automation/bin/seer_console.py" /usr/local/bin/seer-console
  # Provide a simple wrapper so typing 'seer' launches the console
  echo "Installing wrapper /usr/local/bin/seer"
  sudo tee /usr/local/bin/seer >/dev/null <<'EOS'
#!/bin/bash
# Wrapper to run seer-console (with sudo to manage systemd and mounts)
exec sudo /usr/local/bin/seer-console "$@"
EOS
  sudo chmod 0755 /usr/local/bin/seer
fi

# Install Zeek wrapper
if [[ -f "$REPO_ROOT/Automation/seer-zeek.sh" ]]; then
  echo "Installing seer-zeek.sh to /usr/local/bin/seer-zeek.sh"
  sudo install -m 0755 "$REPO_ROOT/Automation/seer-zeek.sh" /usr/local/bin/seer-zeek.sh
fi

# Install Zeek systemd unit
if [[ -f "$REPO_ROOT/Automation/systemd/seer-zeek@.service" ]]; then
  echo "Installing seer-zeek@.service"
  sudo install -m 0644 "$REPO_ROOT/Automation/systemd/seer-zeek@.service" /etc/systemd/system/seer-zeek@.service
fi

# Install hotswap script and service
if [[ -f "$REPO_ROOT/Automation/SEER/seer_hotswap.py" ]]; then
  echo "Installing seer_hotswap.py to /usr/local/bin/seer_hotswap.py"
  sudo install -m 0755 "$REPO_ROOT/Automation/SEER/seer_hotswap.py" /usr/local/bin/seer_hotswap.py
fi
if [[ -f "$REPO_ROOT/Automation/systemd/seer-hotswap.service" ]]; then
  echo "Installing seer-hotswap.service"
  sudo install -m 0644 "$REPO_ROOT/Automation/systemd/seer-hotswap.service" /etc/systemd/system/seer-hotswap.service
fi

# Install Scout Receiver (HTTP server for SCOUT Agent data)
if [[ -d "$REPO_ROOT/Automation/SEER/scout_receiver" ]]; then
  echo "Installing Scout Receiver module..."

  # Create directories for Scout Receiver
  sudo mkdir -p /var/seer/scout_data
  sudo mkdir -p /opt/seer/Automation/SEER/scout_receiver
  sudo mkdir -p /opt/seer/Automation/SEER/scout_receiver/utils

  # Create __init__.py for SEER package so Python can find the module
  sudo touch /opt/seer/Automation/__init__.py
  sudo touch /opt/seer/Automation/SEER/__init__.py

  # Copy scout_receiver module to /opt/seer
  sudo cp -r "$REPO_ROOT/Automation/SEER/scout_receiver"/* /opt/seer/Automation/SEER/scout_receiver/

  # Set ownership
  sudo chown -R seer:seer /var/seer/scout_data 2>/dev/null || true
  sudo chown -R seer:seer /opt/seer/Automation 2>/dev/null || true

  # Create virtualenv if it doesn't exist or is broken, and install dependencies
  # Always recreate venv to ensure clean state
  echo "Creating Python virtualenv at /opt/seer/venv..."
  sudo rm -rf /opt/seer/venv 2>/dev/null || true
  if ! sudo python3 -m venv /opt/seer/venv; then
    echo "ERROR: Failed to create virtualenv. Ensure python3-venv is installed." >&2
    echo "Trying: sudo apt-get install -y python3-venv" >&2
    sudo -E apt-get install -y python3-venv
    if ! sudo python3 -m venv /opt/seer/venv; then
      echo "ERROR: Still cannot create venv. Will use system Python." >&2
    fi
  fi
  if [[ -d /opt/seer/venv ]]; then
    sudo chown -R seer:seer /opt/seer/venv
  fi

  # Install Python dependencies for Scout Receiver
  if [[ -f "$REPO_ROOT/Automation/SEER/scout_receiver/requirements.txt" ]]; then
    echo "Installing Scout Receiver Python dependencies..."
    DEPS_INSTALLED=0

    # Try venv pip first
    if [[ -x /opt/seer/venv/bin/pip ]]; then
      echo "  Using virtualenv pip..."
      sudo /opt/seer/venv/bin/pip install --upgrade pip -q 2>/dev/null || true
      if sudo /opt/seer/venv/bin/pip install -r "$REPO_ROOT/Automation/SEER/scout_receiver/requirements.txt"; then
        # Verify it actually worked in the venv
        if /opt/seer/venv/bin/python -c "import aiohttp" 2>/dev/null; then
          DEPS_INSTALLED=1
          echo "  Scout Receiver dependencies installed in virtualenv."
        else
          echo "  WARNING: pip reported success but aiohttp not importable in venv"
        fi
      fi
    fi

    # Fallback to system pip if venv failed
    if [[ $DEPS_INSTALLED -eq 0 ]]; then
      echo "  Falling back to system pip..."
      if sudo pip3 install --break-system-packages -r "$REPO_ROOT/Automation/SEER/scout_receiver/requirements.txt" 2>/dev/null; then
        DEPS_INSTALLED=1
      elif sudo pip3 install -r "$REPO_ROOT/Automation/SEER/scout_receiver/requirements.txt" 2>/dev/null; then
        DEPS_INSTALLED=1
      fi
    fi

    # Final verification
    if /opt/seer/venv/bin/python -c "import aiohttp" 2>/dev/null; then
      echo "  Verified: aiohttp is available in venv."
    elif python3 -c "import aiohttp" 2>/dev/null; then
      echo "  Verified: aiohttp is available in system Python."
    else
      echo "ERROR: aiohttp not importable after install. Scout Receiver will not work." >&2
      echo "  Try manually: sudo /opt/seer/venv/bin/pip install aiohttp aiohttp-cors pyyaml jsonschema" >&2
    fi
  fi

  # Install Scout Receiver systemd service
  if [[ -f "$REPO_ROOT/Automation/systemd/seer-scout-receiver.service" ]]; then
    echo "Installing seer-scout-receiver.service"
    sudo install -m 0644 "$REPO_ROOT/Automation/systemd/seer-scout-receiver.service" /etc/systemd/system/seer-scout-receiver.service
  fi
fi

# Ensure log/state directory exists with correct ownership
sudo mkdir -p /var/log/seer
sudo chown seer:seer /var/log/seer || true

if [[ -f "$REPO_ROOT/Automation/systemd/seer-move-oldest.service" ]]; then
  echo "Installing seer-move-oldest.service"
  sudo install -m 0644 "$REPO_ROOT/Automation/systemd/seer-move-oldest.service" /etc/systemd/system/seer-move-oldest.service
fi
if [[ -f "$REPO_ROOT/Automation/systemd/seer-move-oldest.timer" ]]; then
  echo "Installing seer-move-oldest.timer"
  sudo install -m 0644 "$REPO_ROOT/Automation/systemd/seer-move-oldest.timer" /etc/systemd/system/seer-move-oldest.timer
fi

echo "Reloading systemd daemon and enabling services"
sudo systemctl daemon-reload

# Enable and start capture for detected interface (use what was written to /opt/seer/etc/seer.yml if present)
INTERFACE="enp2s0"
if [[ -f /opt/seer/etc/seer.yml ]]; then
  INTERFACE=$(python3 - <<'PY'
import yaml
try:
    cfg = yaml.safe_load(open('/opt/seer/etc/seer.yml'))
    print(cfg.get('interface', 'enp2s0'))
except Exception:
    print('enp2s0')
PY
  )
fi

# Create a persistent NIC setup unit to ensure PROMISC and offloads are configured on boot
echo "Installing persistent NIC monitor setup: seer-net-setup@.service"
sudo tee /usr/local/bin/seer-net-setup.sh >/dev/null <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
IFACE=${1:?iface required}
ip link set dev "$IFACE" up || true
ip link set dev "$IFACE" promisc on || true
if command -v ethtool >/dev/null 2>&1; then
  ethtool -K "$IFACE" gro off lro off tso off gso off || true
fi
exit 0
EOS
sudo chmod 0755 /usr/local/bin/seer-net-setup.sh

sudo tee /etc/systemd/system/seer-net-setup@.service >/dev/null <<'EOS'
[Unit]
Description=SEER NIC monitor-mode setup for %i
After=network-pre.target
Before=network.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/usr/local/bin/seer-net-setup.sh %i
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOS

sudo systemctl daemon-reload
echo "Enabling seer-net-setup@${INTERFACE}.service"
sudo systemctl enable --now seer-net-setup@${INTERFACE}.service || true

# Also apply NIC settings immediately in case the unit ordering hasn't run yet
echo "Configuring monitor port now: ${INTERFACE} (UP, PROMISC, offloads off)"
sudo /usr/local/bin/seer-net-setup.sh "${INTERFACE}" || true

echo "Enabling and starting seer-capture@${INTERFACE}.service"
sudo systemctl enable --now seer-capture@${INTERFACE}.service || true

# Install wait-for-link helper and drop-in so capture waits for link at boot
WAIT_LINK_TIMEOUT=60
if [[ -f /opt/seer/etc/seer.yml ]]; then
  WAIT_LINK_TIMEOUT=$(python3 - <<'PY'
import yaml
try:
    cfg=yaml.safe_load(open('/opt/seer/etc/seer.yml')) or {}
    print(int(cfg.get('wait_link_timeout', 60)))
except Exception:
    print(60)
PY
)
fi

if [[ -f "$REPO_ROOT/Automation/bin/seer_wait_link.py" ]]; then
  echo "Installing seer_wait_link helper"
  sudo install -m 0755 "$REPO_ROOT/Automation/bin/seer_wait_link.py" /usr/local/bin/seer_wait_link.py || true
  sudo chown root:root /usr/local/bin/seer_wait_link.py || true
  echo "Writing systemd drop-in for seer-capture to wait for link"
  sudo mkdir -p /etc/systemd/system/seer-capture@.service.d || true
  sudo tee /etc/systemd/system/seer-capture@.service.d/wait-link.conf >/dev/null <<EOS
[Unit]
Description=Wait for link before starting capture
Before=seer-capture@%i.service

[Service]
ExecStartPre=/usr/bin/python3 /usr/local/bin/seer_wait_link.py %i ${WAIT_LINK_TIMEOUT}
EOS
  sudo systemctl daemon-reload || true
fi

# Enable and start Zeek (if unit is installed and zeek binary exists)
if [[ -f /etc/systemd/system/seer-zeek@.service ]]; then
  if command -v zeek >/dev/null 2>&1; then
    echo "Enabling and starting seer-zeek@${INTERFACE}.service"
    sudo systemctl enable --now seer-zeek@${INTERFACE}.service || true
  elif [[ -x /opt/zeek/bin/zeek ]]; then
    echo "Zeek found at /opt/zeek/bin; proceeding to enable service"
    sudo systemctl enable --now seer-zeek@${INTERFACE}.service || true
  else
    echo "WARNING: zeek binary not found; skipping seer-zeek@ enable/start." >&2
  fi
else
  echo "WARNING: seer-zeek@.service unit file not found; skipping seer-zeek@ enable/start." >&2
fi

if systemctl list-unit-files | grep -q seer-move-oldest.timer; then
  echo "Enabling and starting seer-move-oldest.timer"
  sudo systemctl enable --now seer-move-oldest.timer || true
fi

# Enable and start hotswap unconditionally if the unit was installed
if [[ -f /etc/systemd/system/seer-hotswap.service ]]; then
  echo "Enabling and starting seer-hotswap.service"
  sudo systemctl enable --now seer-hotswap.service || true
fi

# Enable and start Scout Receiver if the unit was installed
if [[ -f /etc/systemd/system/seer-scout-receiver.service ]]; then
  echo "Enabling and starting seer-scout-receiver.service"
  sudo systemctl enable --now seer-scout-receiver.service || true
fi

echo "Verification: listing units and recent journal entries"
systemctl status seer-capture@${INTERFACE}.service --no-pager || true
systemctl list-timers --all | grep seer || true
sudo journalctl -u seer-capture@${INTERFACE}.service -n 30 --no-pager || true

echo "Install finished. If setup wrote /opt/seer/etc/seer.yml, review it and adjust as needed."

# Install verifier and run it
if [[ -f "$REPO_ROOT/Automation/bin/seer_verify_install.py" ]]; then
  echo "Installing verifier to /usr/local/bin/seer_verify_install.py"
  sudo install -m 0755 "$REPO_ROOT/Automation/bin/seer_verify_install.py" /usr/local/bin/seer_verify_install.py
  echo "Running post-install verification (this may trigger mover once)"
  if ! timeout "${VERIFY_TIMEOUT:-120s}" sudo /usr/bin/python3 /usr/local/bin/seer_verify_install.py; then
    if [[ $ASSUME_YES -eq 1 ]]; then
      echo "WARNING: Post-install verification failed or timed out. Check seer-move-oldest and seer-capture logs." >&2
    else
      echo "Post-install verification failed. Check journalctl -u seer-move-oldest.service and seer-capture logs." >&2
      exit 4
    fi
  fi
fi
