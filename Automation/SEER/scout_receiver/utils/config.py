"""
Configuration Management for Scout Receiver

Loads configuration from the main seer.yml file and provides
access to scout_receiver-specific settings.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

# Default configuration path
DEFAULT_CONFIG_PATH = Path("/opt/seer/etc/seer.yml")

# Environment variable override
ENV_CONFIG_PATH = "SEER_CONFIG"


class ScoutReceiverConfig:
    """Configuration manager for Scout Receiver.

    Reads from the main seer.yml configuration file and extracts
    the scout_receiver section with sensible defaults.
    """

    def __init__(self, config_path: Optional[Path] = None):
        """Initialize configuration manager.

        Args:
            config_path: Optional path to configuration file.
                        Falls back to SEER_CONFIG env var or default path.
        """
        if config_path:
            self.config_path = Path(config_path)
        elif os.environ.get(ENV_CONFIG_PATH):
            self.config_path = Path(os.environ[ENV_CONFIG_PATH])
        else:
            self.config_path = DEFAULT_CONFIG_PATH

        self._full_config = self._load_full_config()
        self._config = self._extract_receiver_config()

    def _load_full_config(self) -> Dict[str, Any]:
        """Load the full seer.yml configuration file."""
        try:
            if self.config_path.exists():
                with open(self.config_path) as f:
                    return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Warning: Failed to load config from {self.config_path}: {e}")
        return {}

    def _extract_receiver_config(self) -> Dict[str, Any]:
        """Extract scout_receiver section with defaults."""
        receiver_config = self._full_config.get("scout_receiver", {})

        # Merge with defaults
        defaults = self._get_defaults()
        return self._deep_merge(defaults, receiver_config)

    def _get_defaults(self) -> Dict[str, Any]:
        """Return default configuration values."""
        return {
            "enabled": True,
            "server": {
                "host": "0.0.0.0",
                "port": 8080,
                "cors_enabled": True,
                "max_request_size_mb": 50,
            },
            "storage": {
                "data_dir": "/var/seer/scout_data",
                "max_file_size_mb": 100,
                "rotate_files": True,
                "retention_days": 30,
                "organize_by_date": True,
            },
            "validation": {
                "enforce_schema": True,
                "verify_checksums": True,
                "max_data_size_mb": 50,
                "strict_mode": False,
            },
            "heartbeat": {
                "enabled": True,
                "interval_seconds": 30,
                "response_delay_ms": 0,
            },
            "logging": {
                "level": "INFO",
                "format": "structured",
                "file": "/var/log/seer/scout_receiver.log",
                "max_size_mb": 50,
                "backup_count": 5,
            },
            "web_interface": {
                "enabled": True,
                "static_path": "/opt/seer/www/scout_dashboard",
            },
        }

    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """Deep merge two dictionaries, with override taking precedence."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key.

        Args:
            key: Dot-separated key path (e.g., 'server.port')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split(".")
        value = self._config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get an entire configuration section.

        Args:
            section: Section name (e.g., 'server', 'storage')

        Returns:
            Section dictionary or empty dict
        """
        return self._config.get(section, {})

    def get_full_config(self) -> Dict[str, Any]:
        """Get the complete scout_receiver configuration."""
        return self._config.copy()

    def get_seer_config(self, key: str, default: Any = None) -> Any:
        """Get a value from the main SEER configuration
        (outside scout_receiver).

        Args:
            key: Configuration key
            default: Default value if not found

        Returns:
            Configuration value or default
        """
        return self._full_config.get(key, default)

    def is_enabled(self) -> bool:
        """Check if Scout Receiver is enabled."""
        return self.get("enabled", True)

    def __repr__(self) -> str:
        return f"ScoutReceiverConfig(path={self.config_path}, enabled={self.is_enabled()})"


def load_config(config_path: Optional[Path] = None) -> ScoutReceiverConfig:
    """Convenience function to load configuration.

    Args:
        config_path: Optional path to configuration file

    Returns:
        ScoutReceiverConfig instance
    """
    return ScoutReceiverConfig(config_path)
