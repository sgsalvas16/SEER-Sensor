"""
Logging Configuration for Scout Receiver

Provides structured logging capabilities with file and console output.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Dict, Optional

# Module-level logger cache
_loggers: Dict[str, logging.Logger] = {}

# Default log format
PLAIN_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
STRUCTURED_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"


class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured log output."""

    def __init__(self, include_extra: bool = True):
        super().__init__(STRUCTURED_FORMAT)
        self.include_extra = include_extra

    def format(self, record: logging.LogRecord) -> str:
        # Base formatting
        message = super().format(record)

        # Add extra fields if present
        if self.include_extra and hasattr(record, "extra_data"):
            extra = record.extra_data
            if extra:
                extra_str = " | ".join(f"{k}={v}" for k, v in extra.items())
                message = f"{message} | {extra_str}"

        return message


class PacketLogger:
    """Specialized logger for packet/data reception logging."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def log_packet_received(self, source_ip: str, packet_size: int, protocol: str, timestamp: float) -> None:
        """Log packet reception event."""
        self.logger.info(
            f"Packet received from {source_ip}",
            extra={
                "extra_data": {
                    "source_ip": source_ip,
                    "size": packet_size,
                    "protocol": protocol,
                    "timestamp": timestamp,
                }
            },
        )

    def log_data_extracted(
        self,
        source_ip: str,
        data_size: int,
        data_type: str,
        checksum: str,
        processing_time: float,
    ) -> None:
        """Log successful data extraction."""
        self.logger.info(
            f"Data extracted: {data_type} from {source_ip}",
            extra={
                "extra_data": {
                    "source_ip": source_ip,
                    "data_size": data_size,
                    "data_type": data_type,
                    "checksum": checksum[:16] if checksum else "none",
                    "processing_time_ms": round(processing_time * 1000, 2),
                }
            },
        )

    def log_validation_error(
        self,
        source_ip: str,
        error_type: str,
        error_message: str,
        data_size: int,
    ) -> None:
        """Log validation error."""
        self.logger.warning(
            f"Validation error from {source_ip}: {error_type}",
            extra={
                "extra_data": {
                    "source_ip": source_ip,
                    "error_type": error_type,
                    "error_message": error_message,
                    "data_size": data_size,
                }
            },
        )


def setup_logging(
    level: str = "INFO",
    format_type: str = "structured",
    log_file: Optional[str] = None,
    max_size_mb: int = 50,
    backup_count: int = 5,
) -> None:
    """Configure logging for the Scout Receiver.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        format_type: 'structured' or 'plain'
        log_file: Optional path to log file
        max_size_mb: Maximum log file size in MB
        backup_count: Number of backup files to keep
    """
    # Get numeric level
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Create formatter
    if format_type == "structured":
        formatter = StructuredFormatter()
    else:
        formatter = logging.Formatter(PLAIN_FORMAT)

    # Configure root logger for scout_receiver
    root_logger = logging.getLogger("scout_receiver")
    root_logger.setLevel(numeric_level)

    # Clear existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_size_mb * 1024 * 1024,
                backupCount=backup_count,
            )
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            root_logger.warning(f"Failed to setup file logging: {e}")


def get_logger(name: str) -> logging.Logger:
    """Get a logger for the given module name.

    Args:
        name: Module name (usually __name__)

    Returns:
        Configured logger instance
    """
    # Prefix with scout_receiver if not already
    if not name.startswith("scout_receiver"):
        name = f"scout_receiver.{name}"

    if name not in _loggers:
        _loggers[name] = logging.getLogger(name)

    return _loggers[name]


def get_packet_logger() -> PacketLogger:
    """Get the specialized packet logger.

    Returns:
        PacketLogger instance
    """
    return PacketLogger(get_logger("packets"))
