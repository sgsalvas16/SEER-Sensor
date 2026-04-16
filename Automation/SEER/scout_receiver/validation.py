"""
Data Validation for Scout Receiver

Provides comprehensive data validation including schema validation,
checksum verification, and format checking for SCOUT Agent data.
"""

import gzip
import hashlib
import json
import zlib
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from .utils.logging import get_logger

logger = get_logger(__name__)


class ValidationResult:
    """Container for validation results with detailed information."""

    def __init__(
        self,
        is_valid: bool,
        message: str = "",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize validation result.

        Args:
            is_valid: Whether validation passed
            message: Validation message or error description
            details: Additional validation details
        """
        self.is_valid = is_valid
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert validation result to dictionary."""
        return {
            "is_valid": self.is_valid,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    def __bool__(self) -> bool:
        return self.is_valid

    def __repr__(self) -> str:
        status = "VALID" if self.is_valid else "INVALID"
        return f"ValidationResult({status}: {self.message})"


class DataValidator:
    """Comprehensive data validator for SCOUT Agent data formats."""

    # Required fields for data envelope
    ENVELOPE_REQUIRED_FIELDS = ["data"]
    ENVELOPE_OPTIONAL_FIELDS = [
        "agent_version",
        "host_id",
        "timestamp",
        "data_type",
        "checksum",
        "compression",
    ]

    # Valid data types
    VALID_DATA_TYPES = ["events", "system", "mixed", "unknown"]

    # Supported compression methods
    SUPPORTED_COMPRESSIONS = ["none", "gzip", "zlib"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize data validator.

        Args:
            config: Optional validation configuration
        """
        config = config or {}
        self.enforce_schema = config.get("enforce_schema", True)
        self.verify_checksums = config.get("verify_checksums", True)
        self.max_data_size = config.get("max_data_size_mb", 50) * 1024 * 1024
        self.strict_mode = config.get("strict_mode", False)

        # Statistics tracking
        self.stats = {
            "total_validations": 0,
            "successful_validations": 0,
            "failed_validations": 0,
            "checksum_failures": 0,
            "format_errors": 0,
            "compression_errors": 0,
            "size_errors": 0,
        }

    def validate_data_envelope(self, data: Dict[str, Any]) -> ValidationResult:
        """Validate SCOUT Agent data envelope format.

        Args:
            data: Data envelope to validate

        Returns:
            ValidationResult with validation outcome
        """
        self.stats["total_validations"] += 1

        try:
            # Check for required fields
            missing_fields = [f for f in self.ENVELOPE_REQUIRED_FIELDS if f not in data]
            if missing_fields:
                self.stats["failed_validations"] += 1
                self.stats["format_errors"] += 1
                return ValidationResult(
                    False,
                    f"Missing required fields: {missing_fields}",
                    {"missing_fields": missing_fields},
                )

            # Build validation details
            details = {
                "schema_valid": True,
                "agent_version": data.get("agent_version", "unknown"),
                "host_id": data.get("host_id", "unknown"),
                "data_type": data.get("data_type", "unknown"),
                "compression": data.get("compression", "none"),
            }

            # Calculate data size
            data_content = data.get("data", "")
            if isinstance(data_content, (dict, list)):
                data_size = len(json.dumps(data_content))
            elif isinstance(data_content, bytes):
                data_size = len(data_content)
            else:
                data_size = len(str(data_content))

            details["data_size"] = data_size

            # Check data size
            if data_size > self.max_data_size:
                self.stats["failed_validations"] += 1
                self.stats["size_errors"] += 1
                return ValidationResult(
                    False,
                    f"Data size {data_size} exceeds maximum {self.max_data_size}",
                    details,
                )

            # Validate compression type
            compression = details["compression"]
            if compression not in self.SUPPORTED_COMPRESSIONS:
                self.stats["failed_validations"] += 1
                self.stats["compression_errors"] += 1
                return ValidationResult(False, f"Unsupported compression: {compression}", details)

            # Validate data type (if strict mode)
            if self.strict_mode:
                data_type = details["data_type"]
                if data_type not in self.VALID_DATA_TYPES:
                    self.stats["failed_validations"] += 1
                    self.stats["format_errors"] += 1
                    return ValidationResult(False, f"Invalid data type: {data_type}", details)

            self.stats["successful_validations"] += 1
            return ValidationResult(True, "Data envelope validation successful", details)

        except Exception as e:
            self.stats["failed_validations"] += 1
            logger.error(f"Validation exception: {e}")
            return ValidationResult(False, f"Validation error: {str(e)}", {"exception": str(e)})

    def validate_event_data(self, events: List[Dict[str, Any]]) -> ValidationResult:
        """Validate event log data format.

        Supports both legacy format (type, timestamp) and ASIM schema
        (EventType, TimeGenerated).

        Args:
            events: List of event entries to validate

        Returns:
            ValidationResult with validation outcome
        """
        if not isinstance(events, list):
            return ValidationResult(
                False,
                "Event data must be a list",
                {"actual_type": type(events).__name__},
            )

        details = {
            "total_events": len(events),
            "valid_events": 0,
            "invalid_events": 0,
            "validation_errors": [],
            "schema_type": "unknown",
        }

        # Support both legacy and ASIM schema field names
        legacy_type_fields = ["type", "timestamp"]
        asim_type_fields = ["EventType", "TimeGenerated"]

        for i, event in enumerate(events):
            if not isinstance(event, dict):
                details["invalid_events"] += 1
                details["validation_errors"].append({"index": i, "error": "Event must be a dictionary"})
                continue

            # Check for ASIM schema fields first
            has_asim = all(f in event for f in asim_type_fields)
            has_legacy = all(f in event for f in legacy_type_fields)

            if has_asim:
                details["valid_events"] += 1
                if details["schema_type"] == "unknown":
                    details["schema_type"] = "ASIM"
            elif has_legacy:
                details["valid_events"] += 1
                if details["schema_type"] == "unknown":
                    details["schema_type"] = "legacy"
            else:
                # Check what's missing from either schema
                missing_asim = [f for f in asim_type_fields if f not in event]
                missing_legacy = [f for f in legacy_type_fields if f not in event]
                details["invalid_events"] += 1
                details["validation_errors"].append(
                    {
                        "index": i,
                        "error": (f"Missing fields (ASIM: {missing_asim}, legacy: {missing_legacy})"),
                    }
                )

        is_valid = details["invalid_events"] == 0
        message = (
            f"Event validation: {details['valid_events']} valid, "
            f"{details['invalid_events']} invalid "
            f"(schema: {details['schema_type']})"
        )

        return ValidationResult(is_valid, message, details)

    def validate_system_data(self, changes: List[Dict[str, Any]]) -> ValidationResult:
        """Validate system state change data format.

        Supports both legacy format (type, timestamp) and ASIM schema
        (EventType, TimeGenerated, EventSchema).

        Args:
            changes: List of system changes to validate

        Returns:
            ValidationResult with validation outcome
        """
        if not isinstance(changes, list):
            return ValidationResult(
                False,
                "System change data must be a list",
                {"actual_type": type(changes).__name__},
            )

        details = {
            "total_changes": len(changes),
            "valid_changes": 0,
            "invalid_changes": 0,
            "validation_errors": [],
            "schema_type": "unknown",
            "schema_breakdown": {},
        }

        # Support both legacy and ASIM schema field names
        legacy_fields = ["type", "timestamp"]
        asim_fields = ["EventType", "TimeGenerated"]

        for i, change in enumerate(changes):
            if not isinstance(change, dict):
                details["invalid_changes"] += 1
                details["validation_errors"].append({"index": i, "error": "Change must be a dictionary"})
                continue

            # Check for ASIM schema fields first
            has_asim = all(f in change for f in asim_fields)
            has_legacy = all(f in change for f in legacy_fields)

            if has_asim:
                details["valid_changes"] += 1
                if details["schema_type"] == "unknown":
                    details["schema_type"] = "ASIM"
                # Track ASIM schema types
                event_schema = change.get("EventSchema", "Unknown")
                details["schema_breakdown"][event_schema] = details["schema_breakdown"].get(event_schema, 0) + 1
            elif has_legacy:
                details["valid_changes"] += 1
                if details["schema_type"] == "unknown":
                    details["schema_type"] = "legacy"
            else:
                # Check what's missing from either schema
                missing_asim = [f for f in asim_fields if f not in change]
                missing_legacy = [f for f in legacy_fields if f not in change]
                details["invalid_changes"] += 1
                details["validation_errors"].append(
                    {
                        "index": i,
                        "error": (f"Missing fields (ASIM: {missing_asim}, legacy: {missing_legacy})"),
                    }
                )

        is_valid = details["invalid_changes"] == 0
        message = (
            f"System change validation: {details['valid_changes']} valid, "
            f"{details['invalid_changes']} invalid "
            f"(schema: {details['schema_type']})"
        )

        return ValidationResult(is_valid, message, details)

    def decompress_data(self, data: Union[str, bytes], compression: str) -> Tuple[bool, Union[str, bytes], str]:
        """Decompress data using specified compression method.

        Args:
            data: Compressed data to decompress
            compression: Compression method ('gzip', 'zlib', 'none')

        Returns:
            Tuple of (success, decompressed_data, error_message)
        """
        try:
            if compression == "none" or not compression:
                return True, data, ""

            if isinstance(data, str):
                data = data.encode("utf-8")

            if compression == "gzip":
                decompressed = gzip.decompress(data)
                return True, decompressed.decode("utf-8"), ""

            if compression == "zlib":
                decompressed = zlib.decompress(data)
                return True, decompressed.decode("utf-8"), ""

            return False, data, f"Unsupported compression: {compression}"

        except Exception as e:
            self.stats["compression_errors"] += 1
            return False, data, f"Decompression failed: {str(e)}"

    def validate_checksum(
        self,
        data: Union[str, bytes],
        expected_checksum: str,
        algorithm: str = "sha256",
    ) -> ValidationResult:
        """Validate data integrity using checksum.

        Args:
            data: Data to validate
            expected_checksum: Expected checksum value
                (may include algorithm prefix)
            algorithm: Hash algorithm to use

        Returns:
            ValidationResult with checksum validation outcome
        """
        try:
            # Handle algorithm prefix in checksum (e.g., "sha256:abc123...")
            if ":" in expected_checksum:
                algorithm, expected_checksum = expected_checksum.split(":", 1)

            # Convert data to bytes
            if isinstance(data, str):
                data_bytes = data.encode("utf-8")
            else:
                data_bytes = data

            # Calculate checksum
            if algorithm == "sha256":
                calculated = hashlib.sha256(data_bytes).hexdigest()
            elif algorithm == "md5":
                calculated = hashlib.md5(data_bytes).hexdigest()
            elif algorithm == "sha1":
                calculated = hashlib.sha1(data_bytes).hexdigest()
            else:
                return ValidationResult(
                    False,
                    f"Unsupported hash algorithm: {algorithm}",
                    {"algorithm": algorithm},
                )

            # Compare checksums (case-insensitive)
            is_valid = calculated.lower() == expected_checksum.lower()

            details = {
                "algorithm": algorithm,
                "expected": expected_checksum,
                "calculated": calculated,
                "data_size": len(data_bytes),
            }

            if not is_valid:
                self.stats["checksum_failures"] += 1
                return ValidationResult(False, "Checksum mismatch", details)

            return ValidationResult(True, "Checksum valid", details)

        except Exception as e:
            self.stats["checksum_failures"] += 1
            return ValidationResult(
                False,
                f"Checksum validation error: {str(e)}",
                {"exception": str(e)},
            )

    def validate_ndjson_format(self, data: str) -> ValidationResult:
        """Validate NDJSON (Newline Delimited JSON) format.

        Args:
            data: NDJSON data string to validate

        Returns:
            ValidationResult with format validation outcome
        """
        try:
            lines = data.strip().split("\n")
            details = {
                "total_lines": len(lines),
                "valid_lines": 0,
                "invalid_lines": 0,
                "parse_errors": [],
            }

            for i, line in enumerate(lines):
                if not line.strip():
                    continue

                try:
                    json.loads(line)
                    details["valid_lines"] += 1
                except json.JSONDecodeError as e:
                    details["invalid_lines"] += 1
                    details["parse_errors"].append(
                        {
                            "line": i + 1,
                            "error": str(e),
                            "preview": line[:100] + "..." if len(line) > 100 else line,
                        }
                    )

            is_valid = details["invalid_lines"] == 0
            message = f"NDJSON validation: {details['valid_lines']} valid, {details['invalid_lines']} invalid"

            return ValidationResult(is_valid, message, details)

        except Exception as e:
            return ValidationResult(
                False,
                f"NDJSON validation error: {str(e)}",
                {"exception": str(e)},
            )

    def get_validation_statistics(self) -> Dict[str, Any]:
        """Get validation statistics.

        Returns:
            Dictionary containing validation statistics
        """
        stats = self.stats.copy()

        if stats["total_validations"] > 0:
            stats["success_rate"] = stats["successful_validations"] / stats["total_validations"]
            stats["failure_rate"] = stats["failed_validations"] / stats["total_validations"]
        else:
            stats["success_rate"] = 0.0
            stats["failure_rate"] = 0.0

        return stats

    def reset_statistics(self) -> None:
        """Reset validation statistics counters."""
        for key in self.stats:
            self.stats[key] = 0


def calculate_checksum(data: Union[str, bytes], algorithm: str = "sha256") -> str:
    """Calculate checksum for data.

    Args:
        data: Data to calculate checksum for
        algorithm: Hash algorithm to use

    Returns:
        Calculated checksum as hexadecimal string
    """
    if isinstance(data, str):
        data_bytes = data.encode("utf-8")
    else:
        data_bytes = data

    if algorithm == "sha256":
        return hashlib.sha256(data_bytes).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(data_bytes).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data_bytes).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
