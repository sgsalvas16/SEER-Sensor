"""
Data Storage for Scout Receiver

Handles persistent storage of received SCOUT Agent data with
organized file structure and integrity tracking.
"""

import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from .utils.logging import get_logger

logger = get_logger(__name__)


class ScoutDataStorage:
    """Persistent storage manager for SCOUT Agent data."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize storage manager.

        Args:
            config: Storage configuration dictionary
        """
        config = config or {}

        self.data_dir = Path(config.get("data_dir", "/var/seer/scout_data"))
        self.max_file_size = config.get("max_file_size_mb", 100) * 1024 * 1024
        self.rotate_files = config.get("rotate_files", True)
        self.retention_days = config.get("retention_days", 30)
        self.organize_by_date = config.get("organize_by_date", True)

        # Statistics
        self.stats = {
            "files_created": 0,
            "bytes_written": 0,
            "write_errors": 0,
            "files_rotated": 0,
        }

        # Ensure data directory exists
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Storage initialized at {self.data_dir}")
        except Exception as e:
            logger.error(f"Failed to create data directory: {e}")

    def _get_storage_path(self, data_type: str, host_id: str) -> Path:
        """Get the storage path for data.

        Args:
            data_type: Type of data (events, system, etc.)
            host_id: Host identifier

        Returns:
            Path object for the storage location
        """
        if self.organize_by_date:
            date_str = datetime.now().strftime("%Y%m%d")
            return self.data_dir / date_str
        return self.data_dir

    def save_data(
        self,
        data: Any,
        data_type: str,
        source_ip: str,
        host_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Save received data to storage.

        Args:
            data: Data to save (dict, list, or string)
            data_type: Type of data
            source_ip: Source IP address
            host_id: Host identifier
            metadata: Optional additional metadata

        Returns:
            Path to saved file, or None if failed
        """
        try:
            # Get storage directory
            storage_dir = self._get_storage_path(data_type, host_id)
            storage_dir.mkdir(parents=True, exist_ok=True)

            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            safe_host_id = self._sanitize_filename(host_id)
            filename = f"scout_{data_type}_{safe_host_id}_{timestamp}.json"
            filepath = storage_dir / filename

            # Build envelope with metadata
            envelope = {
                "received_at": datetime.now().isoformat(),
                "source_ip": source_ip,
                "host_id": host_id,
                "data_type": data_type,
                "record_count": self._count_records(data),
                "data": data,
            }

            if metadata:
                envelope["metadata"] = metadata

            # Write to file
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(envelope, f, indent=2, default=str)

            # Update statistics
            file_size = filepath.stat().st_size
            self.stats["files_created"] += 1
            self.stats["bytes_written"] += file_size

            logger.info(f"Saved data to {filepath} ({file_size} bytes)")
            return str(filepath)

        except Exception as e:
            self.stats["write_errors"] += 1
            logger.error(f"Failed to save data: {e}")
            return None

    def save_raw_data(
        self,
        data: bytes,
        data_type: str,
        source_ip: str,
        host_id: str,
        extension: str = "bin",
    ) -> Optional[str]:
        """Save raw binary data to storage.

        Args:
            data: Raw bytes to save
            data_type: Type of data
            source_ip: Source IP address
            host_id: Host identifier
            extension: File extension

        Returns:
            Path to saved file, or None if failed
        """
        try:
            storage_dir = self._get_storage_path(data_type, host_id)
            storage_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            safe_host_id = self._sanitize_filename(host_id)
            filename = f"scout_{data_type}_{safe_host_id}_{timestamp}.{extension}"
            filepath = storage_dir / filename

            with open(filepath, "wb") as f:
                f.write(data)

            file_size = filepath.stat().st_size
            self.stats["files_created"] += 1
            self.stats["bytes_written"] += file_size

            logger.info(f"Saved raw data to {filepath} ({file_size} bytes)")
            return str(filepath)

        except Exception as e:
            self.stats["write_errors"] += 1
            logger.error(f"Failed to save raw data: {e}")
            return None

    def get_recent_files(self, limit: int = 20, data_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of recently saved files.

        Args:
            limit: Maximum number of files to return
            data_type: Optional filter by data type

        Returns:
            List of file information dictionaries
        """
        files = []

        try:
            # Find all JSON files
            pattern = f"scout_{data_type}_*.json" if data_type else "scout_*.json"

            for filepath in self.data_dir.rglob(pattern):
                try:
                    stat = filepath.stat()
                    files.append(
                        {
                            "path": str(filepath),
                            "filename": filepath.name,
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "modified_ts": stat.st_mtime,
                        }
                    )
                except Exception:
                    continue

            # Sort by modification time, most recent first
            files.sort(key=lambda x: x["modified_ts"], reverse=True)

            return files[:limit]

        except Exception as e:
            logger.error(f"Failed to list recent files: {e}")
            return []

    def get_file_content(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Read and return file content.

        Args:
            filepath: Path to file

        Returns:
            File content as dictionary, or None if failed
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read file {filepath}: {e}")
            return None

    def cleanup_old_files(self, days: Optional[int] = None) -> int:
        """Remove files older than retention period.

        Args:
            days: Override retention days (uses config if not specified)

        Returns:
            Number of files deleted
        """
        retention = days or self.retention_days
        if retention <= 0:
            return 0

        cutoff = datetime.now() - timedelta(days=retention)
        deleted = 0

        try:
            for filepath in self.data_dir.rglob("scout_*.json"):
                try:
                    mtime = datetime.fromtimestamp(filepath.stat().st_mtime)
                    if mtime < cutoff:
                        filepath.unlink()
                        deleted += 1
                        logger.debug(f"Deleted old file: {filepath}")
                except Exception as e:
                    logger.warning(f"Failed to delete {filepath}: {e}")

            # Remove empty date directories
            for dirpath in self.data_dir.iterdir():
                if dirpath.is_dir() and not any(dirpath.iterdir()):
                    try:
                        dirpath.rmdir()
                    except Exception:
                        pass

            if deleted > 0:
                logger.info(f"Cleaned up {deleted} files older than {retention} days")

            self.stats["files_rotated"] += deleted
            return deleted

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return 0

    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics.

        Returns:
            Dictionary with storage statistics
        """
        try:
            total_files = 0
            total_size = 0

            for filepath in self.data_dir.rglob("scout_*.json"):
                try:
                    total_files += 1
                    total_size += filepath.stat().st_size
                except Exception:
                    pass

            # Get disk usage
            try:
                disk_usage = shutil.disk_usage(self.data_dir)
                disk_free_pct = (disk_usage.free / disk_usage.total) * 100
            except Exception:
                disk_free_pct = None

            return {
                "data_dir": str(self.data_dir),
                "total_files": total_files,
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "disk_free_pct": round(disk_free_pct, 1) if disk_free_pct else None,
                "files_created": self.stats["files_created"],
                "bytes_written": self.stats["bytes_written"],
                "write_errors": self.stats["write_errors"],
                "files_rotated": self.stats["files_rotated"],
            }

        except Exception as e:
            logger.error(f"Failed to get storage stats: {e}")
            return {"error": str(e)}

    def get_data_for_export(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> List[Path]:
        """Get list of data files for export.

        Args:
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            List of file paths ready for export
        """
        files = []

        try:
            for filepath in self.data_dir.rglob("scout_*.json"):
                try:
                    mtime = datetime.fromtimestamp(filepath.stat().st_mtime)

                    if start_date and mtime < start_date:
                        continue
                    if end_date and mtime > end_date:
                        continue

                    files.append(filepath)
                except Exception:
                    continue

            files.sort(key=lambda x: x.stat().st_mtime)
            return files

        except Exception as e:
            logger.error(f"Failed to get files for export: {e}")
            return []

    def _sanitize_filename(self, name: str) -> str:
        """Sanitize string for use in filename.

        Args:
            name: String to sanitize

        Returns:
            Safe filename string
        """
        # Replace unsafe characters
        unsafe_chars = '<>:"/\\|?*'
        for char in unsafe_chars:
            name = name.replace(char, "_")

        # Limit length
        return name[:50]

    def _count_records(self, data: Any) -> int:
        """Count number of records in data.

        Args:
            data: Data to count

        Returns:
            Number of records
        """
        if isinstance(data, list):
            return len(data)
        elif isinstance(data, dict):
            # Check for nested data arrays
            for key in ["events", "changes", "records", "items", "data"]:
                if key in data and isinstance(data[key], list):
                    return len(data[key])
            return 1
        return 1

    def reset_statistics(self) -> None:
        """Reset storage statistics."""
        for key in self.stats:
            self.stats[key] = 0
