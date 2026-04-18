"""
Heartbeat Handler for Scout Receiver

Provides heartbeat/health check responses for SCOUT Agent
connectivity verification.
"""

import asyncio
import time
from datetime import datetime
from typing import Any, Dict, Optional

from .utils.logging import get_logger

logger = get_logger(__name__)


class HeartbeatHandler:
    """Handles heartbeat requests and health status reporting."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize heartbeat handler.

        Args:
            config: Heartbeat configuration dictionary
        """
        config = config or {}

        self.enabled = config.get("enabled", True)
        self.interval_seconds = config.get("interval_seconds", 30)
        self.response_delay_ms = config.get("response_delay_ms", 0)

        # State tracking
        self.start_time = time.time()
        self.last_heartbeat_time: Optional[float] = None
        self.heartbeat_count = 0
        self.is_running = False

        # Simulated scenarios (for testing)
        self.current_scenario = "normal"
        self.scenario_until: Optional[float] = None

        # Statistics
        self.stats = {
            "total_heartbeats": 0,
            "successful_responses": 0,
            "delayed_responses": 0,
            "failed_responses": 0,
        }

    async def start(self) -> None:
        """Start the heartbeat handler."""
        self.is_running = True
        self.start_time = time.time()
        logger.info("Heartbeat handler started")

    async def stop(self) -> None:
        """Stop the heartbeat handler."""
        self.is_running = False
        logger.info("Heartbeat handler stopped")

    async def handle_heartbeat_request(self) -> Dict[str, Any]:
        """Handle an incoming heartbeat request.

        Returns:
            Heartbeat response dictionary
        """
        self.stats["total_heartbeats"] += 1
        self.heartbeat_count += 1
        self.last_heartbeat_time = time.time()

        # Apply configured delay (for testing latency scenarios)
        if self.response_delay_ms > 0:
            await asyncio.sleep(self.response_delay_ms / 1000)
            self.stats["delayed_responses"] += 1

        # Check for active scenario
        scenario = self._get_current_scenario()

        # Build response based on scenario
        if scenario == "normal":
            self.stats["successful_responses"] += 1
            return self._build_healthy_response()

        elif scenario == "degraded":
            self.stats["successful_responses"] += 1
            return self._build_degraded_response()

        elif scenario == "timeout":
            # Simulate timeout by waiting longer than typical timeout
            await asyncio.sleep(35)
            self.stats["failed_responses"] += 1
            return self._build_healthy_response()

        elif scenario == "error":
            self.stats["failed_responses"] += 1
            return self._build_error_response()

        else:
            self.stats["successful_responses"] += 1
            return self._build_healthy_response()

    def _build_healthy_response(self) -> Dict[str, Any]:
        """Build a healthy heartbeat response."""
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "uptime_seconds": round(time.time() - self.start_time, 1),
            "heartbeat_count": self.heartbeat_count,
            "server_time": time.time(),
            "version": "1.0.0",
        }

    def _build_degraded_response(self) -> Dict[str, Any]:
        """Build a degraded status response."""
        return {
            "status": "degraded",
            "timestamp": datetime.now().isoformat(),
            "uptime_seconds": round(time.time() - self.start_time, 1),
            "heartbeat_count": self.heartbeat_count,
            "server_time": time.time(),
            "version": "1.0.0",
            "warnings": ["System under high load"],
        }

    def _build_error_response(self) -> Dict[str, Any]:
        """Build an error status response."""
        return {
            "status": "error",
            "timestamp": datetime.now().isoformat(),
            "error": "Internal server error",
            "server_time": time.time(),
        }

    def _get_current_scenario(self) -> str:
        """Get the current active scenario.

        Returns:
            Current scenario name
        """
        if self.scenario_until and time.time() > self.scenario_until:
            self.current_scenario = "normal"
            self.scenario_until = None

        return self.current_scenario

    async def simulate_scenario(self, scenario: str, duration_seconds: int = 60) -> Dict[str, Any]:
        """Activate a simulation scenario for testing.

        Args:
            scenario: Scenario name ('normal', 'degraded', 'timeout', 'error')
            duration_seconds: How long to run the scenario

        Returns:
            Confirmation dictionary
        """
        valid_scenarios = ["normal", "degraded", "timeout", "error"]

        if scenario not in valid_scenarios:
            return {
                "success": False,
                "error": f"Invalid scenario. Valid options: {valid_scenarios}",
            }

        self.current_scenario = scenario
        self.scenario_until = time.time() + duration_seconds

        logger.info(f"Activated scenario '{scenario}' for {duration_seconds}s")

        return {
            "success": True,
            "scenario": scenario,
            "duration_seconds": duration_seconds,
            "expires_at": datetime.fromtimestamp(self.scenario_until).isoformat(),
        }

    async def update_configuration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update heartbeat configuration at runtime.

        Args:
            config: New configuration values

        Returns:
            Confirmation dictionary
        """
        updated = []

        if "enabled" in config:
            self.enabled = config["enabled"]
            updated.append("enabled")

        if "interval_seconds" in config:
            self.interval_seconds = config["interval_seconds"]
            updated.append("interval_seconds")

        if "response_delay_ms" in config:
            self.response_delay_ms = config["response_delay_ms"]
            updated.append("response_delay_ms")

        logger.info(f"Heartbeat config updated: {updated}")

        return {
            "success": True,
            "updated_fields": updated,
            "current_config": {
                "enabled": self.enabled,
                "interval_seconds": self.interval_seconds,
                "response_delay_ms": self.response_delay_ms,
            },
        }

    def get_status(self) -> Dict[str, Any]:
        """Get current heartbeat handler status.

        Returns:
            Status dictionary
        """
        return {
            "enabled": self.enabled,
            "is_running": self.is_running,
            "interval_seconds": self.interval_seconds,
            "response_delay_ms": self.response_delay_ms,
            "current_scenario": self.current_scenario,
            "heartbeat_count": self.heartbeat_count,
            "last_heartbeat": (
                datetime.fromtimestamp(self.last_heartbeat_time).isoformat() if self.last_heartbeat_time else None
            ),
            "uptime_seconds": round(time.time() - self.start_time, 1),
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get heartbeat statistics.

        Returns:
            Statistics dictionary
        """
        return {
            **self.stats,
            "heartbeat_count": self.heartbeat_count,
            "current_scenario": self.current_scenario,
        }

    def reset_statistics(self) -> None:
        """Reset heartbeat statistics."""
        self.heartbeat_count = 0
        self.last_heartbeat_time = None
        for key in self.stats:
            self.stats[key] = 0
        logger.info("Heartbeat statistics reset")
