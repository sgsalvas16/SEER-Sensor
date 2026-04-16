"""
HTTP Server for Scout Receiver

Async HTTP server using aiohttp to accept SCOUT Agent data,
provide heartbeat endpoints, and serve a monitoring dashboard.
"""

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Set

from aiohttp import WSMsgType, web
from aiohttp.web_request import Request
from aiohttp.web_response import Response

try:
    import aiohttp_cors

    HAS_CORS = True
except ImportError:
    HAS_CORS = False

from .heartbeat import HeartbeatHandler
from .statistics import StatisticsCollector
from .storage import ScoutDataStorage
from .utils.config import ScoutReceiverConfig, load_config
from .utils.logging import get_logger, get_packet_logger, setup_logging
from .validation import DataValidator

logger = get_logger(__name__)
packet_logger = get_packet_logger()


class ScoutReceiverServer:
    """HTTP Server for receiving SCOUT Agent data.

    Provides endpoints for:
    - Data reception (/scout/data, /scout/events, /scout/system)
    - Health checks (/scout/health, /scout/status)
    - Control endpoints (/control/*)
    - Web dashboard (/, /api/*)
    """

    def __init__(self, config: Optional[ScoutReceiverConfig] = None):
        """Initialize Scout Receiver Server.

        Args:
            config: Configuration manager instance
        """
        self.config = config or load_config()

        # Initialize components
        self.validator = DataValidator(self.config.get_section("validation"))
        self.storage = ScoutDataStorage(self.config.get_section("storage"))
        self.heartbeat = HeartbeatHandler(self.config.get_section("heartbeat"))
        self.statistics = StatisticsCollector()

        # Server state
        self.app = web.Application()
        self.is_running = False
        self.start_time: Optional[float] = None

        # WebSocket connections for real-time updates
        self.websocket_connections: Set[web.WebSocketResponse] = set()

        # Recent received data (for dashboard)
        self.received_data: list = []
        self.max_received_data = 100

        # Setup routes and middleware
        self._setup_routes()
        self._setup_cors()
        self._setup_middleware()

    def _setup_routes(self) -> None:
        """Configure HTTP routes."""
        router = self.app.router

        # Data reception endpoints
        router.add_post("/scout/data", self._handle_scout_data)
        router.add_post("/scout/events", self._handle_scout_events)
        router.add_post("/scout/system", self._handle_scout_system)

        # Health and status endpoints
        router.add_get("/scout/health", self._handle_health)
        router.add_get("/scout/status", self._handle_status)
        router.add_get("/scout/metrics", self._handle_metrics)

        # Control endpoints
        router.add_post("/control/heartbeat", self._handle_control_heartbeat)
        router.add_post("/control/simulate", self._handle_control_simulate)
        router.add_get("/control/stats", self._handle_control_stats)
        router.add_post("/control/reset", self._handle_control_reset)

        # Web interface endpoints
        router.add_get("/", self._handle_dashboard)
        router.add_get("/api/data", self._handle_api_data)
        router.add_get("/api/statistics", self._handle_api_statistics)
        router.add_get("/api/storage", self._handle_api_storage)
        router.add_get("/api/system", self._handle_api_system)
        router.add_get("/api/analytics", self._handle_api_analytics)
        router.add_get("/ws", self._handle_websocket)

    def _setup_cors(self) -> None:
        """Configure CORS for web interface access."""
        if not HAS_CORS:
            logger.warning("aiohttp-cors not installed, CORS disabled")
            return

        if not self.config.get("server.cors_enabled", True):
            return

        cors = aiohttp_cors.setup(
            self.app,
            defaults={
                "*": aiohttp_cors.ResourceOptions(
                    allow_credentials=True,
                    expose_headers="*",
                    allow_headers="*",
                    allow_methods="*",
                )
            },
        )

        for route in list(self.app.router.routes()):
            try:
                cors.add(route)
            except ValueError:
                pass  # Some routes may not support CORS

    def _setup_middleware(self) -> None:
        """Configure request middleware."""

        @web.middleware
        async def logging_middleware(request: Request, handler):
            """Log all incoming requests."""
            start_time = time.time()

            try:
                response = await handler(request)
                processing_time = time.time() - start_time

                # Log at debug level for health checks
                log_func = logger.debug if request.path == "/scout/health" else logger.info
                log_func(f"{request.method} {request.path} -> {response.status} ({processing_time * 1000:.1f}ms)")

                return response

            except Exception as e:
                processing_time = time.time() - start_time
                logger.error(f"{request.method} {request.path} -> ERROR: {e} ({processing_time * 1000:.1f}ms)")
                raise

        self.app.middlewares.append(logging_middleware)

    # ==================== Data Reception Handlers ====================

    async def _handle_scout_data(self, request: Request) -> Response:
        """Handle SCOUT Agent data POST requests."""
        start_time = time.time()
        client_ip = request.remote or "unknown"

        try:
            # Extract headers
            _content_type = request.headers.get("Content-Type", "")  # noqa: F841
            data_size = int(request.headers.get("Content-Length", 0))
            agent_version = request.headers.get("X-Scout-Agent-Version", "unknown")
            host_id = request.headers.get("X-Scout-Host-ID", "unknown")
            data_type = request.headers.get("X-Scout-Data-Type", "unknown")
            checksum = request.headers.get("X-Scout-Checksum", "")

            # Read and parse request body
            text = await request.text()
            data = self._parse_flexible_json(text)

            # Log packet reception
            packet_logger.log_packet_received(
                source_ip=client_ip,
                packet_size=data_size,
                protocol="HTTP",
                timestamp=start_time,
            )

            # Validate data envelope
            envelope = {
                "agent_version": agent_version,
                "host_id": host_id,
                "timestamp": start_time,
                "data_type": data_type,
                "checksum": checksum,
                "data": data,
            }
            validation_result = self.validator.validate_data_envelope(envelope)

            # Verify checksum if provided
            # NOTE: Checksum must be calculated on the raw request body (text),
            # not on re-serialized JSON, to match what the SCOUT Agent sends
            if checksum and self.config.get("validation.verify_checksums", True):
                checksum_result = self.validator.validate_checksum(text, checksum)
                if not checksum_result.is_valid:
                    logger.warning(f"Checksum mismatch from {client_ip}: {checksum_result.message}")

            # Count records
            record_count = 1
            if isinstance(data, list):
                record_count = len(data)
            elif isinstance(data, dict):
                for key in ["events", "changes", "records", "items"]:
                    if key in data and isinstance(data[key], list):
                        record_count = len(data[key])
                        break

            # Save to storage
            filepath = self.storage.save_data(
                data=data,
                data_type=data_type,
                source_ip=client_ip,
                host_id=host_id,
                metadata={
                    "agent_version": agent_version,
                    "checksum": checksum,
                    "validation": validation_result.to_dict(),
                },
            )

            # Update statistics
            processing_time = time.time() - start_time
            self.statistics.record_data_received(
                data_size=data_size,
                processing_time=processing_time,
                source_ip=client_ip,
                record_count=record_count,
                success=True,
                data_type=data_type,
                data=data,
            )

            # Log successful data extraction
            packet_logger.log_data_extracted(
                source_ip=client_ip,
                data_size=data_size,
                data_type=data_type,
                checksum=checksum,
                processing_time=processing_time,
            )

            # Store for dashboard
            self._add_received_data(
                {
                    "timestamp": datetime.now().isoformat(),
                    "source_ip": client_ip,
                    "agent_version": agent_version,
                    "host_id": host_id,
                    "data_type": data_type,
                    "data_size": data_size,
                    "record_count": record_count,
                    "filepath": filepath,
                    "validation": validation_result.to_dict(),
                }
            )

            # Broadcast to WebSocket clients
            await self._broadcast_websocket(
                {
                    "type": "data_received",
                    "timestamp": datetime.now().isoformat(),
                    "source_ip": client_ip,
                    "host_id": host_id,
                    "data_type": data_type,
                    "record_count": record_count,
                }
            )

            # Return success response
            response_data = {
                "status": "success",
                "message": "Data received and processed",
                "timestamp": datetime.now().isoformat(),
                "processing_time_ms": round(processing_time * 1000, 2),
                "data_size": data_size,
                "record_count": record_count,
            }

            if not validation_result.is_valid:
                response_data["validation_warnings"] = [validation_result.message]

            return web.json_response(response_data, status=200)

        except Exception as e:
            processing_time = time.time() - start_time
            error_message = f"Failed to process data: {str(e)}"

            logger.error(error_message)

            # Record error
            self.statistics.record_data_received(
                data_size=0,
                processing_time=processing_time,
                source_ip=client_ip,
                success=False,
            )
            self.statistics.record_error("data_processing_error")

            packet_logger.log_validation_error(
                source_ip=client_ip,
                error_type="processing_error",
                error_message=str(e),
                data_size=0,
            )

            return web.json_response(
                {
                    "status": "error",
                    "message": error_message,
                    "timestamp": datetime.now().isoformat(),
                },
                status=500,
            )

    async def _handle_scout_events(self, request: Request) -> Response:
        """Handle SCOUT Agent event data."""
        return await self._handle_scout_data(request)

    async def _handle_scout_system(self, request: Request) -> Response:
        """Handle SCOUT Agent system data."""
        return await self._handle_scout_data(request)

    # ==================== Health & Status Handlers ====================

    async def _handle_health(self, request: Request) -> Response:
        """Handle health check requests."""
        response = await self.heartbeat.handle_heartbeat_request()
        return web.json_response(response)

    async def _handle_status(self, request: Request) -> Response:
        """Handle detailed status requests."""
        uptime = time.time() - self.start_time if self.start_time else 0

        status_data = {
            "status": "running" if self.is_running else "stopped",
            "uptime_seconds": round(uptime, 1),
            "start_time": self.start_time,
            "current_time": time.time(),
            "received_data_count": len(self.received_data),
            "websocket_connections": len(self.websocket_connections),
            "heartbeat_status": self.heartbeat.get_status(),
            "validation_statistics": self.validator.get_validation_statistics(),
            "processing_statistics": self.statistics.get_statistics(),
            "storage_statistics": self.storage.get_storage_stats(),
        }

        return web.json_response(status_data)

    async def _handle_metrics(self, request: Request) -> Response:
        """Handle metrics requests."""
        metrics = self.statistics.get_detailed_metrics()
        return web.json_response(metrics)

    # ==================== Control Handlers ====================

    async def _handle_control_heartbeat(self, request: Request) -> Response:
        """Handle heartbeat control requests."""
        try:
            control_data = await request.json()
            result = await self.heartbeat.update_configuration(control_data)
            return web.json_response(
                {
                    "status": "success",
                    "message": "Heartbeat configuration updated",
                    "result": result,
                }
            )
        except Exception as e:
            return web.json_response(
                {
                    "status": "error",
                    "message": str(e),
                },
                status=400,
            )

    async def _handle_control_simulate(self, request: Request) -> Response:
        """Handle simulation control requests."""
        try:
            data = await request.json()
            scenario = data.get("scenario", "normal")
            duration = data.get("duration", 60)

            result = await self.heartbeat.simulate_scenario(scenario, duration)

            return web.json_response(
                {
                    "status": "success" if result.get("success") else "error",
                    "message": f"Scenario '{scenario}' activated" if result.get("success") else result.get("error"),
                    "result": result,
                }
            )
        except Exception as e:
            return web.json_response(
                {
                    "status": "error",
                    "message": str(e),
                },
                status=400,
            )

    async def _handle_control_stats(self, request: Request) -> Response:
        """Handle statistics requests."""
        stats = {
            "server_statistics": self.statistics.get_statistics(),
            "validation_statistics": self.validator.get_validation_statistics(),
            "heartbeat_statistics": self.heartbeat.get_statistics(),
            "storage_statistics": self.storage.get_storage_stats(),
            "data_summary": {
                "total_received": len(self.received_data),
                "recent_data": self.received_data[-10:],
            },
        }
        return web.json_response(stats)

    async def _handle_control_reset(self, request: Request) -> Response:
        """Handle reset requests."""
        try:
            self.statistics.reset_statistics()
            self.validator.reset_statistics()
            self.heartbeat.reset_statistics()
            self.received_data.clear()

            logger.info("Server statistics and data reset")

            return web.json_response(
                {
                    "status": "success",
                    "message": "Server statistics and data reset successfully",
                }
            )
        except Exception as e:
            return web.json_response(
                {
                    "status": "error",
                    "message": str(e),
                },
                status=500,
            )

    # ==================== Web Interface Handlers ====================

    async def _handle_dashboard(self, request: Request) -> Response:
        """Serve the monitoring dashboard."""
        html = self._generate_dashboard_html()
        return web.Response(text=html, content_type="text/html")

    async def _handle_api_data(self, request: Request) -> Response:
        """Return recent received data."""
        limit = int(request.query.get("limit", 20))
        data = self.received_data[-limit:] if self.received_data else []
        return web.json_response(list(reversed(data)))

    async def _handle_api_statistics(self, request: Request) -> Response:
        """Return statistics for dashboard."""
        return web.json_response(self.statistics.get_statistics())

    async def _handle_api_storage(self, request: Request) -> Response:
        """Return storage statistics."""
        return web.json_response(self.storage.get_storage_stats())

    async def _handle_api_system(self, request: Request) -> Response:
        """Return system component statuses including services, PCAP, and drive info."""
        result = self._collect_system_status()
        return web.json_response(result)

    async def _handle_api_analytics(self, request: Request) -> Response:
        """Return event type analytics breakdown."""
        return web.json_response(self.statistics.get_analytics())

    def _collect_system_status(self) -> Dict[str, Any]:
        """Collect system status (runs in thread pool)."""
        import glob
        import os
        import subprocess

        def run_cmd(cmd):
            """Run a command and return stdout."""
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
            except Exception:
                return "unknown"

        def systemctl_is_active(unit):
            """Check if a systemd service is active."""
            if not unit:
                return "inactive"
            result = run_cmd(["systemctl", "is-active", unit])
            return result if result else "inactive"

        def count_pcaps(path):
            """Count .pcap* files in a directory."""
            try:
                return sum(1 for _ in glob.glob(os.path.join(path, "*.pcap*")))
            except Exception:
                return 0

        def read_yaml_config():
            """Read SEER YAML config."""
            try:
                import yaml

                with open("/opt/seer/etc/seer.yml") as f:
                    return yaml.safe_load(f) or {}
            except Exception:
                return {}

        def read_hotswap_state():
            """Read hotswap state file."""
            try:
                with open("/var/log/seer/hotswap_state.json") as f:
                    return json.load(f)
            except Exception:
                return {}

        def json_stats(path):
            """Return file count and total bytes for JSON/log files."""
            try:
                patterns = ["**/*.json*", "**/*.log", "**/*.log.json*"]
                seen = set()
                total = 0
                for pat in patterns:
                    for p in glob.glob(os.path.join(path, pat), recursive=True):
                        if os.path.isdir(p) or p in seen:
                            continue
                        seen.add(p)
                        try:
                            total += os.stat(p).st_size
                        except FileNotFoundError:
                            pass
                return {"count": len(seen), "bytes": total}
            except Exception:
                return {"count": 0, "bytes": 0}

        # Load config
        cfg = read_yaml_config()
        iface = cfg.get("interface", "enp2s0")

        # Service statuses
        services = {
            "capture": systemctl_is_active(f"seer-capture@{iface}.service"),
            "mover": systemctl_is_active("seer-move-oldest.service"),
            "timer": systemctl_is_active("seer-move-oldest.timer"),
            "zeek": systemctl_is_active(f"seer-zeek@{iface}.service"),
            "hotswap": systemctl_is_active("seer-hotswap.service"),
            "receiver": "active",  # We know this is active since we're responding
        }

        # PCAP counts
        ring_dir = cfg.get("ring_dir", "/var/seer/pcap_ring")
        dest_dir = cfg.get("dest_dir", "/opt/seer/var/queue")
        backlog_dir = cfg.get("backlog_dir", "/opt/seer/var/backlog")

        pcap = {
            "ring": count_pcaps(ring_dir),
            "queue": count_pcaps(dest_dir),
            "backlog": count_pcaps(backlog_dir),
        }

        # Export drive status
        hs_state = read_hotswap_state()
        drive_present = hs_state.get("drive_present", False)
        mount_candidates = cfg.get("export", {}).get("mount_candidates", ["/mnt/seer_external"])
        active_mount = None
        drive_files = 0

        for candidate in mount_candidates:
            if os.path.ismount(candidate):
                active_mount = candidate
                try:
                    drive_files = sum(1 for _ in Path(candidate).rglob("*.pcap*"))
                except Exception:
                    pass
                break

        export_drive = {
            "present": drive_present,
            "mounted": active_mount is not None,
            "mount_point": active_mount,
            "files": drive_files,
            "last_export": hs_state.get("last_export_ts"),
            "total_exported": hs_state.get("total_exported", 0),
        }

        # JSON/Zeek stats
        json_spool = cfg.get("json_spool", "/var/seer/json_spool")
        json_data = json_stats(json_spool)

        return {
            "services": services,
            "pcap": pcap,
            "export_drive": export_drive,
            "json": json_data,
            "config": {
                "interface": iface,
                "ring_dir": ring_dir,
                "dest_dir": dest_dir,
                "backlog_dir": backlog_dir,
                "json_spool": json_spool,
            },
        }

    async def _handle_websocket(self, request: Request) -> Response:
        """Handle WebSocket connections for real-time updates."""
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        self.websocket_connections.add(ws)
        logger.info(f"WebSocket connection from {request.remote}")

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        _data = json.loads(msg.data)  # noqa: F841
                        await ws.send_str(
                            json.dumps(
                                {
                                    "type": "response",
                                    "message": "Command received",
                                }
                            )
                        )
                    except json.JSONDecodeError:
                        await ws.send_str(
                            json.dumps(
                                {
                                    "type": "error",
                                    "message": "Invalid JSON",
                                }
                            )
                        )
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {ws.exception()}")
                    break
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            self.websocket_connections.discard(ws)
            logger.info(f"WebSocket closed from {request.remote}")

        return ws

    # ==================== Helper Methods ====================

    def _parse_flexible_json(self, text: str) -> Any:
        """Parse JSON data flexibly, handling various formats.

        Supports:
        - Standard JSON objects/arrays
        - NDJSON (newline-delimited JSON)
        - JSON with trailing newlines
        - Concatenated JSON objects (}{)

        Args:
            text: Raw text data to parse

        Returns:
            Parsed JSON data (dict, list, or raw text if unparseable)
        """
        if not text or not text.strip():
            return {}

        text = text.strip()

        # Try standard JSON first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try splitting by newlines (NDJSON format)
        lines = [line.strip() for line in text.split("\n") if line.strip()]
        if len(lines) > 1:
            try:
                return [json.loads(line) for line in lines]
            except json.JSONDecodeError:
                pass
        elif len(lines) == 1:
            try:
                return json.loads(lines[0])
            except json.JSONDecodeError:
                pass

        # Try handling concatenated JSON objects (}{)
        # This handles cases where multiple JSON objects are on one line
        if "}{" in text:
            try:
                # Split on }{ and reconstruct individual objects
                parts = text.replace("}{", "}\n{").split("\n")
                parsed = [json.loads(part.strip()) for part in parts if part.strip()]
                return parsed if len(parsed) > 1 else parsed[0] if parsed else {}
            except json.JSONDecodeError:
                pass

        # Last resort: try to extract first valid JSON object
        try:
            # Find matching braces for first object
            if text.startswith("{"):
                depth = 0
                in_string = False
                escape = False
                for i, char in enumerate(text):
                    if escape:
                        escape = False
                        continue
                    if char == "\\":
                        escape = True
                        continue
                    if char == '"':
                        in_string = not in_string
                        continue
                    if not in_string:
                        if char == "{":
                            depth += 1
                        elif char == "}":
                            depth -= 1
                            if depth == 0:
                                # Found end of first object
                                return json.loads(text[: i + 1])
        except json.JSONDecodeError:
            pass

        # Return raw text if all parsing attempts fail
        logger.warning(f"Could not parse JSON data, returning raw text ({len(text)} bytes)")
        return text

    def _add_received_data(self, entry: Dict[str, Any]) -> None:
        """Add entry to received data list."""
        self.received_data.append(entry)
        if len(self.received_data) > self.max_received_data:
            self.received_data = self.received_data[-self.max_received_data :]

    async def _broadcast_websocket(self, message: Dict[str, Any]) -> None:
        """Broadcast message to all WebSocket clients."""
        if not self.websocket_connections:
            return

        message_str = json.dumps(message)
        disconnected = set()

        for ws in self.websocket_connections:
            try:
                await ws.send_str(message_str)
            except Exception:
                disconnected.add(ws)

        self.websocket_connections -= disconnected

    def _generate_dashboard_html(self) -> str:
        """Generate the comprehensive SEER monitoring dashboard HTML."""
        return """<!DOCTYPE html>
<html>
<head>
    <title>SEER Sensor Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #1a1a2e; color: #eee; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        h1 { color: #00d4ff; }
        .header-info { color: #888; font-size: 0.9em; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px; }
        .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 15px; }
        .card { background: #16213e; border-radius: 8px; padding: 15px; }
        .card h2 { color: #00d4ff; font-size: 1em; margin-bottom: 12px; border-bottom: 1px solid #0f3460; padding-bottom: 8px; }
        .card h3 { color: #888; font-size: 0.85em; margin: 10px 0 8px 0; text-transform: uppercase; letter-spacing: 0.5px; }
        .stat { display: flex; justify-content: space-between; margin: 6px 0; font-size: 0.9em; }
        .stat-label { color: #888; }
        .stat-value { color: #00d4ff; font-weight: bold; }
        .stat-value.warning { color: #ffaa00; }
        .stat-value.error { color: #ff4444; }
        .stat-value.success { color: #00ff88; }
        .data-entry { background: #0f3460; padding: 10px; margin: 5px 0; border-radius: 4px; font-size: 0.85em; }
        .data-entry.success { border-left: 3px solid #00ff88; }
        .data-entry.error { border-left: 3px solid #ff4444; }
        .refresh-btn { background: #00d4ff; color: #1a1a2e; border: none; padding: 8px 16px;
                      border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 0.9em; }
        .refresh-btn:hover { background: #00a8cc; }
        .status-badge { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.75em; font-weight: bold; }
        .status-badge.active { background: #00ff88; color: #000; }
        .status-badge.running { background: #00d4ff; color: #000; }
        .status-badge.inactive { background: #666; color: #fff; }
        .status-badge.failed { background: #ff4444; color: #fff; }
        .status-badge.unknown { background: #444; color: #888; }
        .status-badge.healthy { background: #00ff88; color: #000; }
        .status-badge.degraded { background: #ffaa00; color: #000; }
        .status-badge.idle { background: #666; color: #fff; }
        .service-row { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid #0f3460; }
        .service-row:last-child { border-bottom: none; }
        .service-name { color: #ccc; font-size: 0.9em; }
        .section-title { color: #00d4ff; font-size: 0.9em; margin: 15px 0 10px 0; padding-top: 10px; border-top: 1px solid #0f3460; }
        .mini-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
        table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.85em; }
        th, td { padding: 6px 8px; text-align: left; border-bottom: 1px solid #0f3460; }
        th { color: #888; font-weight: normal; font-size: 0.8em; text-transform: uppercase; }
        .timestamp { color: #666; font-size: 0.8em; }
        .auto-refresh { display: flex; align-items: center; gap: 10px; }
        .auto-refresh label { color: #888; font-size: 0.85em; }
        #last-update { color: #666; font-size: 0.8em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SEER Sensor Dashboard</h1>
            <div class="header-info">
                <div class="auto-refresh">
                    <button class="refresh-btn" onclick="refreshData()">Refresh</button>
                    <label><input type="checkbox" id="auto-refresh" checked> Auto (5s)</label>
                    <span id="last-update"></span>
                </div>
            </div>
        </div>

        <!-- Services Status Row -->
        <div class="grid" style="margin-bottom: 15px;">
            <div class="card">
                <h2>System Services</h2>
                <div class="service-row">
                    <span class="service-name">Capture</span>
                    <span id="svc-capture" class="status-badge unknown">--</span>
                </div>
                <div class="service-row">
                    <span class="service-name">Mover</span>
                    <span id="svc-mover" class="status-badge unknown">--</span>
                </div>
                <div class="service-row">
                    <span class="service-name">Timer</span>
                    <span id="svc-timer" class="status-badge unknown">--</span>
                </div>
                <div class="service-row">
                    <span class="service-name">Zeek</span>
                    <span id="svc-zeek" class="status-badge unknown">--</span>
                </div>
                <div class="service-row">
                    <span class="service-name">Hotswap</span>
                    <span id="svc-hotswap" class="status-badge unknown">--</span>
                </div>
                <div class="service-row">
                    <span class="service-name">Scout Receiver</span>
                    <span id="svc-receiver" class="status-badge unknown">--</span>
                </div>
            </div>

            <div class="card">
                <h2>Scout Receiver</h2>
                <div class="stat"><span class="stat-label">Status</span><span id="recv-status" class="status-badge unknown">--</span></div>
                <div class="stat"><span class="stat-label">Uptime</span><span id="recv-uptime" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Requests</span><span id="recv-requests" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Success Rate</span><span id="recv-success" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Requests/min</span><span id="recv-rpm" class="stat-value">-</span></div>
            </div>

            <div class="card">
                <h2>Data Reception</h2>
                <div class="stat"><span class="stat-label">Data Received</span><span id="data-received" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Records</span><span id="records" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Unique Sources</span><span id="sources" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Avg Processing</span><span id="avg-time" class="stat-value">-</span></div>
            </div>

            <div class="card">
                <h2>Storage</h2>
                <div class="stat"><span class="stat-label">Files Created</span><span id="files-created" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Total Size</span><span id="storage-size" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Disk Free</span><span id="disk-free" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Retention</span><span id="retention" class="stat-value">-</span></div>
            </div>
        </div>

        <!-- PCAP and JSON Stats -->
        <div class="grid" style="margin-bottom: 15px;">
            <div class="card">
                <h2>PCAP Status</h2>
                <div class="stat"><span class="stat-label">Ring Buffer</span><span id="pcap-ring" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Backlog</span><span id="pcap-backlog" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Queue</span><span id="pcap-queue" class="stat-value">-</span></div>
            </div>

            <div class="card">
                <h2>Export Drive</h2>
                <div class="stat"><span class="stat-label">Status</span><span id="drive-status" class="status-badge unknown">--</span></div>
                <div class="stat"><span class="stat-label">Mount Point</span><span id="drive-mount" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Files on Drive</span><span id="drive-files" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Last Export</span><span id="drive-export" class="stat-value">-</span></div>
            </div>

            <div class="card">
                <h2>JSON/Zeek Data</h2>
                <div class="stat"><span class="stat-label">File Count</span><span id="json-count" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Total Size</span><span id="json-size" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Write Rate</span><span id="json-rate" class="stat-value">-</span></div>
            </div>

            <div class="card">
                <h2>Validation</h2>
                <div class="stat"><span class="stat-label">Total Validated</span><span id="val-total" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Successful</span><span id="val-success" class="stat-value success">-</span></div>
                <div class="stat"><span class="stat-label">Failed</span><span id="val-failed" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Checksum Errors</span><span id="val-checksum" class="stat-value">-</span></div>
            </div>
        </div>

        <!-- Event Analytics -->
        <div class="grid" style="margin-bottom: 15px;">
            <div class="card">
                <h2>Data Types (X-Scout-Data-Type)</h2>
                <div id="data-types-breakdown">Loading...</div>
            </div>

            <div class="card">
                <h2>Event Schemas (ASIM)</h2>
                <div id="event-schemas-breakdown">Loading...</div>
            </div>

            <div class="card">
                <h2>Event Types (Granular)</h2>
                <div id="event-types-breakdown">Loading...</div>
            </div>

            <div class="card">
                <h2>Analytics Summary</h2>
                <div class="stat"><span class="stat-label">Unique Data Types</span><span id="unique-data-types" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Unique Event Schemas</span><span id="unique-schemas" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Unique Event Types</span><span id="unique-event-types" class="stat-value">-</span></div>
                <div class="stat"><span class="stat-label">Total Records</span><span id="analytics-records" class="stat-value">-</span></div>
            </div>
        </div>

        <!-- Source Breakdown and Recent Data -->
        <div class="grid-2">
            <div class="card">
                <h2>Connected Agents</h2>
                <table>
                    <thead>
                        <tr><th>Source IP</th><th>Requests</th><th>Data</th><th>Last Seen</th></tr>
                    </thead>
                    <tbody id="source-table">
                        <tr><td colspan="4" style="color: #666;">Loading...</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h2>Recent Activity</h2>
                <div id="recent-data">Loading...</div>
            </div>
        </div>
    </div>

    <script>
        let refreshInterval = null;

        function formatBytes(bytes) {
            if (bytes === 0 || bytes === undefined) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }

        function formatUptime(seconds) {
            if (!seconds) return '-';
            const h = Math.floor(seconds / 3600);
            const m = Math.floor((seconds % 3600) / 60);
            const s = Math.floor(seconds % 60);
            if (h > 0) return `${h}h ${m}m`;
            if (m > 0) return `${m}m ${s}s`;
            return `${s}s`;
        }

        function getStatusBadge(state) {
            const s = (state || '').toLowerCase();
            if (s === 'active' || s === 'running') return { text: 'ACTIVE', class: 'active' };
            if (s === 'failed') return { text: 'FAILED', class: 'failed' };
            if (s === 'inactive' || s === 'dead' || s === 'stopped') return { text: 'STOPPED', class: 'inactive' };
            if (s.startsWith('activat')) return { text: 'STARTING', class: 'inactive' };
            return { text: s || 'N/A', class: 'unknown' };
        }

        function getHealthBadge(stats) {
            if (!stats || stats.total_requests === 0) return { text: 'IDLE', class: 'idle' };
            if (stats.success_rate >= 99) return { text: 'HEALTHY', class: 'healthy' };
            if (stats.success_rate >= 95) return { text: 'DEGRADED', class: 'degraded' };
            return { text: 'UNHEALTHY', class: 'failed' };
        }

        function renderBreakdown(items, nameKey, countKey) {
            if (!items || items.length === 0) {
                return '<p style="color: #666; font-size: 0.85em;">No data yet</p>';
            }
            return items.slice(0, 8).map(item => `
                <div class="stat">
                    <span class="stat-label">${item[nameKey] || 'unknown'}</span>
                    <span class="stat-value">${item[countKey] || 0}</span>
                </div>
            `).join('');
        }

        async function refreshData() {
            try {
                const [statsRes, dataRes, storageRes, statusRes, systemRes, analyticsRes] = await Promise.all([
                    fetch('/api/statistics'),
                    fetch('/api/data?limit=8'),
                    fetch('/api/storage'),
                    fetch('/scout/status'),
                    fetch('/api/system'),
                    fetch('/api/analytics')
                ]);

                const stats = await statsRes.json();
                const data = await dataRes.json();
                const storage = await storageRes.json();
                const status = await statusRes.json();
                const system = await systemRes.json();
                const analytics = await analyticsRes.json();

                // Update last refresh time
                document.getElementById('last-update').textContent =
                    'Updated: ' + new Date().toLocaleTimeString();

                // Update service statuses
                if (system.services) {
                    const svc = system.services;
                    ['capture', 'mover', 'timer', 'zeek', 'hotswap', 'receiver'].forEach(name => {
                        const badge = getStatusBadge(svc[name]);
                        const el = document.getElementById('svc-' + name);
                        if (el) {
                            el.textContent = badge.text;
                            el.className = 'status-badge ' + badge.class;
                        }
                    });
                }

                // PCAP counts
                if (system.pcap) {
                    document.getElementById('pcap-ring').textContent = system.pcap.ring || 0;
                    document.getElementById('pcap-backlog').textContent = system.pcap.backlog || 0;
                    document.getElementById('pcap-queue').textContent = system.pcap.queue || 0;
                }

                // Export drive
                if (system.export_drive) {
                    const drv = system.export_drive;
                    const driveEl = document.getElementById('drive-status');
                    if (drv.mounted) {
                        driveEl.textContent = 'CONNECTED';
                        driveEl.className = 'status-badge active';
                    } else if (drv.present) {
                        driveEl.textContent = 'PRESENT';
                        driveEl.className = 'status-badge inactive';
                    } else {
                        driveEl.textContent = 'NOT CONNECTED';
                        driveEl.className = 'status-badge inactive';
                    }
                    document.getElementById('drive-mount').textContent = drv.mount_point || '-';
                    document.getElementById('drive-files').textContent = drv.files || 0;
                    document.getElementById('drive-export').textContent = drv.last_export || 'never';
                }

                // JSON/Zeek stats
                if (system.json) {
                    document.getElementById('json-count').textContent = system.json.count || 0;
                    document.getElementById('json-size').textContent = formatBytes(system.json.bytes);
                    document.getElementById('json-rate').textContent = '-'; // Would need rate tracking
                }

                // Scout Receiver Status
                const health = getHealthBadge(stats);
                document.getElementById('recv-status').textContent = health.text;
                document.getElementById('recv-status').className = 'status-badge ' + health.class;
                document.getElementById('recv-uptime').textContent = formatUptime(stats.uptime_seconds);
                document.getElementById('recv-requests').textContent = stats.total_requests || 0;
                document.getElementById('recv-success').textContent = (stats.success_rate || 0) + '%';
                document.getElementById('recv-rpm').textContent = (stats.requests_per_minute || 0).toFixed(1);

                // Data Reception
                document.getElementById('data-received').textContent = (stats.total_data_received_mb || 0) + ' MB';
                document.getElementById('records').textContent = stats.total_records_received || 0;
                document.getElementById('sources').textContent = stats.unique_sources || 0;
                document.getElementById('avg-time').textContent =
                    ((stats.average_processing_time || 0) * 1000).toFixed(1) + 'ms';

                // Storage
                document.getElementById('files-created').textContent =
                    storage.files_created || storage.total_files || 0;
                document.getElementById('storage-size').textContent =
                    (storage.total_size_mb || 0).toFixed(1) + ' MB';
                const diskFree = storage.disk_free_pct;
                const diskFreeEl = document.getElementById('disk-free');
                diskFreeEl.textContent = (diskFree !== undefined ? diskFree + '%' : 'N/A');
                if (diskFree !== undefined && diskFree < 10) {
                    diskFreeEl.classList.add('error');
                } else if (diskFree !== undefined && diskFree < 25) {
                    diskFreeEl.classList.add('warning');
                }
                document.getElementById('retention').textContent =
                    (storage.retention_days || 30) + ' days';

                // Validation stats from status
                if (status.validation_statistics) {
                    const val = status.validation_statistics;
                    document.getElementById('val-total').textContent = val.total_validations || 0;
                    document.getElementById('val-success').textContent = val.successful_validations || 0;
                    document.getElementById('val-failed').textContent = val.failed_validations || 0;
                    const valFailed = document.getElementById('val-failed');
                    if ((val.failed_validations || 0) > 0) {
                        valFailed.classList.add('error');
                    }
                    document.getElementById('val-checksum').textContent = val.checksum_failures || 0;
                }

                // Event Analytics
                if (analytics) {
                    // Data Types breakdown
                    document.getElementById('data-types-breakdown').innerHTML =
                        renderBreakdown(analytics.data_types, 'type', 'count');

                    // Event Schemas breakdown
                    document.getElementById('event-schemas-breakdown').innerHTML =
                        renderBreakdown(analytics.event_schemas, 'schema', 'count');

                    // Event Types breakdown
                    document.getElementById('event-types-breakdown').innerHTML =
                        renderBreakdown(analytics.event_types, 'event_type', 'count');

                    // Analytics summary
                    if (analytics.totals) {
                        document.getElementById('unique-data-types').textContent = analytics.totals.unique_data_types || 0;
                        document.getElementById('unique-schemas').textContent = analytics.totals.unique_event_schemas || 0;
                        document.getElementById('unique-event-types').textContent = analytics.totals.unique_event_types || 0;
                        document.getElementById('analytics-records').textContent = analytics.totals.total_records || 0;
                    }
                }

                // Source breakdown from detailed metrics
                try {
                    const metricsRes = await fetch('/scout/metrics');
                    const metrics = await metricsRes.json();
                    if (metrics.source_breakdown && metrics.source_breakdown.length > 0) {
                        const sourceHtml = metrics.source_breakdown.slice(0, 10).map(src => `
                            <tr>
                                <td>${src.source_ip}</td>
                                <td>${src.requests}</td>
                                <td>${formatBytes(src.bytes)}</td>
                                <td class="timestamp">${src.last_seen ? new Date(src.last_seen).toLocaleTimeString() : '-'}</td>
                            </tr>
                        `).join('');
                        document.getElementById('source-table').innerHTML = sourceHtml ||
                            '<tr><td colspan="4" style="color: #666;">No agents connected</td></tr>';
                    }
                } catch (e) {
                    console.log('Could not fetch metrics:', e);
                }

                // Recent Data
                const dataHtml = data.map(entry => `
                    <div class="data-entry success">
                        <strong>${entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : '-'}</strong>
                        - ${entry.source_ip} (${entry.data_type || 'unknown'})<br>
                        <span style="color: #888;">Host: ${entry.host_id || '-'} |
                        Records: ${entry.record_count || 1} |
                        Size: ${formatBytes(entry.data_size)}</span>
                    </div>
                `).join('') || '<p style="color: #666;">No data received yet</p>';
                document.getElementById('recent-data').innerHTML = dataHtml;

            } catch (error) {
                console.error('Refresh failed:', error);
                document.getElementById('recv-status').textContent = 'ERROR';
                document.getElementById('recv-status').className = 'status-badge failed';
            }
        }

        // Auto-refresh toggle
        document.getElementById('auto-refresh').addEventListener('change', function() {
            if (this.checked) {
                refreshInterval = setInterval(refreshData, 5000);
            } else {
                clearInterval(refreshInterval);
            }
        });

        // Initial load and start auto-refresh
        refreshData();
        refreshInterval = setInterval(refreshData, 5000);
    </script>
</body>
</html>"""

    # ==================== Server Lifecycle ====================

    async def start(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        """Start the HTTP server.

        Args:
            host: Host address to bind to
            port: Port number to bind to
        """
        host = host or self.config.get("server.host", "0.0.0.0")
        port = port or self.config.get("server.port", 8080)

        self.is_running = True
        self.start_time = time.time()

        # Start heartbeat handler
        await self.heartbeat.start()

        logger.info(f"Starting Scout Receiver on {host}:{port}")

        # Create and start the web server
        runner = web.AppRunner(self.app)
        await runner.setup()

        site = web.TCPSite(runner, host, port)
        await site.start()

        logger.info(f"Scout Receiver started successfully on http://{host}:{port}")

    async def stop(self) -> None:
        """Stop the HTTP server."""
        self.is_running = False

        # Stop heartbeat
        await self.heartbeat.stop()

        # Close WebSocket connections
        for ws in self.websocket_connections.copy():
            await ws.close()

        logger.info("Scout Receiver stopped")

    def get_statistics(self) -> Dict[str, Any]:
        """Get server statistics."""
        return {
            "is_running": self.is_running,
            "start_time": self.start_time,
            "uptime": time.time() - self.start_time if self.start_time else 0,
            "received_data_count": len(self.received_data),
            "websocket_connections": len(self.websocket_connections),
            "processing_statistics": self.statistics.get_statistics(),
            "validation_statistics": self.validator.get_validation_statistics(),
            "heartbeat_statistics": self.heartbeat.get_statistics(),
            "storage_statistics": self.storage.get_storage_stats(),
        }


async def main() -> None:
    """Main entry point for the server."""
    # Load configuration
    config = load_config()

    # Setup logging
    logging_config = config.get_section("logging")
    setup_logging(
        level=logging_config.get("level", "INFO"),
        format_type=logging_config.get("format", "structured"),
        log_file=logging_config.get("file"),
        max_size_mb=logging_config.get("max_size_mb", 50),
        backup_count=logging_config.get("backup_count", 5),
    )

    # Check if enabled
    if not config.is_enabled():
        logger.info("Scout Receiver is disabled in configuration")
        return

    # Create and start server
    server = ScoutReceiverServer(config)

    server_config = config.get_section("server")
    host = server_config.get("host", "0.0.0.0")
    port = server_config.get("port", 8080)

    try:
        await server.start(host, port)

        # Keep server running
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
