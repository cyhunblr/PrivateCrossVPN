#!/usr/bin/env python3
"""
PrivateCrossVPN — A production-grade, cross-platform VPN management application.

Supports WireGuard, OpenVPN, and SSH SOCKS5 tunneling on Windows 11 and Ubuntu 20.04/22.04.
Built with CustomTkinter for a modern, intuitive UI.

Author : PrivateCrossVPN Team
License: MIT
Python : 3.10+
"""

from __future__ import annotations

import ctypes
import datetime
import ipaddress
import json
import logging
import os
import platform
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import traceback
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# Third-party imports (CustomTkinter)
# ---------------------------------------------------------------------------
try:
    import customtkinter as ctk  # type: ignore[import-untyped]
    from tkinter import filedialog, messagebox
except ImportError:
    sys.exit(
        "[FATAL] customtkinter is required.\n"
        "Install it with:  pip install customtkinter\n"
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_NAME = "PrivateCrossVPN"
APP_VERSION = "1.0.0"
LOG_DATE_FMT = "%Y-%m-%d %H:%M:%S"
IP_API_URL = "https://ipinfo.io/json"
IP_API_TIMEOUT = 8  # seconds
RECONNECT_DELAY_BASE = 3  # seconds (exponential back-off base)
RECONNECT_MAX_RETRIES = 5
HEARTBEAT_INTERVAL = 15  # seconds between connection health checks
CONFIG_DIR = Path.home() / ".privatecrossvpn"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Enums & Data Classes
# ---------------------------------------------------------------------------

class OSType(Enum):
    WINDOWS = auto()
    LINUX = auto()
    UNSUPPORTED = auto()


class Protocol(Enum):
    WIREGUARD = "WireGuard"
    OPENVPN = "OpenVPN"
    SSH_SOCKS5 = "SSH SOCKS5"


class TunnelState(Enum):
    DISCONNECTED = "Disconnected"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"
    RECONNECTING = "Reconnecting"
    DISCONNECTING = "Disconnecting"
    ERROR = "Error"


@dataclass
class ConnectionProfile:
    """Holds all parameters needed to establish a tunnel."""
    protocol: Protocol
    config_path: Optional[Path] = None       # .conf / .ovpn
    ssh_host: str = ""
    ssh_port: int = 22
    ssh_user: str = ""
    ssh_key_path: Optional[Path] = None      # .pem
    socks_port: int = 1080
    extra_args: list[str] = field(default_factory=list)


@dataclass
class IPInfo:
    ip: str = "N/A"
    city: str = "N/A"
    region: str = "N/A"
    country: str = "N/A"
    org: str = "N/A"
    timezone: str = "N/A"


# ---------------------------------------------------------------------------
# Logging — thread-safe queue-based handler that feeds into the UI
# ---------------------------------------------------------------------------

class QueueLogHandler(logging.Handler):
    """Pushes log records into a queue for the UI to consume."""

    def __init__(self, log_queue: queue.Queue[str]) -> None:
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self.log_queue.put(msg)
        except Exception:
            self.handleError(record)


log_queue: queue.Queue[str] = queue.Queue()
logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.DEBUG)

_queue_handler = QueueLogHandler(log_queue)
_queue_handler.setFormatter(logging.Formatter(f"%(asctime)s [%(levelname)s] %(message)s", datefmt=LOG_DATE_FMT))
logger.addHandler(_queue_handler)

_stream_handler = logging.StreamHandler(sys.stdout)
_stream_handler.setFormatter(logging.Formatter(f"%(asctime)s [%(levelname)s] %(message)s", datefmt=LOG_DATE_FMT))
logger.addHandler(_stream_handler)


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 1 — SystemHandler
# ═══════════════════════════════════════════════════════════════════════════

class SystemHandler:
    """Detects the host OS and manages administrative privilege escalation."""

    def __init__(self) -> None:
        self.os_type = self._detect_os()
        logger.info("Detected OS: %s (%s)", self.os_type.name, platform.platform())

    # --- OS detection -------------------------------------------------------

    @staticmethod
    def _detect_os() -> OSType:
        system = platform.system().lower()
        if system == "windows":
            return OSType.WINDOWS
        if system == "linux":
            return OSType.LINUX
        return OSType.UNSUPPORTED

    # --- Privilege checks ---------------------------------------------------

    def is_admin(self) -> bool:
        """Return True if the process is running with elevated privileges."""
        if self.os_type == OSType.WINDOWS:
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
            except AttributeError:
                return False
        if self.os_type == OSType.LINUX:
            return os.geteuid() == 0
        return False

    def request_elevation(self) -> bool:
        """
        Attempt to re-launch the current process with elevated privileges.

        On Windows: triggers a UAC prompt via ShellExecuteW.
        On Linux : re-launches with pkexec / sudo.

        Returns True if re-launch was initiated (caller should exit).
        Returns False if elevation is not possible or was declined.
        """
        if self.is_admin():
            return False  # Already elevated

        logger.warning("Elevated privileges required — requesting escalation …")

        if self.os_type == OSType.WINDOWS:
            try:
                params = " ".join([f'"{arg}"' for arg in sys.argv])
                ret = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
                    None, "runas", sys.executable, params, None, 1,
                )
                return ret > 32  # ShellExecute returns >32 on success
            except Exception as exc:
                logger.error("UAC elevation failed: %s", exc)
                return False

        if self.os_type == OSType.LINUX:
            escalation_cmds = ["pkexec", "sudo"]
            for cmd in escalation_cmds:
                if shutil.which(cmd):
                    try:
                        args = [cmd, sys.executable] + sys.argv
                        logger.info("Re-launching with: %s", " ".join(args))
                        subprocess.Popen(args, shell=False)
                        return True
                    except Exception as exc:
                        logger.error("Elevation with %s failed: %s", cmd, exc)
            logger.error("No suitable elevation tool found (pkexec, sudo).")
            return False

        return False

    # --- Binary availability ------------------------------------------------

    def check_binary(self, name: str) -> Optional[str]:
        """Return the full path to *name* if it exists on PATH, else None."""
        path = shutil.which(name)
        if path:
            logger.debug("Binary found: %s -> %s", name, path)
        else:
            logger.warning("Binary NOT found on PATH: %s", name)
        return path

    # --- Safe subprocess execution ------------------------------------------

    def run_cmd(
        self,
        args: list[str],
        *,
        timeout: int = 60,
        capture: bool = True,
        check: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        """
        Execute a command with shell=False for safety.
        All stdout/stderr is captured and streamed to the logger.
        """
        logger.info("CMD> %s", " ".join(args))
        try:
            result = subprocess.run(
                args,
                shell=False,
                capture_output=capture,
                text=True,
                timeout=timeout,
                check=check,
            )
            if result.stdout:
                for line in result.stdout.strip().splitlines():
                    logger.debug("  stdout: %s", line)
            if result.stderr:
                for line in result.stderr.strip().splitlines():
                    logger.debug("  stderr: %s", line)
            return result
        except subprocess.TimeoutExpired:
            logger.error("Command timed out after %ds: %s", timeout, " ".join(args))
            raise
        except FileNotFoundError:
            logger.error("Command not found: %s", args[0])
            raise

    def popen_cmd(
        self,
        args: list[str],
        **kwargs: Any,
    ) -> subprocess.Popen[str]:
        """
        Launch a long-running process (e.g. openvpn, ssh) via Popen with
        shell=False. Returns the Popen handle so the caller can manage it.
        """
        logger.info("POPEN> %s", " ".join(args))
        return subprocess.Popen(
            args,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **kwargs,
        )


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 2 — SecurityGuard  (Kill-Switch)
# ═══════════════════════════════════════════════════════════════════════════

class SecurityGuard:
    """
    Implements a strict Kill-Switch that blocks all non-VPN traffic.

    - Windows : netsh advfirewall rules
    - Linux   : iptables / ufw
    """

    RULE_PREFIX = "PrivateCrossVPN_KillSwitch"

    def __init__(self, system: SystemHandler) -> None:
        self.system = system
        self._active = False

    @property
    def is_active(self) -> bool:
        return self._active

    # --- Public API ---------------------------------------------------------

    def enable(self, vpn_interface: str = "", vpn_server_ip: str = "", vpn_port: int = 0, protocol_name: str = "udp") -> None:
        """Activate the kill-switch."""
        if self._active:
            logger.info("Kill-switch already active.")
            return
        logger.info("Enabling kill-switch …")
        try:
            if self.system.os_type == OSType.WINDOWS:
                self._enable_windows(vpn_server_ip, vpn_port, protocol_name)
            elif self.system.os_type == OSType.LINUX:
                self._enable_linux(vpn_interface, vpn_server_ip, vpn_port, protocol_name)
            self._active = True
            logger.info("Kill-switch ENABLED.")
        except Exception as exc:
            logger.error("Failed to enable kill-switch: %s", exc)
            raise

    def disable(self) -> None:
        """Deactivate the kill-switch and restore default rules."""
        if not self._active:
            return
        logger.info("Disabling kill-switch …")
        try:
            if self.system.os_type == OSType.WINDOWS:
                self._disable_windows()
            elif self.system.os_type == OSType.LINUX:
                self._disable_linux()
            self._active = False
            logger.info("Kill-switch DISABLED.")
        except Exception as exc:
            logger.error("Failed to disable kill-switch: %s", exc)
            raise

    # --- Windows implementation (netsh advfirewall) -------------------------

    def _enable_windows(self, vpn_server_ip: str, vpn_port: int, protocol_name: str) -> None:
        # Block all outbound traffic by default
        self.system.run_cmd([
            "netsh", "advfirewall", "set", "allprofiles",
            "firewallpolicy", "blockinbound,blockoutbound",
        ])

        # Allow traffic to the VPN server itself
        if vpn_server_ip:
            self.system.run_cmd([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={self.RULE_PREFIX}_AllowVPN",
                "dir=out", "action=allow",
                f"remoteip={vpn_server_ip}",
                f"protocol={protocol_name}",
                f"remoteport={vpn_port}" if vpn_port else "",
                "enable=yes",
            ])

        # Allow loopback
        self.system.run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={self.RULE_PREFIX}_AllowLoopback",
            "dir=out", "action=allow",
            "remoteip=127.0.0.0/8",
            "enable=yes",
        ])

        # Allow LAN (DHCP / DNS)
        for subnet in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            self.system.run_cmd([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={self.RULE_PREFIX}_AllowLAN_{subnet.replace('/', '_')}",
                "dir=out", "action=allow",
                f"remoteip={subnet}",
                "enable=yes",
            ])

    def _disable_windows(self) -> None:
        # Remove our custom rules
        try:
            result = self.system.run_cmd([
                "netsh", "advfirewall", "firewall", "show", "rule",
                f"name=all", "dir=out",
            ], timeout=30)
            # Delete all rules with our prefix
            for rule_name_suffix in ("_AllowVPN", "_AllowLoopback",
                                     "_AllowLAN_10.0.0.0_8",
                                     "_AllowLAN_172.16.0.0_12",
                                     "_AllowLAN_192.168.0.0_16"):
                try:
                    self.system.run_cmd([
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={self.RULE_PREFIX}{rule_name_suffix}",
                    ])
                except Exception:
                    pass  # Rule may not exist
        except Exception:
            pass

        # Restore default outbound policy
        self.system.run_cmd([
            "netsh", "advfirewall", "set", "allprofiles",
            "firewallpolicy", "blockinbound,allowoutbound",
        ])

    # --- Linux implementation (iptables) ------------------------------------

    def _enable_linux(self, vpn_interface: str, vpn_server_ip: str, vpn_port: int, protocol_name: str) -> None:
        iptables = "iptables"

        # Flush any previous kill-switch rules via our custom chain
        for cmd in (
            [iptables, "-D", "OUTPUT", "-j", self.RULE_PREFIX],
            [iptables, "-F", self.RULE_PREFIX],
            [iptables, "-X", self.RULE_PREFIX],
        ):
            try:
                self.system.run_cmd(cmd, timeout=10)
            except Exception:
                pass

        # Create our chain
        self.system.run_cmd([iptables, "-N", self.RULE_PREFIX])

        # Allow loopback
        self.system.run_cmd([
            iptables, "-A", self.RULE_PREFIX,
            "-o", "lo", "-j", "ACCEPT",
        ])

        # Allow LAN subnets
        for subnet in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            self.system.run_cmd([
                iptables, "-A", self.RULE_PREFIX,
                "-d", subnet, "-j", "ACCEPT",
            ])

        # Allow established/related connections
        self.system.run_cmd([
            iptables, "-A", self.RULE_PREFIX,
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ])

        # Allow traffic to the VPN server
        if vpn_server_ip:
            proto_args = ["-p", protocol_name] if protocol_name else []
            port_args = ["--dport", str(vpn_port)] if vpn_port else []
            self.system.run_cmd([
                iptables, "-A", self.RULE_PREFIX,
                "-d", vpn_server_ip,
                *proto_args, *port_args,
                "-j", "ACCEPT",
            ])

        # Allow traffic through the VPN interface
        if vpn_interface:
            self.system.run_cmd([
                iptables, "-A", self.RULE_PREFIX,
                "-o", vpn_interface, "-j", "ACCEPT",
            ])

        # Default: drop everything else
        self.system.run_cmd([
            iptables, "-A", self.RULE_PREFIX, "-j", "DROP",
        ])

        # Insert our chain into OUTPUT
        self.system.run_cmd([
            iptables, "-I", "OUTPUT", "-j", self.RULE_PREFIX,
        ])

    def _disable_linux(self) -> None:
        iptables = "iptables"
        for cmd in (
            [iptables, "-D", "OUTPUT", "-j", self.RULE_PREFIX],
            [iptables, "-F", self.RULE_PREFIX],
            [iptables, "-X", self.RULE_PREFIX],
        ):
            try:
                self.system.run_cmd(cmd, timeout=10)
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 3 — TunnelEngine
# ═══════════════════════════════════════════════════════════════════════════

class BaseTunnel:
    """Abstract base for tunnel implementations."""

    def __init__(self, system: SystemHandler, profile: ConnectionProfile) -> None:
        self.system = system
        self.profile = profile
        self.state = TunnelState.DISCONNECTED
        self._process: Optional[subprocess.Popen[str]] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def connect(self) -> None:
        raise NotImplementedError

    def disconnect(self) -> None:
        raise NotImplementedError

    def is_alive(self) -> bool:
        """Check if the tunnel process is still running."""
        if self._process is None:
            return False
        return self._process.poll() is None

    def _kill_process(self) -> None:
        if self._process is None:
            return
        try:
            self._process.terminate()
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=5)
        except Exception as exc:
            logger.error("Error killing tunnel process: %s", exc)
        finally:
            self._process = None

    def _stream_output(self, proc: subprocess.Popen[str]) -> None:
        """Read stdout/stderr from a running process and log it."""
        def _reader(stream: Any, label: str) -> None:
            if stream is None:
                return
            try:
                for line in iter(stream.readline, ""):
                    if self._stop_event.is_set():
                        break
                    stripped = line.rstrip()
                    if stripped:
                        logger.debug("[%s] %s", label, stripped)
            except Exception:
                pass

        for stream, label in ((proc.stdout, "OUT"), (proc.stderr, "ERR")):
            t = threading.Thread(target=_reader, args=(stream, label), daemon=True)
            t.start()


# --- WireGuard Tunnel -------------------------------------------------------

class WireGuardTunnel(BaseTunnel):
    """
    WireGuard tunnel via `wg-quick` (Linux) or `wireguard.exe` (Windows).
    """

    def connect(self) -> None:
        if self.state in (TunnelState.CONNECTED, TunnelState.CONNECTING):
            logger.warning("WireGuard tunnel already active or connecting.")
            return

        conf = self.profile.config_path
        if not conf or not conf.exists():
            raise FileNotFoundError(f"WireGuard config not found: {conf}")

        self.state = TunnelState.CONNECTING
        self._stop_event.clear()
        logger.info("Starting WireGuard tunnel with config: %s", conf)

        if self.system.os_type == OSType.LINUX:
            self._connect_linux(conf)
        elif self.system.os_type == OSType.WINDOWS:
            self._connect_windows(conf)

        self.state = TunnelState.CONNECTED
        logger.info("WireGuard tunnel CONNECTED.")

    def _connect_linux(self, conf: Path) -> None:
        wg_quick = self.system.check_binary("wg-quick")
        if not wg_quick:
            raise RuntimeError("wg-quick not found. Install WireGuard: sudo apt install wireguard")

        interface_name = conf.stem
        self.system.run_cmd([wg_quick, "up", str(conf)], timeout=30, check=True)
        logger.info("WireGuard interface '%s' is up.", interface_name)

    def _connect_windows(self, conf: Path) -> None:
        wg_exe = self.system.check_binary("wireguard.exe")
        if not wg_exe:
            wg_exe = r"C:\Program Files\WireGuard\wireguard.exe"
            if not Path(wg_exe).exists():
                raise RuntimeError(
                    "wireguard.exe not found. Install WireGuard from https://www.wireguard.com/install/"
                )

        tunnel_name = conf.stem
        self.system.run_cmd([
            wg_exe, "/installtunnelservice", str(conf),
        ], timeout=30, check=True)
        logger.info("WireGuard tunnel service '%s' installed.", tunnel_name)

    def disconnect(self) -> None:
        if self.state == TunnelState.DISCONNECTED:
            return

        self.state = TunnelState.DISCONNECTING
        self._stop_event.set()
        conf = self.profile.config_path

        if conf:
            if self.system.os_type == OSType.LINUX:
                wg_quick = self.system.check_binary("wg-quick") or "wg-quick"
                try:
                    self.system.run_cmd([wg_quick, "down", str(conf)], timeout=30)
                except Exception as exc:
                    logger.error("wg-quick down failed: %s", exc)
            elif self.system.os_type == OSType.WINDOWS:
                wg_exe = self.system.check_binary("wireguard.exe") or "wireguard.exe"
                tunnel_name = conf.stem
                try:
                    self.system.run_cmd([
                        wg_exe, "/uninstalltunnelservice", tunnel_name,
                    ], timeout=30)
                except Exception as exc:
                    logger.error("wireguard.exe uninstall failed: %s", exc)

        self.state = TunnelState.DISCONNECTED
        logger.info("WireGuard tunnel DISCONNECTED.")

    def is_alive(self) -> bool:
        """Check WireGuard interface status."""
        if self.profile.config_path is None:
            return False
        interface_name = self.profile.config_path.stem

        if self.system.os_type == OSType.LINUX:
            wg = self.system.check_binary("wg") or "wg"
            try:
                result = self.system.run_cmd([wg, "show", interface_name], timeout=10)
                return result.returncode == 0
            except Exception:
                return False
        elif self.system.os_type == OSType.WINDOWS:
            # On Windows, check if the tunnel service is running
            try:
                result = self.system.run_cmd(
                    ["sc", "query", f"WireGuardTunnel${interface_name}"], timeout=10
                )
                return "RUNNING" in (result.stdout or "")
            except Exception:
                return False
        return False


# --- OpenVPN Tunnel ---------------------------------------------------------

class OpenVPNTunnel(BaseTunnel):
    """
    OpenVPN tunnel using the official openvpn binary to parse .ovpn files.
    """

    def connect(self) -> None:
        if self.state in (TunnelState.CONNECTED, TunnelState.CONNECTING):
            logger.warning("OpenVPN tunnel already active or connecting.")
            return

        conf = self.profile.config_path
        if not conf or not conf.exists():
            raise FileNotFoundError(f"OpenVPN config not found: {conf}")

        self.state = TunnelState.CONNECTING
        self._stop_event.clear()
        logger.info("Starting OpenVPN tunnel with config: %s", conf)

        openvpn = self._find_openvpn_binary()
        if not openvpn:
            raise RuntimeError(
                "openvpn binary not found. Install OpenVPN:\n"
                "  Linux:   sudo apt install openvpn\n"
                "  Windows: https://openvpn.net/community-downloads/"
            )

        args = [openvpn, "--config", str(conf)]

        # Append management interface for status queries
        mgmt_port = 7505
        args += ["--management", "127.0.0.1", str(mgmt_port)]

        # Suppress interactive prompts in non-interactive mode
        args += ["--verb", "4"]

        self._process = self.system.popen_cmd(args)
        self._stream_output(self._process)

        # Wait briefly and verify it didn't immediately crash
        time.sleep(3)
        if self._process.poll() is not None:
            stderr = self._process.stderr.read() if self._process.stderr else ""
            self.state = TunnelState.ERROR
            raise RuntimeError(f"OpenVPN exited immediately. stderr: {stderr}")

        self.state = TunnelState.CONNECTED
        logger.info("OpenVPN tunnel CONNECTED (PID %d).", self._process.pid)

    def _find_openvpn_binary(self) -> Optional[str]:
        path = self.system.check_binary("openvpn")
        if path:
            return path
        if self.system.os_type == OSType.WINDOWS:
            candidates = [
                r"C:\Program Files\OpenVPN\bin\openvpn.exe",
                r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
            ]
            for c in candidates:
                if Path(c).exists():
                    return c
        return None

    def disconnect(self) -> None:
        if self.state == TunnelState.DISCONNECTED:
            return

        self.state = TunnelState.DISCONNECTING
        self._stop_event.set()

        # Send SIGTERM / kill the process
        self._kill_process()

        self.state = TunnelState.DISCONNECTED
        logger.info("OpenVPN tunnel DISCONNECTED.")


# --- SSH SOCKS5 Tunnel ------------------------------------------------------

class SSHTunnel(BaseTunnel):
    """
    Lightweight SSH SOCKS5 tunneling via `ssh -D`.
    Creates a local SOCKS5 proxy for browser-based tunneling.
    """

    def connect(self) -> None:
        if self.state in (TunnelState.CONNECTED, TunnelState.CONNECTING):
            logger.warning("SSH SOCKS5 tunnel already active or connecting.")
            return

        p = self.profile
        if not p.ssh_host:
            raise ValueError("SSH host is required for SOCKS5 tunneling.")

        self.state = TunnelState.CONNECTING
        self._stop_event.clear()
        logger.info(
            "Starting SSH SOCKS5 tunnel: %s@%s:%d → local SOCKS5 :%d",
            p.ssh_user or "current_user", p.ssh_host, p.ssh_port, p.socks_port,
        )

        ssh_bin = self.system.check_binary("ssh")
        if not ssh_bin:
            raise RuntimeError("ssh binary not found on PATH.")

        args: list[str] = [
            ssh_bin,
            "-D", str(p.socks_port),
            "-N",                     # No remote command
            "-C",                     # Compression
            "-q",                     # Quiet
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-o", "ExitOnForwardFailure=yes",
            "-p", str(p.ssh_port),
        ]

        if p.ssh_key_path and p.ssh_key_path.exists():
            args += ["-i", str(p.ssh_key_path)]

        target = f"{p.ssh_user}@{p.ssh_host}" if p.ssh_user else p.ssh_host
        args.append(target)

        self._process = self.system.popen_cmd(args)
        self._stream_output(self._process)

        # Verify the SOCKS port is listening
        for attempt in range(10):
            time.sleep(1)
            if self._process.poll() is not None:
                stderr = self._process.stderr.read() if self._process.stderr else ""
                self.state = TunnelState.ERROR
                raise RuntimeError(f"SSH process exited. stderr: {stderr}")
            if self._check_socks_port(p.socks_port):
                break
        else:
            self._kill_process()
            self.state = TunnelState.ERROR
            raise RuntimeError(f"SOCKS5 port {p.socks_port} did not become available.")

        self.state = TunnelState.CONNECTED
        logger.info(
            "SSH SOCKS5 tunnel CONNECTED (PID %d). Configure your browser "
            "to use SOCKS5 proxy at 127.0.0.1:%d",
            self._process.pid, p.socks_port,
        )

    @staticmethod
    def _check_socks_port(port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                return True
        except OSError:
            return False

    def disconnect(self) -> None:
        if self.state == TunnelState.DISCONNECTED:
            return

        self.state = TunnelState.DISCONNECTING
        self._stop_event.set()
        self._kill_process()
        self.state = TunnelState.DISCONNECTED
        logger.info("SSH SOCKS5 tunnel DISCONNECTED.")


# --- Tunnel Factory ---------------------------------------------------------

class TunnelEngine:
    """Factory that creates the appropriate tunnel based on the selected protocol."""

    @staticmethod
    def create(system: SystemHandler, profile: ConnectionProfile) -> BaseTunnel:
        if profile.protocol == Protocol.WIREGUARD:
            return WireGuardTunnel(system, profile)
        elif profile.protocol == Protocol.OPENVPN:
            return OpenVPNTunnel(system, profile)
        elif profile.protocol == Protocol.SSH_SOCKS5:
            return SSHTunnel(system, profile)
        else:
            raise ValueError(f"Unsupported protocol: {profile.protocol}")


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 4 — ReconnectManager
# ═══════════════════════════════════════════════════════════════════════════

class ReconnectManager:
    """
    Monitors tunnel health and automatically reconnects on failure.
    Uses exponential back-off between retries.
    """

    def __init__(
        self,
        tunnel: BaseTunnel,
        on_state_change: Optional[Callable[[TunnelState], None]] = None,
    ) -> None:
        self.tunnel = tunnel
        self.on_state_change = on_state_change
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._retries = 0

    def start(self) -> None:
        """Begin monitoring the tunnel health."""
        self._stop_event.clear()
        self._retries = 0
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="ReconnectManager"
        )
        self._monitor_thread.start()
        logger.info("Reconnect monitor started.")

    def stop(self) -> None:
        """Stop monitoring."""
        self._stop_event.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        logger.info("Reconnect monitor stopped.")

    def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(HEARTBEAT_INTERVAL)
            if self._stop_event.is_set():
                break

            if self.tunnel.state != TunnelState.CONNECTED:
                continue

            if self.tunnel.is_alive():
                self._retries = 0
                continue

            # Tunnel dropped — attempt reconnect
            logger.warning("Tunnel appears to be down. Attempting reconnect …")
            self._attempt_reconnect()

    def _attempt_reconnect(self) -> None:
        while self._retries < RECONNECT_MAX_RETRIES and not self._stop_event.is_set():
            self._retries += 1
            delay = RECONNECT_DELAY_BASE * (2 ** (self._retries - 1))
            logger.info(
                "Reconnect attempt %d/%d in %ds …",
                self._retries, RECONNECT_MAX_RETRIES, delay,
            )

            self.tunnel.state = TunnelState.RECONNECTING
            if self.on_state_change:
                self.on_state_change(TunnelState.RECONNECTING)

            self._stop_event.wait(delay)
            if self._stop_event.is_set():
                break

            try:
                self.tunnel.disconnect()
                self.tunnel.connect()
                if self.tunnel.state == TunnelState.CONNECTED:
                    logger.info("Reconnect succeeded on attempt %d.", self._retries)
                    self._retries = 0
                    if self.on_state_change:
                        self.on_state_change(TunnelState.CONNECTED)
                    return
            except Exception as exc:
                logger.error("Reconnect attempt %d failed: %s", self._retries, exc)

        if self._retries >= RECONNECT_MAX_RETRIES:
            logger.error("Max reconnect retries reached. Giving up.")
            self.tunnel.state = TunnelState.ERROR
            if self.on_state_change:
                self.on_state_change(TunnelState.ERROR)


# ═══════════════════════════════════════════════════════════════════════════
#  IP Info Fetcher (thread-safe)
# ═══════════════════════════════════════════════════════════════════════════

def fetch_ip_info() -> IPInfo:
    """Fetch current public IP information from ipinfo.io."""
    try:
        req = Request(IP_API_URL, headers={"Accept": "application/json", "User-Agent": APP_NAME})
        with urlopen(req, timeout=IP_API_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
            return IPInfo(
                ip=data.get("ip", "N/A"),
                city=data.get("city", "N/A"),
                region=data.get("region", "N/A"),
                country=data.get("country", "N/A"),
                org=data.get("org", "N/A"),
                timezone=data.get("timezone", "N/A"),
            )
    except Exception as exc:
        logger.warning("Failed to fetch IP info: %s", exc)
        return IPInfo()


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 5 — CustomTkinter UI
# ═══════════════════════════════════════════════════════════════════════════

class PrivateCrossVPNApp(ctk.CTk):
    """Main application window built with CustomTkinter."""

    WIDTH = 960
    HEIGHT = 700

    def __init__(self) -> None:
        super().__init__()

        # --- Core modules ---
        self.system = SystemHandler()
        self.security = SecurityGuard(self.system)
        self.tunnel: Optional[BaseTunnel] = None
        self.reconnect_mgr: Optional[ReconnectManager] = None

        # --- State ---
        self._current_profile = ConnectionProfile(protocol=Protocol.WIREGUARD)
        self._tunnel_state = TunnelState.DISCONNECTED
        self._ip_info = IPInfo()
        self._kill_switch_var = ctk.BooleanVar(value=False)

        # --- Window setup ---
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.minsize(800, 600)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self._build_ui()
        self._check_privileges()
        self._poll_log_queue()
        self._refresh_ip_info()

        # Graceful shutdown
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -----------------------------------------------------------------------
    # UI Construction
    # -----------------------------------------------------------------------

    def _build_ui(self) -> None:
        # Grid: sidebar (col 0) + main area (col 1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_area()

    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(10, weight=1)

        # Title
        ctk.CTkLabel(
            sidebar, text=APP_NAME, font=ctk.CTkFont(size=20, weight="bold"),
        ).grid(row=0, column=0, padx=20, pady=(20, 4))

        ctk.CTkLabel(
            sidebar, text=f"v{APP_VERSION}", font=ctk.CTkFont(size=12),
        ).grid(row=1, column=0, padx=20, pady=(0, 20))

        # Protocol selector
        ctk.CTkLabel(sidebar, text="Protocol", anchor="w").grid(
            row=2, column=0, padx=20, pady=(10, 0), sticky="w",
        )
        self._protocol_var = ctk.StringVar(value=Protocol.WIREGUARD.value)
        self._protocol_menu = ctk.CTkOptionMenu(
            sidebar,
            values=[p.value for p in Protocol],
            variable=self._protocol_var,
            command=self._on_protocol_change,
        )
        self._protocol_menu.grid(row=3, column=0, padx=20, pady=(4, 10), sticky="ew")

        # Config file import
        ctk.CTkLabel(sidebar, text="Config File", anchor="w").grid(
            row=4, column=0, padx=20, pady=(10, 0), sticky="w",
        )
        self._config_label = ctk.CTkLabel(
            sidebar, text="No file selected", anchor="w",
            font=ctk.CTkFont(size=11), text_color="gray",
        )
        self._config_label.grid(row=5, column=0, padx=20, pady=(2, 2), sticky="w")
        self._import_btn = ctk.CTkButton(
            sidebar, text="Import Config", command=self._import_config,
        )
        self._import_btn.grid(row=6, column=0, padx=20, pady=(2, 10), sticky="ew")

        # --- SSH-specific fields (hidden by default) ---
        self._ssh_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        # Not gridded initially — shown when SSH protocol selected

        ctk.CTkLabel(self._ssh_frame, text="SSH Host", anchor="w").grid(
            row=0, column=0, padx=0, pady=(4, 0), sticky="w",
        )
        self._ssh_host_entry = ctk.CTkEntry(self._ssh_frame, placeholder_text="host.example.com")
        self._ssh_host_entry.grid(row=1, column=0, padx=0, pady=(2, 4), sticky="ew")

        ctk.CTkLabel(self._ssh_frame, text="SSH User", anchor="w").grid(
            row=2, column=0, padx=0, pady=(4, 0), sticky="w",
        )
        self._ssh_user_entry = ctk.CTkEntry(self._ssh_frame, placeholder_text="root")
        self._ssh_user_entry.grid(row=3, column=0, padx=0, pady=(2, 4), sticky="ew")

        ctk.CTkLabel(self._ssh_frame, text="SSH Port", anchor="w").grid(
            row=4, column=0, padx=0, pady=(4, 0), sticky="w",
        )
        self._ssh_port_entry = ctk.CTkEntry(self._ssh_frame, placeholder_text="22")
        self._ssh_port_entry.grid(row=5, column=0, padx=0, pady=(2, 4), sticky="ew")

        ctk.CTkLabel(self._ssh_frame, text="SOCKS5 Port", anchor="w").grid(
            row=6, column=0, padx=0, pady=(4, 0), sticky="w",
        )
        self._socks_port_entry = ctk.CTkEntry(self._ssh_frame, placeholder_text="1080")
        self._socks_port_entry.grid(row=7, column=0, padx=0, pady=(2, 4), sticky="ew")

        self._ssh_key_label = ctk.CTkLabel(
            self._ssh_frame, text="No key selected", anchor="w",
            font=ctk.CTkFont(size=11), text_color="gray",
        )
        self._ssh_key_label.grid(row=8, column=0, padx=0, pady=(4, 2), sticky="w")
        ctk.CTkButton(
            self._ssh_frame, text="Import SSH Key (.pem)", command=self._import_ssh_key,
        ).grid(row=9, column=0, padx=0, pady=(2, 4), sticky="ew")

        self._ssh_frame.grid_columnconfigure(0, weight=1)

        # Kill-switch toggle
        self._kill_switch_check = ctk.CTkCheckBox(
            sidebar, text="Kill-Switch", variable=self._kill_switch_var,
        )
        self._kill_switch_check.grid(row=8, column=0, padx=20, pady=(10, 10), sticky="w")

        # Connect / Disconnect buttons
        self._connect_btn = ctk.CTkButton(
            sidebar, text="Connect", fg_color="green",
            hover_color="#2d8a2d", command=self._on_connect,
        )
        self._connect_btn.grid(row=11, column=0, padx=20, pady=(10, 4), sticky="ew")

        self._disconnect_btn = ctk.CTkButton(
            sidebar, text="Disconnect", fg_color="#c0392b",
            hover_color="#a93226", command=self._on_disconnect, state="disabled",
        )
        self._disconnect_btn.grid(row=12, column=0, padx=20, pady=(4, 20), sticky="ew")

        # Appearance mode
        ctk.CTkLabel(sidebar, text="Theme", anchor="w").grid(
            row=13, column=0, padx=20, pady=(10, 0), sticky="w",
        )
        ctk.CTkOptionMenu(
            sidebar, values=["Dark", "Light", "System"],
            command=lambda v: ctk.set_appearance_mode(v.lower()),
        ).grid(row=14, column=0, padx=20, pady=(4, 20), sticky="ew")

    def _build_main_area(self) -> None:
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)  # Log area expands

        # --- Status & Location card ---
        status_card = ctk.CTkFrame(main)
        status_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        status_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            status_card, text="Status & Location",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).grid(row=0, column=0, columnspan=3, padx=16, pady=(12, 8), sticky="w")

        # Status indicator
        self._status_label = ctk.CTkLabel(
            status_card, text="● Disconnected",
            font=ctk.CTkFont(size=14), text_color="#e74c3c",
        )
        self._status_label.grid(row=1, column=0, padx=16, pady=4, sticky="w")

        # IP info labels
        labels_data = [
            ("IP Address:", "_ip_val"),
            ("Location:", "_loc_val"),
            ("ISP / Org:", "_org_val"),
            ("Timezone:", "_tz_val"),
        ]
        for i, (text, attr) in enumerate(labels_data, start=2):
            ctk.CTkLabel(status_card, text=text, anchor="w").grid(
                row=i, column=0, padx=(16, 4), pady=2, sticky="w",
            )
            lbl = ctk.CTkLabel(status_card, text="N/A", anchor="w")
            lbl.grid(row=i, column=1, padx=(4, 16), pady=2, sticky="w")
            setattr(self, attr, lbl)

        self._refresh_ip_btn = ctk.CTkButton(
            status_card, text="Refresh IP", width=100, command=self._refresh_ip_info,
        )
        self._refresh_ip_btn.grid(row=2, column=2, rowspan=2, padx=16, pady=4, sticky="e")

        # Bottom padding
        ctk.CTkLabel(status_card, text="").grid(row=6, column=0, pady=(0, 8))

        # --- Connection info bar ---
        info_bar = ctk.CTkFrame(main)
        info_bar.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        info_bar.grid_columnconfigure(1, weight=1)

        self._proto_info_label = ctk.CTkLabel(
            info_bar, text="Protocol: WireGuard", anchor="w",
        )
        self._proto_info_label.grid(row=0, column=0, padx=16, pady=8, sticky="w")

        self._killswitch_info_label = ctk.CTkLabel(
            info_bar, text="Kill-Switch: OFF", anchor="w", text_color="gray",
        )
        self._killswitch_info_label.grid(row=0, column=1, padx=16, pady=8, sticky="w")

        self._uptime_label = ctk.CTkLabel(
            info_bar, text="Uptime: --:--:--", anchor="e",
        )
        self._uptime_label.grid(row=0, column=2, padx=16, pady=8, sticky="e")

        # --- Activity Log ---
        log_label_frame = ctk.CTkFrame(main, fg_color="transparent")
        log_label_frame.grid(row=2, column=0, sticky="nsew")
        log_label_frame.grid_columnconfigure(0, weight=1)
        log_label_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            log_label_frame, text="Activity Log",
            font=ctk.CTkFont(size=14, weight="bold"), anchor="w",
        ).grid(row=0, column=0, padx=0, pady=(0, 4), sticky="w")

        self._log_textbox = ctk.CTkTextbox(
            log_label_frame, state="disabled",
            font=ctk.CTkFont(family="Consolas" if self.system.os_type == OSType.WINDOWS else "monospace", size=12),
        )
        self._log_textbox.grid(row=1, column=0, sticky="nsew")

        ctk.CTkButton(
            log_label_frame, text="Clear Log", width=80,
            command=self._clear_log,
        ).grid(row=0, column=0, padx=0, pady=(0, 4), sticky="e")

    # -----------------------------------------------------------------------
    # Event Handlers
    # -----------------------------------------------------------------------

    def _on_protocol_change(self, value: str) -> None:
        proto = Protocol(value)
        self._current_profile.protocol = proto
        self._proto_info_label.configure(text=f"Protocol: {proto.value}")

        # Show/hide SSH fields
        if proto == Protocol.SSH_SOCKS5:
            self._ssh_frame.grid(row=7, column=0, padx=20, pady=(0, 10), sticky="ew")
            self._import_btn.configure(state="disabled")
            self._config_label.configure(text="(Not needed for SSH)")
        else:
            self._ssh_frame.grid_forget()
            self._import_btn.configure(state="normal")
            self._config_label.configure(text="No file selected")

    def _import_config(self) -> None:
        proto = Protocol(self._protocol_var.get())
        if proto == Protocol.WIREGUARD:
            filetypes = [("WireGuard Config", "*.conf"), ("All Files", "*.*")]
        elif proto == Protocol.OPENVPN:
            filetypes = [("OpenVPN Config", "*.ovpn"), ("All Files", "*.*")]
        else:
            filetypes = [("All Files", "*.*")]

        path = filedialog.askopenfilename(
            title="Import VPN Configuration",
            filetypes=filetypes,
        )
        if path:
            self._current_profile.config_path = Path(path)
            self._config_label.configure(text=Path(path).name)
            logger.info("Config imported: %s", path)

    def _import_ssh_key(self) -> None:
        path = filedialog.askopenfilename(
            title="Import SSH Private Key",
            filetypes=[("PEM Key", "*.pem"), ("All Files", "*.*")],
        )
        if path:
            self._current_profile.ssh_key_path = Path(path)
            self._ssh_key_label.configure(text=Path(path).name)
            logger.info("SSH key imported: %s", path)

    def _build_profile(self) -> ConnectionProfile:
        """Build a ConnectionProfile from the current UI state."""
        proto = Protocol(self._protocol_var.get())
        profile = ConnectionProfile(protocol=proto)
        profile.config_path = self._current_profile.config_path
        profile.ssh_key_path = self._current_profile.ssh_key_path

        if proto == Protocol.SSH_SOCKS5:
            profile.ssh_host = self._ssh_host_entry.get().strip()
            profile.ssh_user = self._ssh_user_entry.get().strip()
            try:
                profile.ssh_port = int(self._ssh_port_entry.get().strip() or "22")
            except ValueError:
                profile.ssh_port = 22
            try:
                profile.socks_port = int(self._socks_port_entry.get().strip() or "1080")
            except ValueError:
                profile.socks_port = 1080

        return profile

    def _on_connect(self) -> None:
        """Validate inputs and start the tunnel in a background thread."""
        profile = self._build_profile()

        # Validation
        if profile.protocol in (Protocol.WIREGUARD, Protocol.OPENVPN):
            if not profile.config_path or not profile.config_path.exists():
                messagebox.showerror("Error", "Please import a valid configuration file.")
                return
        elif profile.protocol == Protocol.SSH_SOCKS5:
            if not profile.ssh_host:
                messagebox.showerror("Error", "SSH host is required.")
                return

        # Disable connect, enable disconnect
        self._connect_btn.configure(state="disabled")
        self._protocol_menu.configure(state="disabled")
        self._import_btn.configure(state="disabled")

        self._update_state(TunnelState.CONNECTING)
        self._connect_start_time = time.time()

        threading.Thread(
            target=self._connect_worker, args=(profile,), daemon=True,
        ).start()

    def _connect_worker(self, profile: ConnectionProfile) -> None:
        """Runs in a background thread to avoid blocking the UI."""
        try:
            self.tunnel = TunnelEngine.create(self.system, profile)
            self.tunnel.connect()

            # Enable kill-switch if requested
            if self._kill_switch_var.get():
                self.security.enable(vpn_interface="", vpn_server_ip="", vpn_port=0)

            # Start reconnect monitor
            self.reconnect_mgr = ReconnectManager(
                self.tunnel, on_state_change=self._on_reconnect_state,
            )
            self.reconnect_mgr.start()

            self.after(0, lambda: self._update_state(TunnelState.CONNECTED))
            self.after(0, lambda: self._disconnect_btn.configure(state="normal"))
            self.after(500, self._refresh_ip_info)
            self.after(0, self._tick_uptime)

        except Exception as exc:
            logger.error("Connection failed: %s", exc)
            self.after(0, lambda: self._update_state(TunnelState.ERROR))
            self.after(0, lambda: self._connect_btn.configure(state="normal"))
            self.after(0, lambda: self._protocol_menu.configure(state="normal"))
            self.after(0, lambda: self._import_btn.configure(state="normal"))
            self.after(
                0,
                lambda e=str(exc): messagebox.showerror("Connection Failed", e),
            )

    def _on_disconnect(self) -> None:
        self._disconnect_btn.configure(state="disabled")
        self._update_state(TunnelState.DISCONNECTING)
        threading.Thread(target=self._disconnect_worker, daemon=True).start()

    def _disconnect_worker(self) -> None:
        try:
            if self.reconnect_mgr:
                self.reconnect_mgr.stop()
                self.reconnect_mgr = None

            if self.tunnel:
                self.tunnel.disconnect()
                self.tunnel = None

            if self.security.is_active:
                self.security.disable()

        except Exception as exc:
            logger.error("Disconnect error: %s", exc)
        finally:
            self.after(0, lambda: self._update_state(TunnelState.DISCONNECTED))
            self.after(0, lambda: self._connect_btn.configure(state="normal"))
            self.after(0, lambda: self._protocol_menu.configure(state="normal"))
            self.after(0, lambda: self._import_btn.configure(state="normal"))
            self.after(500, self._refresh_ip_info)

    def _on_reconnect_state(self, state: TunnelState) -> None:
        """Called by ReconnectManager from its thread."""
        self.after(0, lambda: self._update_state(state))
        if state == TunnelState.CONNECTED:
            self.after(500, self._refresh_ip_info)

    # -----------------------------------------------------------------------
    # UI State Updates
    # -----------------------------------------------------------------------

    def _update_state(self, state: TunnelState) -> None:
        self._tunnel_state = state
        color_map = {
            TunnelState.DISCONNECTED: "#e74c3c",
            TunnelState.CONNECTING: "#f39c12",
            TunnelState.CONNECTED: "#2ecc71",
            TunnelState.RECONNECTING: "#f39c12",
            TunnelState.DISCONNECTING: "#f39c12",
            TunnelState.ERROR: "#e74c3c",
        }
        color = color_map.get(state, "gray")
        self._status_label.configure(text=f"● {state.value}", text_color=color)

        ks_text = "Kill-Switch: ON" if self._kill_switch_var.get() and state == TunnelState.CONNECTED else "Kill-Switch: OFF"
        ks_color = "#2ecc71" if "ON" in ks_text else "gray"
        self._killswitch_info_label.configure(text=ks_text, text_color=ks_color)

    def _tick_uptime(self) -> None:
        if self._tunnel_state not in (TunnelState.CONNECTED, TunnelState.RECONNECTING):
            self._uptime_label.configure(text="Uptime: --:--:--")
            return
        elapsed = int(time.time() - self._connect_start_time)
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        self._uptime_label.configure(text=f"Uptime: {h:02d}:{m:02d}:{s:02d}")
        self.after(1000, self._tick_uptime)

    def _refresh_ip_info(self) -> None:
        """Fetch IP info in a background thread and update the UI."""
        def _worker() -> None:
            info = fetch_ip_info()
            self.after(0, lambda: self._display_ip_info(info))

        threading.Thread(target=_worker, daemon=True).start()

    def _display_ip_info(self, info: IPInfo) -> None:
        self._ip_info = info
        self._ip_val.configure(text=info.ip)
        self._loc_val.configure(text=f"{info.city}, {info.region}, {info.country}")
        self._org_val.configure(text=info.org)
        self._tz_val.configure(text=info.timezone)

    # -----------------------------------------------------------------------
    # Log Console
    # -----------------------------------------------------------------------

    def _poll_log_queue(self) -> None:
        """Drain the log queue and append to the textbox — called every 200ms."""
        batch: list[str] = []
        try:
            while True:
                batch.append(log_queue.get_nowait())
        except queue.Empty:
            pass
        if batch:
            self._log_textbox.configure(state="normal")
            for msg in batch:
                self._log_textbox.insert("end", msg + "\n")
            self._log_textbox.see("end")
            self._log_textbox.configure(state="disabled")
        self.after(200, self._poll_log_queue)

    def _clear_log(self) -> None:
        self._log_textbox.configure(state="normal")
        self._log_textbox.delete("1.0", "end")
        self._log_textbox.configure(state="disabled")

    # -----------------------------------------------------------------------
    # Privilege Check
    # -----------------------------------------------------------------------

    def _check_privileges(self) -> None:
        if self.system.os_type == OSType.UNSUPPORTED:
            logger.error("Unsupported OS detected. Only Windows and Linux are supported.")
            messagebox.showwarning(
                "Unsupported OS",
                "PrivateCrossVPN supports Windows 11 and Ubuntu 20.04/22.04 only.",
            )
            return

        if not self.system.is_admin():
            logger.warning(
                "Running WITHOUT elevated privileges. "
                "VPN tunnels and kill-switch require admin/root access."
            )
            result = messagebox.askyesno(
                "Elevated Privileges Required",
                "PrivateCrossVPN requires administrator/root privileges to manage "
                "VPN tunnels and firewall rules.\n\n"
                "Would you like to restart with elevated privileges?",
            )
            if result:
                if self.system.request_elevation():
                    self.destroy()
                    sys.exit(0)
                else:
                    messagebox.showwarning(
                        "Elevation Failed",
                        "Could not obtain elevated privileges. "
                        "Some features may not work correctly.",
                    )

    # -----------------------------------------------------------------------
    # Graceful Shutdown
    # -----------------------------------------------------------------------

    def _on_close(self) -> None:
        logger.info("Shutting down %s …", APP_NAME)
        try:
            if self.reconnect_mgr:
                self.reconnect_mgr.stop()
            if self.tunnel and self.tunnel.state != TunnelState.DISCONNECTED:
                self.tunnel.disconnect()
            if self.security.is_active:
                self.security.disable()
        except Exception as exc:
            logger.error("Shutdown error: %s", exc)
        self.destroy()


# ═══════════════════════════════════════════════════════════════════════════
#  Entry Point
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    logger.info("Starting %s v%s on %s", APP_NAME, APP_VERSION, platform.platform())
    app = PrivateCrossVPNApp()
    app.mainloop()


if __name__ == "__main__":
    main()
