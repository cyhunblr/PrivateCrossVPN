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
APP_VERSION = "1.1.0"
LOG_DATE_FMT = "%Y-%m-%d %H:%M:%S"
IP_API_URL = "https://ipinfo.io/json"
IP_API_TIMEOUT = 8  # seconds
RECONNECT_DELAY_BASE = 3  # seconds (exponential back-off base)
RECONNECT_MAX_RETRIES = 5
HEARTBEAT_INTERVAL = 15  # seconds between connection health checks
APP_DIR = Path.home() / ".privatecrossvpn"
APP_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_CONFIGS_DIR = APP_DIR / "configs"
DEFAULT_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
SETTINGS_FILE = APP_DIR / "settings.json"

# Icon path resolution: works both from source and when packaged (PyInstaller/Nuitka)
def _resolve_asset_path(relative: str) -> Path:
    """Resolve path to a bundled asset, supporting PyInstaller's _MEIPASS."""
    if hasattr(sys, "_MEIPASS"):
        base = Path(sys._MEIPASS)  # type: ignore[attr-defined]
    else:
        base = Path(__file__).resolve().parent
    return base / relative

ICON_PNG = _resolve_asset_path("img/logo_raw.png")
ICON_ICO = _resolve_asset_path("img/logo.ico")


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
# App Settings (persisted to JSON)
# ---------------------------------------------------------------------------

class AppSettings:
    """Manages persistent application settings."""

    DEFAULTS = {
        "configs_dir": str(DEFAULT_CONFIGS_DIR),
        "theme": "dark",
        "last_profile": "",
    }

    def __init__(self) -> None:
        self._data: dict[str, Any] = dict(self.DEFAULTS)
        self._load()

    def _load(self) -> None:
        if SETTINGS_FILE.exists():
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                self._data.update(saved)
            except Exception:
                pass

    def save(self) -> None:
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except Exception as exc:
            logger.error("Failed to save settings: %s", exc)

    @property
    def configs_dir(self) -> Path:
        p = Path(self._data["configs_dir"])
        p.mkdir(parents=True, exist_ok=True)
        return p

    @configs_dir.setter
    def configs_dir(self, value: Path) -> None:
        self._data["configs_dir"] = str(value)
        self.save()

    @property
    def theme(self) -> str:
        return self._data.get("theme", "dark")

    @theme.setter
    def theme(self, value: str) -> None:
        self._data["theme"] = value
        self.save()

    @property
    def last_profile(self) -> str:
        return self._data.get("last_profile", "")

    @last_profile.setter
    def last_profile(self, value: str) -> None:
        self._data["last_profile"] = value
        self.save()


# ---------------------------------------------------------------------------
# Profile Manager — save / load / list / delete profiles as JSON
# ---------------------------------------------------------------------------

class ProfileManager:
    """Manages saved VPN profiles as JSON files in the configs directory."""

    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings

    @property
    def _dir(self) -> Path:
        return self.settings.configs_dir

    def list_profiles(self) -> list[str]:
        """Return sorted list of saved profile names (without extension)."""
        profiles = []
        for f in self._dir.glob("*.json"):
            profiles.append(f.stem)
        return sorted(profiles)

    def save_profile(self, name: str, data: dict[str, Any]) -> Path:
        """Save a profile dict as JSON. Returns the saved file path."""
        safe_name = re.sub(r'[^\w\-. ]', '_', name)
        path = self._dir / f"{safe_name}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("Profile saved: %s", path)
        return path

    def load_profile(self, name: str) -> Optional[dict[str, Any]]:
        """Load a profile by name. Returns None if not found."""
        path = self._dir / f"{name}.json"
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.error("Failed to load profile '%s': %s", name, exc)
            return None

    def delete_profile(self, name: str) -> bool:
        path = self._dir / f"{name}.json"
        if path.exists():
            path.unlink()
            logger.info("Profile deleted: %s", name)
            return True
        return False

    def profile_to_connection(self, data: dict[str, Any]) -> ConnectionProfile:
        """Convert a saved profile dict to a ConnectionProfile."""
        proto = Protocol(data.get("protocol", "WireGuard"))
        profile = ConnectionProfile(protocol=proto)

        # For WireGuard/OpenVPN the actual config file is generated/saved alongside
        config_file = data.get("config_file")
        if config_file:
            profile.config_path = Path(config_file)

        profile.ssh_host = data.get("ssh_host", "")
        profile.ssh_port = int(data.get("ssh_port", 22))
        profile.ssh_user = data.get("ssh_user", "")
        profile.socks_port = int(data.get("socks_port", 1080))

        ssh_key = data.get("ssh_key_path")
        if ssh_key:
            profile.ssh_key_path = Path(ssh_key)

        return profile

    def generate_wireguard_conf(self, name: str, data: dict[str, Any]) -> Path:
        """Generate a .conf file from the profile fields and return its path."""
        conf_path = self._dir / f"{re.sub(r'[^a-zA-Z0-9_-]', '_', name)}.conf"
        lines = ["[Interface]"]
        if data.get("wg_private_key"):
            lines.append(f"PrivateKey = {data['wg_private_key']}")
        if data.get("wg_address"):
            lines.append(f"Address = {data['wg_address']}")
        if data.get("wg_dns"):
            lines.append(f"DNS = {data['wg_dns']}")
        if data.get("wg_listen_port"):
            lines.append(f"ListenPort = {data['wg_listen_port']}")
        lines.append("")
        lines.append("[Peer]")
        if data.get("wg_public_key"):
            lines.append(f"PublicKey = {data['wg_public_key']}")
        if data.get("wg_preshared_key"):
            lines.append(f"PresharedKey = {data['wg_preshared_key']}")
        if data.get("wg_endpoint"):
            lines.append(f"Endpoint = {data['wg_endpoint']}")
        if data.get("wg_allowed_ips"):
            lines.append(f"AllowedIPs = {data['wg_allowed_ips']}")
        if data.get("wg_keepalive"):
            lines.append(f"PersistentKeepalive = {data['wg_keepalive']}")
        lines.append("")
        conf_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("WireGuard config generated: %s", conf_path)
        return conf_path

    def generate_openvpn_conf(self, name: str, data: dict[str, Any]) -> Path:
        """Generate an .ovpn file from the profile fields and return its path."""
        conf_path = self._dir / f"{re.sub(r'[^a-zA-Z0-9_-]', '_', name)}.ovpn"
        lines = ["client"]
        lines.append(f"dev {data.get('ovpn_dev', 'tun')}")
        lines.append(f"proto {data.get('ovpn_proto', 'udp')}")
        if data.get("ovpn_remote"):
            port = data.get("ovpn_port", "1194")
            lines.append(f"remote {data['ovpn_remote']} {port}")
        lines.append("resolv-retry infinite")
        lines.append("nobind")
        lines.append("persist-key")
        lines.append("persist-tun")
        if data.get("ovpn_cipher"):
            lines.append(f"cipher {data['ovpn_cipher']}")
        if data.get("ovpn_auth"):
            lines.append(f"auth {data['ovpn_auth']}")
        lines.append("verb 3")
        # Inline certificates
        if data.get("ovpn_ca"):
            lines.append("<ca>")
            lines.append(data["ovpn_ca"].strip())
            lines.append("</ca>")
        if data.get("ovpn_cert"):
            lines.append("<cert>")
            lines.append(data["ovpn_cert"].strip())
            lines.append("</cert>")
        if data.get("ovpn_key"):
            lines.append("<key>")
            lines.append(data["ovpn_key"].strip())
            lines.append("</key>")
        if data.get("ovpn_tls_auth"):
            lines.append("<tls-auth>")
            lines.append(data["ovpn_tls_auth"].strip())
            lines.append("</tls-auth>")
        if data.get("ovpn_extra"):
            lines.append(data["ovpn_extra"].strip())
        lines.append("")
        conf_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("OpenVPN config generated: %s", conf_path)
        return conf_path


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
_queue_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt=LOG_DATE_FMT))
logger.addHandler(_queue_handler)

_stream_handler = logging.StreamHandler(sys.stdout)
_stream_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt=LOG_DATE_FMT))
logger.addHandler(_stream_handler)


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 1 — SystemHandler
# ═══════════════════════════════════════════════════════════════════════════

class SystemHandler:
    """Detects the host OS and manages administrative privilege escalation."""

    def __init__(self) -> None:
        self.os_type = self._detect_os()
        logger.info("Detected OS: %s (%s)", self.os_type.name, platform.platform())

    @staticmethod
    def _detect_os() -> OSType:
        system = platform.system().lower()
        if system == "windows":
            return OSType.WINDOWS
        if system == "linux":
            return OSType.LINUX
        return OSType.UNSUPPORTED

    def is_admin(self) -> bool:
        if self.os_type == OSType.WINDOWS:
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
            except AttributeError:
                return False
        if self.os_type == OSType.LINUX:
            return os.geteuid() == 0
        return False

    def request_elevation(self) -> bool:
        if self.is_admin():
            return False

        logger.warning("Elevated privileges required — requesting escalation …")

        if self.os_type == OSType.WINDOWS:
            try:
                params = " ".join([f'"{arg}"' for arg in sys.argv])
                ret = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
                    None, "runas", sys.executable, params, None, 1,
                )
                return ret > 32
            except Exception as exc:
                logger.error("UAC elevation failed: %s", exc)
                return False

        if self.os_type == OSType.LINUX:
            for cmd in ("pkexec", "sudo"):
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

    def check_binary(self, name: str) -> Optional[str]:
        path = shutil.which(name)
        if path:
            logger.debug("Binary found: %s -> %s", name, path)
        else:
            logger.warning("Binary NOT found on PATH: %s", name)
        return path

    def run_cmd(
        self,
        args: list[str],
        *,
        timeout: int = 60,
        capture: bool = True,
        check: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        logger.info("CMD> %s", " ".join(args))
        try:
            result = subprocess.run(
                args, shell=False, capture_output=capture,
                text=True, timeout=timeout, check=check,
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

    def popen_cmd(self, args: list[str], **kwargs: Any) -> subprocess.Popen[str]:
        logger.info("POPEN> %s", " ".join(args))
        return subprocess.Popen(
            args, shell=False, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, **kwargs,
        )


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 2 — SecurityGuard  (Kill-Switch)
# ═══════════════════════════════════════════════════════════════════════════

class SecurityGuard:
    """Kill-Switch: blocks all non-VPN traffic via OS firewall."""

    RULE_PREFIX = "PrivateCrossVPN_KillSwitch"

    def __init__(self, system: SystemHandler) -> None:
        self.system = system
        self._active = False

    @property
    def is_active(self) -> bool:
        return self._active

    def enable(self, vpn_interface: str = "", vpn_server_ip: str = "", vpn_port: int = 0, protocol_name: str = "udp") -> None:
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

    # --- Windows (netsh advfirewall) ----------------------------------------

    def _enable_windows(self, vpn_server_ip: str, vpn_port: int, protocol_name: str) -> None:
        self.system.run_cmd([
            "netsh", "advfirewall", "set", "allprofiles",
            "firewallpolicy", "blockinbound,blockoutbound",
        ])
        if vpn_server_ip:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={self.RULE_PREFIX}_AllowVPN",
                "dir=out", "action=allow",
                f"remoteip={vpn_server_ip}",
                f"protocol={protocol_name}",
            ]
            if vpn_port:
                cmd.append(f"remoteport={vpn_port}")
            cmd.append("enable=yes")
            self.system.run_cmd(cmd)
        self.system.run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={self.RULE_PREFIX}_AllowLoopback",
            "dir=out", "action=allow", "remoteip=127.0.0.0/8", "enable=yes",
        ])
        for subnet in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            self.system.run_cmd([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={self.RULE_PREFIX}_AllowLAN_{subnet.replace('/', '_')}",
                "dir=out", "action=allow", f"remoteip={subnet}", "enable=yes",
            ])

    def _disable_windows(self) -> None:
        for suffix in ("_AllowVPN", "_AllowLoopback",
                        "_AllowLAN_10.0.0.0_8", "_AllowLAN_172.16.0.0_12",
                        "_AllowLAN_192.168.0.0_16"):
            try:
                self.system.run_cmd([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={self.RULE_PREFIX}{suffix}",
                ])
            except Exception:
                pass
        self.system.run_cmd([
            "netsh", "advfirewall", "set", "allprofiles",
            "firewallpolicy", "blockinbound,allowoutbound",
        ])

    # --- Linux (iptables) ---------------------------------------------------

    def _enable_linux(self, vpn_interface: str, vpn_server_ip: str, vpn_port: int, protocol_name: str) -> None:
        ipt = "iptables"
        for cmd in (
            [ipt, "-D", "OUTPUT", "-j", self.RULE_PREFIX],
            [ipt, "-F", self.RULE_PREFIX],
            [ipt, "-X", self.RULE_PREFIX],
        ):
            try:
                self.system.run_cmd(cmd, timeout=10)
            except Exception:
                pass
        self.system.run_cmd([ipt, "-N", self.RULE_PREFIX])
        self.system.run_cmd([ipt, "-A", self.RULE_PREFIX, "-o", "lo", "-j", "ACCEPT"])
        for subnet in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            self.system.run_cmd([ipt, "-A", self.RULE_PREFIX, "-d", subnet, "-j", "ACCEPT"])
        self.system.run_cmd([
            ipt, "-A", self.RULE_PREFIX,
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT",
        ])
        if vpn_server_ip:
            cmd = [ipt, "-A", self.RULE_PREFIX, "-d", vpn_server_ip]
            if protocol_name:
                cmd += ["-p", protocol_name]
            if vpn_port:
                cmd += ["--dport", str(vpn_port)]
            cmd += ["-j", "ACCEPT"]
            self.system.run_cmd(cmd)
        if vpn_interface:
            self.system.run_cmd([ipt, "-A", self.RULE_PREFIX, "-o", vpn_interface, "-j", "ACCEPT"])
        self.system.run_cmd([ipt, "-A", self.RULE_PREFIX, "-j", "DROP"])
        self.system.run_cmd([ipt, "-I", "OUTPUT", "-j", self.RULE_PREFIX])

    def _disable_linux(self) -> None:
        ipt = "iptables"
        for cmd in (
            [ipt, "-D", "OUTPUT", "-j", self.RULE_PREFIX],
            [ipt, "-F", self.RULE_PREFIX],
            [ipt, "-X", self.RULE_PREFIX],
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
        self._stop_event = threading.Event()

    def connect(self) -> None:
        raise NotImplementedError

    def disconnect(self) -> None:
        raise NotImplementedError

    def is_alive(self) -> bool:
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


class WireGuardTunnel(BaseTunnel):
    def connect(self) -> None:
        if self.state in (TunnelState.CONNECTED, TunnelState.CONNECTING):
            return
        conf = self.profile.config_path
        if not conf or not conf.exists():
            raise FileNotFoundError(f"WireGuard config not found: {conf}")
        self.state = TunnelState.CONNECTING
        self._stop_event.clear()
        logger.info("Starting WireGuard tunnel with config: %s", conf)
        if self.system.os_type == OSType.LINUX:
            wg_quick = self.system.check_binary("wg-quick")
            if not wg_quick:
                raise RuntimeError("wg-quick not found. Install: sudo apt install wireguard")
            self.system.run_cmd([wg_quick, "up", str(conf)], timeout=30, check=True)
        elif self.system.os_type == OSType.WINDOWS:
            wg_exe = self.system.check_binary("wireguard.exe")
            if not wg_exe:
                wg_exe = r"C:\Program Files\WireGuard\wireguard.exe"
                if not Path(wg_exe).exists():
                    raise RuntimeError("wireguard.exe not found.")
            self.system.run_cmd([wg_exe, "/installtunnelservice", str(conf)], timeout=30, check=True)
        self.state = TunnelState.CONNECTED
        logger.info("WireGuard tunnel CONNECTED.")

    def disconnect(self) -> None:
        if self.state == TunnelState.DISCONNECTED:
            return
        self.state = TunnelState.DISCONNECTING
        self._stop_event.set()
        conf = self.profile.config_path
        if conf:
            if self.system.os_type == OSType.LINUX:
                try:
                    self.system.run_cmd([self.system.check_binary("wg-quick") or "wg-quick", "down", str(conf)], timeout=30)
                except Exception as exc:
                    logger.error("wg-quick down failed: %s", exc)
            elif self.system.os_type == OSType.WINDOWS:
                try:
                    self.system.run_cmd([
                        self.system.check_binary("wireguard.exe") or "wireguard.exe",
                        "/uninstalltunnelservice", conf.stem,
                    ], timeout=30)
                except Exception as exc:
                    logger.error("wireguard.exe uninstall failed: %s", exc)
        self.state = TunnelState.DISCONNECTED
        logger.info("WireGuard tunnel DISCONNECTED.")

    def is_alive(self) -> bool:
        if not self.profile.config_path:
            return False
        iface = self.profile.config_path.stem
        if self.system.os_type == OSType.LINUX:
            try:
                return self.system.run_cmd([self.system.check_binary("wg") or "wg", "show", iface], timeout=10).returncode == 0
            except Exception:
                return False
        elif self.system.os_type == OSType.WINDOWS:
            try:
                r = self.system.run_cmd(["sc", "query", f"WireGuardTunnel${iface}"], timeout=10)
                return "RUNNING" in (r.stdout or "")
            except Exception:
                return False
        return False


class OpenVPNTunnel(BaseTunnel):
    def connect(self) -> None:
        if self.state in (TunnelState.CONNECTED, TunnelState.CONNECTING):
            return
        conf = self.profile.config_path
        if not conf or not conf.exists():
            raise FileNotFoundError(f"OpenVPN config not found: {conf}")
        self.state = TunnelState.CONNECTING
        self._stop_event.clear()
        logger.info("Starting OpenVPN tunnel with config: %s", conf)
        openvpn = self._find_binary()
        if not openvpn:
            raise RuntimeError("openvpn binary not found.")
        args = [openvpn, "--config", str(conf), "--management", "127.0.0.1", "7505", "--verb", "4"]
        self._process = self.system.popen_cmd(args)
        self._stream_output(self._process)
        time.sleep(3)
        if self._process.poll() is not None:
            stderr = self._process.stderr.read() if self._process.stderr else ""
            self.state = TunnelState.ERROR
            raise RuntimeError(f"OpenVPN exited immediately. stderr: {stderr}")
        self.state = TunnelState.CONNECTED
        logger.info("OpenVPN tunnel CONNECTED (PID %d).", self._process.pid)

    def _find_binary(self) -> Optional[str]:
        path = self.system.check_binary("openvpn")
        if path:
            return path
        if self.system.os_type == OSType.WINDOWS:
            for c in (r"C:\Program Files\OpenVPN\bin\openvpn.exe",
                       r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe"):
                if Path(c).exists():
                    return c
        return None

    def disconnect(self) -> None:
        if self.state == TunnelState.DISCONNECTED:
            return
        self.state = TunnelState.DISCONNECTING
        self._stop_event.set()
        self._kill_process()
        self.state = TunnelState.DISCONNECTED
        logger.info("OpenVPN tunnel DISCONNECTED.")


class SSHTunnel(BaseTunnel):
    def connect(self) -> None:
        if self.state in (TunnelState.CONNECTED, TunnelState.CONNECTING):
            return
        p = self.profile
        if not p.ssh_host:
            raise ValueError("SSH host is required.")
        self.state = TunnelState.CONNECTING
        self._stop_event.clear()
        logger.info("Starting SSH SOCKS5: %s@%s:%d -> :%d",
                     p.ssh_user or "user", p.ssh_host, p.ssh_port, p.socks_port)
        ssh_bin = self.system.check_binary("ssh")
        if not ssh_bin:
            raise RuntimeError("ssh binary not found.")
        args = [
            ssh_bin, "-D", str(p.socks_port), "-N", "-C", "-q",
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
        for _ in range(10):
            time.sleep(1)
            if self._process.poll() is not None:
                stderr = self._process.stderr.read() if self._process.stderr else ""
                self.state = TunnelState.ERROR
                raise RuntimeError(f"SSH exited. stderr: {stderr}")
            if self._check_port(p.socks_port):
                break
        else:
            self._kill_process()
            self.state = TunnelState.ERROR
            raise RuntimeError(f"SOCKS5 port {p.socks_port} not available.")
        self.state = TunnelState.CONNECTED
        logger.info("SSH SOCKS5 CONNECTED (PID %d). Proxy: 127.0.0.1:%d",
                     self._process.pid, p.socks_port)

    @staticmethod
    def _check_port(port: int) -> bool:
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


class TunnelEngine:
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
    def __init__(self, tunnel: BaseTunnel, on_state_change: Optional[Callable[[TunnelState], None]] = None) -> None:
        self.tunnel = tunnel
        self.on_state_change = on_state_change
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._retries = 0

    def start(self) -> None:
        self._stop_event.clear()
        self._retries = 0
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ReconnectManager")
        self._thread.start()
        logger.info("Reconnect monitor started.")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("Reconnect monitor stopped.")

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(HEARTBEAT_INTERVAL)
            if self._stop_event.is_set():
                break
            if self.tunnel.state != TunnelState.CONNECTED:
                continue
            if self.tunnel.is_alive():
                self._retries = 0
                continue
            logger.warning("Tunnel down — reconnecting …")
            self._reconnect()

    def _reconnect(self) -> None:
        while self._retries < RECONNECT_MAX_RETRIES and not self._stop_event.is_set():
            self._retries += 1
            delay = RECONNECT_DELAY_BASE * (2 ** (self._retries - 1))
            logger.info("Reconnect %d/%d in %ds …", self._retries, RECONNECT_MAX_RETRIES, delay)
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
            logger.error("Max reconnect retries reached.")
            self.tunnel.state = TunnelState.ERROR
            if self.on_state_change:
                self.on_state_change(TunnelState.ERROR)


# ═══════════════════════════════════════════════════════════════════════════
#  IP Info
# ═══════════════════════════════════════════════════════════════════════════

def fetch_ip_info() -> IPInfo:
    try:
        req = Request(IP_API_URL, headers={"Accept": "application/json", "User-Agent": APP_NAME})
        with urlopen(req, timeout=IP_API_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
            return IPInfo(
                ip=data.get("ip", "N/A"), city=data.get("city", "N/A"),
                region=data.get("region", "N/A"), country=data.get("country", "N/A"),
                org=data.get("org", "N/A"), timezone=data.get("timezone", "N/A"),
            )
    except Exception as exc:
        logger.warning("Failed to fetch IP info: %s", exc)
        return IPInfo()


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 5 — CustomTkinter UI
# ═══════════════════════════════════════════════════════════════════════════

class PrivateCrossVPNApp(ctk.CTk):
    WIDTH = 1060
    HEIGHT = 740

    def __init__(self) -> None:
        super().__init__()

        # Core modules
        self.system = SystemHandler()
        self.settings = AppSettings()
        self.profile_mgr = ProfileManager(self.settings)
        self.security = SecurityGuard(self.system)
        self.tunnel: Optional[BaseTunnel] = None
        self.reconnect_mgr: Optional[ReconnectManager] = None

        # State
        self._tunnel_state = TunnelState.DISCONNECTED
        self._ip_info = IPInfo()
        self._kill_switch_var = ctk.BooleanVar(value=False)
        self._connect_start_time = 0.0

        # Window
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.minsize(900, 640)
        ctk.set_appearance_mode(self.settings.theme)
        ctk.set_default_color_theme("blue")
        self._set_app_icon()

        self._build_ui()
        self._check_privileges()
        self._poll_log_queue()
        self._refresh_ip_info()
        self._load_profile_list()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -----------------------------------------------------------------------
    # App Icon
    # -----------------------------------------------------------------------

    def _set_app_icon(self) -> None:
        """Set the window icon for title bar, taskbar, and Alt-Tab on all platforms."""
        try:
            if self.system.os_type == OSType.WINDOWS and ICON_ICO.exists():
                # Windows: .ico is preferred for taskbar, title bar, alt-tab
                self.iconbitmap(str(ICON_ICO))
            elif ICON_PNG.exists():
                # Linux / fallback: use PhotoImage from PNG
                from tkinter import PhotoImage
                icon = PhotoImage(file=str(ICON_PNG))
                self.iconphoto(True, icon)
                self._icon_ref = icon  # prevent garbage collection
            logger.debug("App icon set successfully.")
        except Exception as exc:
            logger.warning("Could not set app icon: %s", exc)

    # -----------------------------------------------------------------------
    # UI Construction
    # -----------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main_area()

    def _build_sidebar(self) -> None:
        sb = ctk.CTkFrame(self, width=260, corner_radius=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_rowconfigure(20, weight=1)
        sb.grid_columnconfigure(0, weight=1)

        # Title
        ctk.CTkLabel(sb, text=APP_NAME, font=ctk.CTkFont(size=20, weight="bold")).grid(
            row=0, column=0, padx=20, pady=(20, 2))
        ctk.CTkLabel(sb, text=f"v{APP_VERSION}", font=ctk.CTkFont(size=11)).grid(
            row=1, column=0, padx=20, pady=(0, 16))

        # --- Saved Profiles ---
        ctk.CTkLabel(sb, text="Saved Profiles", anchor="w").grid(
            row=2, column=0, padx=20, pady=(8, 0), sticky="w")

        profile_frame = ctk.CTkFrame(sb, fg_color="transparent")
        profile_frame.grid(row=3, column=0, padx=20, pady=(4, 4), sticky="ew")
        profile_frame.grid_columnconfigure(0, weight=1)

        self._profile_var = ctk.StringVar(value="(new profile)")
        self._profile_menu = ctk.CTkOptionMenu(
            profile_frame, variable=self._profile_var,
            values=["(new profile)"], command=self._on_profile_select,
        )
        self._profile_menu.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        self._delete_profile_btn = ctk.CTkButton(
            profile_frame, text="X", width=32, fg_color="#c0392b",
            hover_color="#a93226", command=self._on_delete_profile,
        )
        self._delete_profile_btn.grid(row=0, column=1)

        # --- Protocol selector ---
        ctk.CTkLabel(sb, text="Protocol", anchor="w").grid(
            row=4, column=0, padx=20, pady=(12, 0), sticky="w")
        self._protocol_var = ctk.StringVar(value=Protocol.WIREGUARD.value)
        self._protocol_menu = ctk.CTkOptionMenu(
            sb, values=[p.value for p in Protocol],
            variable=self._protocol_var, command=self._on_protocol_change,
        )
        self._protocol_menu.grid(row=5, column=0, padx=20, pady=(4, 4), sticky="ew")

        # --- Import from file (alternative) ---
        self._import_btn = ctk.CTkButton(sb, text="Import from File…", command=self._import_config)
        self._import_btn.grid(row=6, column=0, padx=20, pady=(4, 4), sticky="ew")

        # Kill-switch
        self._kill_switch_check = ctk.CTkCheckBox(sb, text="Kill-Switch", variable=self._kill_switch_var)
        self._kill_switch_check.grid(row=7, column=0, padx=20, pady=(12, 4), sticky="w")

        # Connect / Disconnect
        self._connect_btn = ctk.CTkButton(
            sb, text="Connect", fg_color="green", hover_color="#2d8a2d",
            command=self._on_connect,
        )
        self._connect_btn.grid(row=21, column=0, padx=20, pady=(10, 4), sticky="ew")

        self._disconnect_btn = ctk.CTkButton(
            sb, text="Disconnect", fg_color="#c0392b", hover_color="#a93226",
            command=self._on_disconnect, state="disabled",
        )
        self._disconnect_btn.grid(row=22, column=0, padx=20, pady=(4, 10), sticky="ew")

        # Theme selector
        ctk.CTkLabel(sb, text="Theme", anchor="w").grid(row=23, column=0, padx=20, pady=(10, 0), sticky="w")
        ctk.CTkOptionMenu(
            sb, values=["Dark", "Light", "System"],
            command=self._on_theme_change,
        ).grid(row=24, column=0, padx=20, pady=(4, 10), sticky="ew")

        # Configs directory
        ctk.CTkLabel(sb, text="Configs Folder", anchor="w").grid(
            row=25, column=0, padx=20, pady=(6, 0), sticky="w")
        self._configs_dir_label = ctk.CTkLabel(
            sb, text=str(self.settings.configs_dir), anchor="w",
            font=ctk.CTkFont(size=10), text_color="gray", wraplength=220,
        )
        self._configs_dir_label.grid(row=26, column=0, padx=20, pady=(2, 2), sticky="w")
        ctk.CTkButton(
            sb, text="Change…", width=80, command=self._change_configs_dir,
        ).grid(row=27, column=0, padx=20, pady=(2, 16), sticky="w")

    def _build_main_area(self) -> None:
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, padx=16, pady=16, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)  # Log expands

        # --- Status & Location card ---
        self._build_status_card(main)

        # --- Config Editor (tabview for each protocol) ---
        self._build_config_editor(main)

        # --- Activity Log ---
        self._build_log_area(main)

    def _build_status_card(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(parent)
        card.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="Status & Location",
                      font=ctk.CTkFont(size=15, weight="bold")).grid(
            row=0, column=0, columnspan=3, padx=14, pady=(10, 6), sticky="w")

        self._status_label = ctk.CTkLabel(
            card, text="● Disconnected", font=ctk.CTkFont(size=13), text_color="#e74c3c")
        self._status_label.grid(row=1, column=0, padx=14, pady=3, sticky="w")

        for i, (text, attr) in enumerate([
            ("IP:", "_ip_val"), ("Location:", "_loc_val"),
            ("ISP:", "_org_val"), ("Timezone:", "_tz_val"),
        ], start=2):
            ctk.CTkLabel(card, text=text, anchor="w").grid(row=i, column=0, padx=(14, 4), pady=1, sticky="w")
            lbl = ctk.CTkLabel(card, text="N/A", anchor="w")
            lbl.grid(row=i, column=1, padx=(4, 14), pady=1, sticky="w")
            setattr(self, attr, lbl)

        self._refresh_ip_btn = ctk.CTkButton(card, text="Refresh IP", width=90, command=self._refresh_ip_info)
        self._refresh_ip_btn.grid(row=2, column=2, rowspan=2, padx=14, pady=3, sticky="e")

        self._uptime_label = ctk.CTkLabel(card, text="Uptime: --:--:--", anchor="e")
        self._uptime_label.grid(row=1, column=2, padx=14, pady=3, sticky="e")

        self._killswitch_info = ctk.CTkLabel(card, text="Kill-Switch: OFF", text_color="gray")
        self._killswitch_info.grid(row=4, column=2, padx=14, pady=3, sticky="e")

        ctk.CTkLabel(card, text="").grid(row=6, column=0, pady=(0, 6))

    def _build_config_editor(self, parent: ctk.CTkFrame) -> None:
        self._editor_tabview = ctk.CTkTabview(parent, height=220)
        self._editor_tabview.grid(row=1, column=0, sticky="ew", pady=(0, 8))

        # --- WireGuard tab ---
        wg = self._editor_tabview.add("WireGuard")
        wg.grid_columnconfigure(1, weight=1)

        wg_fields = [
            ("Profile Name:", "wg_name", "my-wireguard", 0),
            ("Private Key:", "wg_private_key", "Interface PrivateKey", 1),
            ("Address:", "wg_address", "10.0.0.2/24", 2),
            ("DNS:", "wg_dns", "1.1.1.1", 3),
            ("Peer Public Key:", "wg_public_key", "Peer PublicKey", 4),
            ("Preshared Key:", "wg_preshared_key", "(optional)", 5),
            ("Endpoint:", "wg_endpoint", "vpn.example.com:51820", 6),
            ("Allowed IPs:", "wg_allowed_ips", "0.0.0.0/0, ::/0", 7),
            ("Keepalive:", "wg_keepalive", "25", 8),
        ]
        self._wg_entries: dict[str, ctk.CTkEntry] = {}
        for label, key, placeholder, row in wg_fields:
            ctk.CTkLabel(wg, text=label, anchor="w").grid(row=row, column=0, padx=(8, 4), pady=2, sticky="w")
            entry = ctk.CTkEntry(wg, placeholder_text=placeholder)
            entry.grid(row=row, column=1, padx=(4, 8), pady=2, sticky="ew")
            self._wg_entries[key] = entry

        wg_btn_frame = ctk.CTkFrame(wg, fg_color="transparent")
        wg_btn_frame.grid(row=9, column=0, columnspan=2, pady=(6, 4))
        ctk.CTkButton(wg_btn_frame, text="Save Profile", command=self._save_wg_profile).pack(side="left", padx=4)

        # --- OpenVPN tab ---
        ovpn = self._editor_tabview.add("OpenVPN")
        ovpn.grid_columnconfigure(1, weight=1)

        ovpn_fields = [
            ("Profile Name:", "ovpn_name", "my-openvpn", 0),
            ("Remote Server:", "ovpn_remote", "vpn.example.com", 1),
            ("Port:", "ovpn_port", "1194", 2),
            ("Protocol:", "ovpn_proto", "udp", 3),
            ("Device:", "ovpn_dev", "tun", 4),
            ("Cipher:", "ovpn_cipher", "AES-256-GCM", 5),
            ("Auth:", "ovpn_auth", "SHA256", 6),
        ]
        self._ovpn_entries: dict[str, ctk.CTkEntry] = {}
        for label, key, placeholder, row in ovpn_fields:
            ctk.CTkLabel(ovpn, text=label, anchor="w").grid(row=row, column=0, padx=(8, 4), pady=2, sticky="w")
            entry = ctk.CTkEntry(ovpn, placeholder_text=placeholder)
            entry.grid(row=row, column=1, padx=(4, 8), pady=2, sticky="ew")
            self._ovpn_entries[key] = entry

        # CA / Cert / Key — textbox fields
        cert_row = len(ovpn_fields)
        ctk.CTkLabel(ovpn, text="CA Cert (paste PEM):", anchor="w").grid(
            row=cert_row, column=0, padx=(8, 4), pady=2, sticky="nw")
        self._ovpn_ca_text = ctk.CTkTextbox(ovpn, height=50)
        self._ovpn_ca_text.grid(row=cert_row, column=1, padx=(4, 8), pady=2, sticky="ew")

        ctk.CTkLabel(ovpn, text="Extra directives:", anchor="w").grid(
            row=cert_row + 1, column=0, padx=(8, 4), pady=2, sticky="nw")
        self._ovpn_extra_text = ctk.CTkTextbox(ovpn, height=40)
        self._ovpn_extra_text.grid(row=cert_row + 1, column=1, padx=(4, 8), pady=2, sticky="ew")

        ovpn_btn_frame = ctk.CTkFrame(ovpn, fg_color="transparent")
        ovpn_btn_frame.grid(row=cert_row + 2, column=0, columnspan=2, pady=(6, 4))
        ctk.CTkButton(ovpn_btn_frame, text="Save Profile", command=self._save_ovpn_profile).pack(side="left", padx=4)

        # --- SSH SOCKS5 tab ---
        ssh = self._editor_tabview.add("SSH SOCKS5")
        ssh.grid_columnconfigure(1, weight=1)

        ssh_fields = [
            ("Profile Name:", "ssh_name", "my-ssh-tunnel", 0),
            ("SSH Host:", "ssh_host", "server.example.com", 1),
            ("SSH Port:", "ssh_port", "22", 2),
            ("SSH User:", "ssh_user", "root", 3),
            ("SOCKS5 Port:", "ssh_socks_port", "1080", 4),
        ]
        self._ssh_entries: dict[str, ctk.CTkEntry] = {}
        for label, key, placeholder, row in ssh_fields:
            ctk.CTkLabel(ssh, text=label, anchor="w").grid(row=row, column=0, padx=(8, 4), pady=2, sticky="w")
            entry = ctk.CTkEntry(ssh, placeholder_text=placeholder)
            entry.grid(row=row, column=1, padx=(4, 8), pady=2, sticky="ew")
            self._ssh_entries[key] = entry

        # SSH key import
        ssh_key_frame = ctk.CTkFrame(ssh, fg_color="transparent")
        ssh_key_frame.grid(row=5, column=0, columnspan=2, padx=8, pady=2, sticky="ew")
        ssh_key_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(ssh_key_frame, text="SSH Key:", anchor="w").grid(row=0, column=0, padx=(0, 4), sticky="w")
        self._ssh_key_label = ctk.CTkLabel(ssh_key_frame, text="(none)", text_color="gray", anchor="w")
        self._ssh_key_label.grid(row=0, column=1, sticky="w")
        ctk.CTkButton(ssh_key_frame, text="Browse .pem", width=100, command=self._import_ssh_key).grid(
            row=0, column=2, padx=(8, 0))
        self._ssh_key_path: Optional[Path] = None

        ssh_btn_frame = ctk.CTkFrame(ssh, fg_color="transparent")
        ssh_btn_frame.grid(row=6, column=0, columnspan=2, pady=(6, 4))
        ctk.CTkButton(ssh_btn_frame, text="Save Profile", command=self._save_ssh_profile).pack(side="left", padx=4)

        # Sync the tab to the protocol selector
        self._on_protocol_change(self._protocol_var.get())

    def _build_log_area(self, parent: ctk.CTkFrame) -> None:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=2, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Activity Log", font=ctk.CTkFont(size=13, weight="bold"), anchor="w").grid(
            row=0, column=0, sticky="w")
        ctk.CTkButton(header, text="Clear", width=60, command=self._clear_log).grid(row=0, column=1, sticky="e")

        mono = "Consolas" if self.system.os_type == OSType.WINDOWS else "monospace"
        self._log_textbox = ctk.CTkTextbox(frame, state="disabled", font=ctk.CTkFont(family=mono, size=11))
        self._log_textbox.grid(row=1, column=0, sticky="nsew", pady=(4, 0))

    # -----------------------------------------------------------------------
    # Profile Save / Load / Delete
    # -----------------------------------------------------------------------

    def _load_profile_list(self) -> None:
        profiles = self.profile_mgr.list_profiles()
        values = ["(new profile)"] + profiles
        self._profile_menu.configure(values=values)

        last = self.settings.last_profile
        if last and last in profiles:
            self._profile_var.set(last)
            self._on_profile_select(last)

    def _on_profile_select(self, name: str) -> None:
        if name == "(new profile)":
            self._clear_editor_fields()
            return
        data = self.profile_mgr.load_profile(name)
        if not data:
            return
        self.settings.last_profile = name
        proto = data.get("protocol", "WireGuard")
        self._protocol_var.set(proto)
        self._on_protocol_change(proto)
        self._populate_editor(data)

    def _on_delete_profile(self) -> None:
        name = self._profile_var.get()
        if name == "(new profile)":
            return
        if messagebox.askyesno("Delete Profile", f"Delete '{name}'?"):
            self.profile_mgr.delete_profile(name)
            self._load_profile_list()
            self._profile_var.set("(new profile)")
            self._clear_editor_fields()

    def _populate_editor(self, data: dict[str, Any]) -> None:
        """Fill the editor fields from a loaded profile dict."""
        proto = data.get("protocol", "WireGuard")

        if proto == Protocol.WIREGUARD.value:
            field_map = {
                "wg_name": "name", "wg_private_key": "wg_private_key",
                "wg_address": "wg_address", "wg_dns": "wg_dns",
                "wg_public_key": "wg_public_key", "wg_preshared_key": "wg_preshared_key",
                "wg_endpoint": "wg_endpoint", "wg_allowed_ips": "wg_allowed_ips",
                "wg_keepalive": "wg_keepalive",
            }
            for ui_key, data_key in field_map.items():
                if ui_key in self._wg_entries:
                    self._wg_entries[ui_key].delete(0, "end")
                    self._wg_entries[ui_key].insert(0, data.get(data_key, ""))

        elif proto == Protocol.OPENVPN.value:
            field_map = {
                "ovpn_name": "name", "ovpn_remote": "ovpn_remote",
                "ovpn_port": "ovpn_port", "ovpn_proto": "ovpn_proto",
                "ovpn_dev": "ovpn_dev", "ovpn_cipher": "ovpn_cipher",
                "ovpn_auth": "ovpn_auth",
            }
            for ui_key, data_key in field_map.items():
                if ui_key in self._ovpn_entries:
                    self._ovpn_entries[ui_key].delete(0, "end")
                    self._ovpn_entries[ui_key].insert(0, data.get(data_key, ""))
            self._ovpn_ca_text.delete("1.0", "end")
            self._ovpn_ca_text.insert("1.0", data.get("ovpn_ca", ""))
            self._ovpn_extra_text.delete("1.0", "end")
            self._ovpn_extra_text.insert("1.0", data.get("ovpn_extra", ""))

        elif proto == Protocol.SSH_SOCKS5.value:
            field_map = {
                "ssh_name": "name", "ssh_host": "ssh_host",
                "ssh_port": "ssh_port", "ssh_user": "ssh_user",
                "ssh_socks_port": "socks_port",
            }
            for ui_key, data_key in field_map.items():
                if ui_key in self._ssh_entries:
                    self._ssh_entries[ui_key].delete(0, "end")
                    self._ssh_entries[ui_key].insert(0, str(data.get(data_key, "")))
            key_path = data.get("ssh_key_path", "")
            if key_path:
                self._ssh_key_path = Path(key_path)
                self._ssh_key_label.configure(text=Path(key_path).name)
            else:
                self._ssh_key_path = None
                self._ssh_key_label.configure(text="(none)")

    def _clear_editor_fields(self) -> None:
        for entry in self._wg_entries.values():
            entry.delete(0, "end")
        for entry in self._ovpn_entries.values():
            entry.delete(0, "end")
        self._ovpn_ca_text.delete("1.0", "end")
        self._ovpn_extra_text.delete("1.0", "end")
        for entry in self._ssh_entries.values():
            entry.delete(0, "end")
        self._ssh_key_path = None
        self._ssh_key_label.configure(text="(none)")

    def _save_wg_profile(self) -> None:
        name = self._wg_entries["wg_name"].get().strip()
        if not name:
            messagebox.showerror("Error", "Profile name is required.")
            return
        data: dict[str, Any] = {"protocol": Protocol.WIREGUARD.value, "name": name}
        for key, entry in self._wg_entries.items():
            if key != "wg_name":
                data[key] = entry.get().strip()
        # Generate the actual .conf file
        conf_path = self.profile_mgr.generate_wireguard_conf(name, data)
        data["config_file"] = str(conf_path)
        self.profile_mgr.save_profile(name, data)
        self.settings.last_profile = name
        self._load_profile_list()
        self._profile_var.set(name)
        logger.info("WireGuard profile '%s' saved.", name)

    def _save_ovpn_profile(self) -> None:
        name = self._ovpn_entries["ovpn_name"].get().strip()
        if not name:
            messagebox.showerror("Error", "Profile name is required.")
            return
        data: dict[str, Any] = {"protocol": Protocol.OPENVPN.value, "name": name}
        for key, entry in self._ovpn_entries.items():
            if key != "ovpn_name":
                data[key] = entry.get().strip()
        data["ovpn_ca"] = self._ovpn_ca_text.get("1.0", "end").strip()
        data["ovpn_extra"] = self._ovpn_extra_text.get("1.0", "end").strip()
        conf_path = self.profile_mgr.generate_openvpn_conf(name, data)
        data["config_file"] = str(conf_path)
        self.profile_mgr.save_profile(name, data)
        self.settings.last_profile = name
        self._load_profile_list()
        self._profile_var.set(name)
        logger.info("OpenVPN profile '%s' saved.", name)

    def _save_ssh_profile(self) -> None:
        name = self._ssh_entries["ssh_name"].get().strip()
        if not name:
            messagebox.showerror("Error", "Profile name is required.")
            return
        data: dict[str, Any] = {
            "protocol": Protocol.SSH_SOCKS5.value,
            "name": name,
            "ssh_host": self._ssh_entries["ssh_host"].get().strip(),
            "ssh_port": self._ssh_entries["ssh_port"].get().strip() or "22",
            "ssh_user": self._ssh_entries["ssh_user"].get().strip(),
            "socks_port": self._ssh_entries["ssh_socks_port"].get().strip() or "1080",
            "ssh_key_path": str(self._ssh_key_path) if self._ssh_key_path else "",
        }
        self.profile_mgr.save_profile(name, data)
        self.settings.last_profile = name
        self._load_profile_list()
        self._profile_var.set(name)
        logger.info("SSH profile '%s' saved.", name)

    # -----------------------------------------------------------------------
    # Event Handlers
    # -----------------------------------------------------------------------

    def _on_protocol_change(self, value: str) -> None:
        tab_map = {
            Protocol.WIREGUARD.value: "WireGuard",
            Protocol.OPENVPN.value: "OpenVPN",
            Protocol.SSH_SOCKS5.value: "SSH SOCKS5",
        }
        target_tab = tab_map.get(value, "WireGuard")
        try:
            self._editor_tabview.set(target_tab)
        except Exception:
            pass

    def _on_theme_change(self, value: str) -> None:
        ctk.set_appearance_mode(value.lower())
        self.settings.theme = value.lower()

    def _import_config(self) -> None:
        proto = Protocol(self._protocol_var.get())
        if proto == Protocol.WIREGUARD:
            filetypes = [("WireGuard Config", "*.conf"), ("All Files", "*.*")]
        elif proto == Protocol.OPENVPN:
            filetypes = [("OpenVPN Config", "*.ovpn"), ("All Files", "*.*")]
        else:
            filetypes = [("PEM Key", "*.pem"), ("All Files", "*.*")]

        path = filedialog.askopenfilename(title="Import Configuration", filetypes=filetypes)
        if not path:
            return

        src = Path(path)
        # Copy to configs dir
        dest = self.settings.configs_dir / src.name
        shutil.copy2(src, dest)
        logger.info("Imported config: %s -> %s", src, dest)

        # Auto-create a profile for it
        name = src.stem
        if proto == Protocol.WIREGUARD:
            data = {"protocol": proto.value, "name": name, "config_file": str(dest)}
        elif proto == Protocol.OPENVPN:
            data = {"protocol": proto.value, "name": name, "config_file": str(dest)}
        else:
            # SSH — import key
            self._ssh_key_path = dest
            self._ssh_key_label.configure(text=dest.name)
            return

        self.profile_mgr.save_profile(name, data)
        self.settings.last_profile = name
        self._load_profile_list()
        self._profile_var.set(name)

    def _import_ssh_key(self) -> None:
        path = filedialog.askopenfilename(
            title="Select SSH Key", filetypes=[("PEM Key", "*.pem"), ("All Files", "*.*")])
        if path:
            self._ssh_key_path = Path(path)
            self._ssh_key_label.configure(text=Path(path).name)
            logger.info("SSH key selected: %s", path)

    def _change_configs_dir(self) -> None:
        d = filedialog.askdirectory(title="Select Configs Folder", initialdir=str(self.settings.configs_dir))
        if d:
            self.settings.configs_dir = Path(d)
            self._configs_dir_label.configure(text=d)
            self._load_profile_list()
            logger.info("Configs directory changed to: %s", d)

    # -----------------------------------------------------------------------
    # Connect / Disconnect
    # -----------------------------------------------------------------------

    def _build_profile_from_current(self) -> ConnectionProfile:
        """Build a ConnectionProfile from the currently selected saved profile or editor fields."""
        name = self._profile_var.get()
        if name != "(new profile)":
            data = self.profile_mgr.load_profile(name)
            if data:
                return self.profile_mgr.profile_to_connection(data)

        # Fallback: build from editor fields directly
        proto = Protocol(self._protocol_var.get())
        profile = ConnectionProfile(protocol=proto)

        if proto == Protocol.WIREGUARD:
            pname = self._wg_entries["wg_name"].get().strip() or "temp_wg"
            data = {}
            for key, entry in self._wg_entries.items():
                data[key] = entry.get().strip()
            conf = self.profile_mgr.generate_wireguard_conf(pname, data)
            profile.config_path = conf
        elif proto == Protocol.OPENVPN:
            pname = self._ovpn_entries["ovpn_name"].get().strip() or "temp_ovpn"
            data = {}
            for key, entry in self._ovpn_entries.items():
                data[key] = entry.get().strip()
            data["ovpn_ca"] = self._ovpn_ca_text.get("1.0", "end").strip()
            data["ovpn_extra"] = self._ovpn_extra_text.get("1.0", "end").strip()
            conf = self.profile_mgr.generate_openvpn_conf(pname, data)
            profile.config_path = conf
        elif proto == Protocol.SSH_SOCKS5:
            profile.ssh_host = self._ssh_entries["ssh_host"].get().strip()
            profile.ssh_user = self._ssh_entries["ssh_user"].get().strip()
            try:
                profile.ssh_port = int(self._ssh_entries["ssh_port"].get().strip() or "22")
            except ValueError:
                profile.ssh_port = 22
            try:
                profile.socks_port = int(self._ssh_entries["ssh_socks_port"].get().strip() or "1080")
            except ValueError:
                profile.socks_port = 1080
            profile.ssh_key_path = self._ssh_key_path

        return profile

    def _on_connect(self) -> None:
        profile = self._build_profile_from_current()

        if profile.protocol in (Protocol.WIREGUARD, Protocol.OPENVPN):
            if not profile.config_path or not profile.config_path.exists():
                messagebox.showerror("Error", "No valid config. Fill in the fields and save, or import a file.")
                return
        elif profile.protocol == Protocol.SSH_SOCKS5:
            if not profile.ssh_host:
                messagebox.showerror("Error", "SSH host is required.")
                return

        self._connect_btn.configure(state="disabled")
        self._protocol_menu.configure(state="disabled")
        self._update_state(TunnelState.CONNECTING)
        self._connect_start_time = time.time()

        threading.Thread(target=self._connect_worker, args=(profile,), daemon=True).start()

    def _connect_worker(self, profile: ConnectionProfile) -> None:
        try:
            self.tunnel = TunnelEngine.create(self.system, profile)
            self.tunnel.connect()

            if self._kill_switch_var.get():
                self.security.enable()

            self.reconnect_mgr = ReconnectManager(self.tunnel, on_state_change=self._on_reconnect_state)
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
            self.after(0, lambda e=str(exc): messagebox.showerror("Connection Failed", e))

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
            self.after(500, self._refresh_ip_info)

    def _on_reconnect_state(self, state: TunnelState) -> None:
        self.after(0, lambda: self._update_state(state))
        if state == TunnelState.CONNECTED:
            self.after(500, self._refresh_ip_info)

    # -----------------------------------------------------------------------
    # UI Updates
    # -----------------------------------------------------------------------

    def _update_state(self, state: TunnelState) -> None:
        self._tunnel_state = state
        colors = {
            TunnelState.DISCONNECTED: "#e74c3c", TunnelState.CONNECTING: "#f39c12",
            TunnelState.CONNECTED: "#2ecc71", TunnelState.RECONNECTING: "#f39c12",
            TunnelState.DISCONNECTING: "#f39c12", TunnelState.ERROR: "#e74c3c",
        }
        self._status_label.configure(text=f"● {state.value}", text_color=colors.get(state, "gray"))
        ks_on = self._kill_switch_var.get() and state == TunnelState.CONNECTED
        self._killswitch_info.configure(
            text=f"Kill-Switch: {'ON' if ks_on else 'OFF'}",
            text_color="#2ecc71" if ks_on else "gray",
        )

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
        def _worker() -> None:
            info = fetch_ip_info()
            self.after(0, lambda: self._display_ip(info))
        threading.Thread(target=_worker, daemon=True).start()

    def _display_ip(self, info: IPInfo) -> None:
        self._ip_info = info
        self._ip_val.configure(text=info.ip)
        self._loc_val.configure(text=f"{info.city}, {info.region}, {info.country}")
        self._org_val.configure(text=info.org)
        self._tz_val.configure(text=info.timezone)

    def _poll_log_queue(self) -> None:
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
            messagebox.showwarning("Unsupported OS", "Only Windows 11 and Ubuntu 20.04/22.04 are supported.")
            return
        if not self.system.is_admin():
            logger.warning("Running WITHOUT elevated privileges.")
            if messagebox.askyesno(
                "Elevated Privileges Required",
                "Admin/root privileges are needed for VPN tunnels and firewall rules.\n\n"
                "Restart with elevated privileges?",
            ):
                if self.system.request_elevation():
                    self.destroy()
                    sys.exit(0)
                else:
                    messagebox.showwarning("Elevation Failed", "Some features may not work.")

    # -----------------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------------

    def _on_close(self) -> None:
        logger.info("Shutting down …")
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
