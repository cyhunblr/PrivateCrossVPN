#!/usr/bin/env python3
"""
PrivateCrossVPN — A production-grade, cross-platform VPN management application.

Supports WireGuard, OpenVPN, and SSH SOCKS5 tunneling on Windows 11 and Ubuntu 20.04.
Built with CustomTkinter for a modern, intuitive UI.

Author : PrivateCrossVPN Team
License: MIT
Python : 3.10+
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import logging
import os
import shlex
import platform
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# Third-party imports (CustomTkinter)
# ---------------------------------------------------------------------------
try:
    import customtkinter as ctk  # type: ignore[import-untyped]
    from tkinter import TclError, filedialog, messagebox
except ImportError:
    sys.exit(
        "[FATAL] customtkinter is required.\n"
        "Install it with:  pip install customtkinter\n"
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_NAME = "PrivateCrossVPN"
APP_VERSION = os.environ.get("PVCVPN_VERSION", "1.10.0")
LOG_DATE_FMT = "%Y-%m-%d %H:%M:%S"
IP_API_URL = "https://ipinfo.io/json"
IP_API_TIMEOUT = 8  # seconds
RECONNECT_DELAY_BASE = 3  # seconds (exponential back-off base)
RECONNECT_MAX_RETRIES = 5
HEARTBEAT_INTERVAL = 15  # seconds between connection health checks


def _resolve_app_dir() -> Path:
    """Resolve the app data directory, preferring the invoking user home under sudo."""
    user_home = Path.home()

    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
        sudo_user = os.environ.get("SUDO_USER")
        pkexec_uid = os.environ.get("PKEXEC_UID")

        try:
            import pwd  # type: ignore[import-not-found]

            if sudo_user:
                user_home = Path(pwd.getpwnam(sudo_user).pw_dir)
            elif pkexec_uid and pkexec_uid.isdigit():
                user_home = Path(pwd.getpwuid(int(pkexec_uid)).pw_dir)
        except Exception:
            pass

    return user_home / ".privatecrossvpn"


def _resolve_app_file_owner() -> tuple[Optional[int], Optional[int]]:
    """Resolve target uid/gid for files created during elevated runs."""
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None, None

    sudo_user = os.environ.get("SUDO_USER")
    pkexec_uid = os.environ.get("PKEXEC_UID")
    try:
        import pwd  # type: ignore[import-not-found]

        if sudo_user:
            pw = pwd.getpwnam(sudo_user)
            return pw.pw_uid, pw.pw_gid
        if pkexec_uid and pkexec_uid.isdigit():
            pw = pwd.getpwuid(int(pkexec_uid))
            return pw.pw_uid, pw.pw_gid
    except Exception:
        pass

    return None, None


def _set_app_file_owner(path: Path) -> None:
    """Best-effort chown to invoking user for files/directories created as root."""
    uid, gid = _resolve_app_file_owner()
    if uid is None or gid is None:
        return
    try:
        os.chown(path, uid, gid)
    except Exception:
        pass


APP_DIR = _resolve_app_dir()
APP_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_CONFIGS_DIR = APP_DIR / "configs"
DEFAULT_CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
_set_app_file_owner(APP_DIR)
_set_app_file_owner(DEFAULT_CONFIGS_DIR)
SETTINGS_FILE = APP_DIR / "settings.json"


# Icon path resolution: works both from source and when packaged (PyInstaller/Nuitka)
def _resolve_asset_path(relative: str) -> Path:
    """Resolve path to a bundled asset, supporting PyInstaller's _MEIPASS."""
    if hasattr(sys, "_MEIPASS"):
        base = Path(sys._MEIPASS)  # type: ignore[attr-defined]
    else:
        base = Path(__file__).resolve().parent
    return base / relative


ICON_PNG = _resolve_asset_path("img/logo.png")
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
    config_path: Optional[Path] = None  # .conf / .ovpn
    ssh_host: str = ""
    ssh_port: int = 22
    ssh_user: str = ""
    ssh_key_path: Optional[Path] = None  # .pem
    socks_port: int = 1080
    extra_args: list[str] = field(default_factory=list)


def build_ssh_login_command(
    key_path: Path, server_ip: str, ssh_user: str = "root", ssh_port: str = "22"
) -> str:
    """Build a shell-safe SSH login command for the Setup wizard."""
    return (
        f"ssh -i {shlex.quote(str(key_path))} "
        f"-p {shlex.quote(str(ssh_port))} "
        f"{shlex.quote(f'{ssh_user}@{server_ip}')}"
    )


WG_IFACE_PATTERN = re.compile(r"^[A-Za-z0-9_=+.]{1,15}$")


def sanitize_wg_interface_name(name: str) -> str:
    """Return a wg-quick compatible interface name (Linux)."""
    sanitized = re.sub(r"[^A-Za-z0-9_=+.]+", "_", name).strip("._")
    if not sanitized:
        sanitized = "wg0"
    return sanitized[:15]


def strip_wireguard_dns_directives(conf_text: str) -> str:
    """Remove DNS directives from a WireGuard config text."""
    filtered = []
    for line in conf_text.splitlines():
        if re.match(r"^\s*DNS\s*=", line):
            continue
        filtered.append(line)
    return "\n".join(filtered) + "\n"


def build_local_dependency_install_commands(
    os_type: OSType,
    missing: list[str],
    *,
    elevated: bool,
    has_pkexec: bool,
    has_winget: bool,
) -> list[list[str]]:
    """Build the command list needed to install missing local prerequisites."""
    if not missing:
        return []

    if os_type == OSType.LINUX:
        packages: list[str] = []
        package_map = {
            "WireGuard": "wireguard",
            "OpenVPN": "openvpn",
            "OpenSSH Client": "openssh-client",
        }
        for item in missing:
            package = package_map.get(item)
            if package and package not in packages:
                packages.append(package)

        if not packages:
            return []

        if elevated:
            return [
                ["apt-get", "update"],
                ["apt-get", "install", "-y", *packages],
            ]

        if has_pkexec:
            package_list = " ".join(packages)
            return [
                [
                    "pkexec",
                    "bash",
                    "-lc",
                    f"apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y {package_list}",
                ]
            ]

        return []

    if os_type == OSType.WINDOWS:
        commands: list[list[str]] = []
        if "OpenSSH Client" in missing:
            commands.append(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0",
                ]
            )

        if has_winget:
            if "WireGuard" in missing:
                commands.append(
                    [
                        "winget",
                        "install",
                        "-e",
                        "--id",
                        "WireGuard.WireGuard",
                        "--accept-package-agreements",
                        "--accept-source-agreements",
                    ]
                )
            if "OpenVPN" in missing:
                commands.append(
                    [
                        "winget",
                        "install",
                        "-e",
                        "--id",
                        "OpenVPNTechnologies.OpenVPN",
                        "--accept-package-agreements",
                        "--accept-source-agreements",
                    ]
                )

        return commands

    return []


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
            _set_app_file_owner(SETTINGS_FILE)
        except Exception as exc:
            logger.error("Failed to save settings: %s", exc)

    @property
    def configs_dir(self) -> Path:
        p = Path(self._data["configs_dir"])
        p.mkdir(parents=True, exist_ok=True)
        _set_app_file_owner(p)
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
        safe_name = re.sub(r"[^\w\-. ]", "_", name)
        path = self._dir / f"{safe_name}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        _set_app_file_owner(path)
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

        # Backward compatibility for old profiles that include config_file.
        config_file = data.get("config_file")
        if proto == Protocol.WIREGUARD:
            # Always derive runtime config from JSON profile fields.
            profile.config_path = self.generate_wireguard_conf(
                data.get("name", "wireguard"), data
            )
        elif proto == Protocol.OPENVPN:
            # Always derive runtime config from JSON profile fields.
            profile.config_path = self.generate_openvpn_conf(
                data.get("name", "openvpn"), data
            )
        elif config_file:
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
        iface_name = sanitize_wg_interface_name(name)
        conf_path = self._dir / f"{iface_name}.conf"
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
        _set_app_file_owner(conf_path)
        try:
            conf_path.chmod(0o600)
        except Exception:
            pass
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
        _set_app_file_owner(conf_path)
        logger.info("OpenVPN config generated: %s", conf_path)
        return conf_path

    def parse_wireguard_conf(self, conf_path: Path) -> dict[str, Any]:
        """Parse a WireGuard .conf file and return a dict with field values."""
        data: dict[str, Any] = {}
        if not conf_path.exists():
            return data

        try:
            content = conf_path.read_text(encoding="utf-8")
            current_section = None

            for line in content.splitlines():
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Section headers
                if line.startswith("["):
                    current_section = line.lower()
                    continue

                # Key=value parsing
                if "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip().lower()
                    value = value.strip()

                    if current_section == "[interface]":
                        if key == "privatekey":
                            data["wg_private_key"] = value
                        elif key == "address":
                            data["wg_address"] = value
                        elif key == "dns":
                            data["wg_dns"] = value
                        elif key == "listenport":
                            data["wg_listen_port"] = value

                    elif current_section == "[peer]":
                        if key == "publickey":
                            data["wg_public_key"] = value
                        elif key == "presharedkey":
                            data["wg_preshared_key"] = value
                        elif key == "endpoint":
                            data["wg_endpoint"] = value
                        elif key == "allowedips":
                            data["wg_allowed_ips"] = value
                        elif key == "persistentkeepalive":
                            data["wg_keepalive"] = value

        except Exception as exc:
            logger.error("Failed to parse WireGuard config %s: %s", conf_path, exc)

        return data

    def parse_openvpn_conf(self, conf_path: Path) -> dict[str, Any]:
        """Parse an OpenVPN .ovpn file and return a dict with field values."""
        data: dict[str, Any] = {}
        if not conf_path.exists():
            return data

        try:
            content = conf_path.read_text(encoding="utf-8")
            lines = content.splitlines()
            extra_lines: list[str] = []
            current_inline_block = None
            inline_content: list[str] = []

            i = 0
            while i < len(lines):
                line = lines[i].strip()
                i += 1

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Inline certificate/key blocks
                if line.startswith("<") and line.endswith(">"):
                    tag = line[1:-1]
                    if tag in ("ca", "cert", "key", "tls-auth"):
                        current_inline_block = tag
                        inline_content = []
                        continue

                if current_inline_block and line.startswith("</"):
                    tag = line[2:-1]
                    if tag == current_inline_block:
                        cert_content = "\n".join(inline_content).strip()
                        if current_inline_block == "ca":
                            data["ovpn_ca"] = cert_content
                        elif current_inline_block == "cert":
                            data["ovpn_cert"] = cert_content
                        elif current_inline_block == "key":
                            data["ovpn_key"] = cert_content
                        elif current_inline_block == "tls-auth":
                            data["ovpn_tls_auth"] = cert_content
                        current_inline_block = None
                    continue

                # Collect lines within inline blocks
                if current_inline_block:
                    inline_content.append(line)
                    continue

                # Parse directives
                if " " in line:
                    parts = line.split(None, 1)
                    key = parts[0]
                    value = parts[1] if len(parts) > 1 else ""

                    if key == "dev":
                        data["ovpn_dev"] = value
                    elif key == "proto":
                        data["ovpn_proto"] = value
                    elif key == "remote":
                        # remote host port [proto]
                        remote_parts = value.split()
                        if len(remote_parts) >= 1:
                            data["ovpn_remote"] = remote_parts[0]
                        if len(remote_parts) >= 2:
                            data["ovpn_port"] = remote_parts[1]
                    elif key == "cipher":
                        data["ovpn_cipher"] = value
                    elif key == "auth":
                        data["ovpn_auth"] = value
                    elif key not in (
                        "client",
                        "resolv-retry",
                        "nobind",
                        "persist-key",
                        "persist-tun",
                        "verb",
                    ):
                        # Collect unrecognized directives as extra
                        extra_lines.append(line)
                else:
                    # Single keyword lines like "client", "nobind"
                    if line not in (
                        "client",
                        "resolv-retry",
                        "nobind",
                        "persist-key",
                        "persist-tun",
                        "verb",
                        "3",
                    ):
                        extra_lines.append(line)

            if extra_lines:
                data["ovpn_extra"] = "\n".join(extra_lines)

        except Exception as exc:
            logger.error("Failed to parse OpenVPN config %s: %s", conf_path, exc)

        return data


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
_queue_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt=LOG_DATE_FMT)
)
logger.addHandler(_queue_handler)

_stream_handler = logging.StreamHandler(sys.stdout)
_stream_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt=LOG_DATE_FMT)
)
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
                    None,
                    "runas",
                    sys.executable,
                    params,
                    None,
                    1,
                )
                return ret > 32
            except Exception as exc:
                logger.error("UAC elevation failed: %s", exc)
                return False

        if self.os_type == OSType.LINUX:
            # In frozen binaries, sys.executable already points to the app binary.
            # Passing sys.argv[0] again creates a duplicate path argument.
            if getattr(sys, "frozen", False):
                relaunch_target = [sys.executable, *sys.argv[1:]]
            else:
                relaunch_target = [sys.executable, *sys.argv]

            # Avoid passing PyInstaller onefile runtime internals to the elevated process.
            # Otherwise, the child may reuse the parent _MEI temp directory and fail after
            # the parent exits and cleans up that directory.
            clean_env = {
                key: value
                for key, value in os.environ.items()
                if not (
                    key.startswith("_PYI")
                    or key.startswith("PYINSTALLER_")
                    or key == "_MEIPASS2"
                )
            }

            candidates: list[list[str]] = []
            has_tty = False
            try:
                has_tty = sys.stdin.isatty()
            except Exception:
                has_tty = False

            if shutil.which("pkexec"):
                pkexec_cmd = ["pkexec", "env"]
                for key in (
                    "DISPLAY",
                    "XAUTHORITY",
                    "WAYLAND_DISPLAY",
                    "XDG_RUNTIME_DIR",
                ):
                    value = os.environ.get(key)
                    if value:
                        pkexec_cmd.append(f"{key}={value}")
                pkexec_cmd.extend(relaunch_target)
                candidates.append(pkexec_cmd)

            if has_tty and shutil.which("sudo"):
                candidates.append(["sudo", *relaunch_target])

            for args in candidates:
                try:
                    logger.info("Re-launching with: %s", " ".join(args))
                    os.execvpe(args[0], args, clean_env)
                    # execvpe replaces the process — this line is never reached on success.
                except Exception as exc:
                    logger.error("Elevation with %s failed: %s", args[0], exc)
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
        args = self._elevate_args_if_needed(args)
        logger.info("CMD> %s", " ".join(args))
        try:
            extra: dict[str, Any] = {}
            if self.os_type == OSType.WINDOWS:
                extra["creationflags"] = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(
                args,
                shell=False,
                capture_output=capture,
                text=True,
                timeout=timeout,
                check=check,
                **extra,
            )
            if result.stdout:
                for line in result.stdout.strip().splitlines():
                    logger.debug("  stdout: %s", line)
            if result.stderr:
                for line in result.stderr.strip().splitlines():
                    logger.debug("  stderr: %s", line)
            return result
        except subprocess.CalledProcessError as exc:
            stdout = (exc.stdout or "").strip()
            stderr = (exc.stderr or "").strip()
            if stdout:
                for line in stdout.splitlines():
                    logger.debug("  stdout: %s", line)
            if stderr:
                for line in stderr.splitlines():
                    logger.debug("  stderr: %s", line)

            detail = (
                stderr or stdout or f"Command failed with exit code {exc.returncode}."
            )
            logger.error("Command failed: %s", detail)
            raise RuntimeError(detail) from exc
        except subprocess.TimeoutExpired:
            logger.error("Command timed out after %ds: %s", timeout, " ".join(args))
            raise
        except FileNotFoundError:
            logger.error("Command not found: %s", args[0])
            raise

    def popen_cmd(self, args: list[str], **kwargs: Any) -> subprocess.Popen[str]:
        args = self._elevate_args_if_needed(args)
        logger.info("POPEN> %s", " ".join(args))
        if self.os_type == OSType.WINDOWS:
            kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
        return subprocess.Popen(
            args,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **kwargs,
        )

    def _elevate_args_if_needed(self, args: list[str]) -> list[str]:
        """Auto-elevate root-required Linux commands at runtime when app runs as normal user."""
        if self.os_type != OSType.LINUX or self.is_admin() or not args:
            return args

        first = Path(args[0]).name
        if first in {"pkexec", "sudo"}:
            return args

        privileged_bins = {
            "wg-quick",
            "wg",
            "openvpn",
            "iptables",
            "ip6tables",
            "systemctl",
            "ufw",
            "apt",
            "apt-get",
            "chown",
        }
        if first not in privileged_bins:
            return args

        if shutil.which("pkexec"):
            elevated = ["pkexec", "env"]
            for key in ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"):
                value = os.environ.get(key)
                if value:
                    elevated.append(f"{key}={value}")
            elevated.extend(args)
            return elevated

        if shutil.which("sudo"):
            return ["sudo", *args]

        return args


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

    def enable(
        self,
        vpn_interface: str = "",
        vpn_server_ip: str = "",
        vpn_port: int = 0,
        protocol_name: str = "udp",
    ) -> None:
        if self._active:
            logger.info("Kill-switch already active.")
            return
        logger.info("Enabling kill-switch …")
        try:
            if self.system.os_type == OSType.WINDOWS:
                self._enable_windows(vpn_server_ip, vpn_port, protocol_name)
            elif self.system.os_type == OSType.LINUX:
                self._enable_linux(
                    vpn_interface, vpn_server_ip, vpn_port, protocol_name
                )
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

    def _enable_windows(
        self, vpn_server_ip: str, vpn_port: int, protocol_name: str
    ) -> None:
        self.system.run_cmd(
            [
                "netsh",
                "advfirewall",
                "set",
                "allprofiles",
                "firewallpolicy",
                "blockinbound,blockoutbound",
            ]
        )
        if vpn_server_ip:
            cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={self.RULE_PREFIX}_AllowVPN",
                "dir=out",
                "action=allow",
                f"remoteip={vpn_server_ip}",
                f"protocol={protocol_name}",
            ]
            if vpn_port:
                cmd.append(f"remoteport={vpn_port}")
            cmd.append("enable=yes")
            self.system.run_cmd(cmd)
        self.system.run_cmd(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={self.RULE_PREFIX}_AllowLoopback",
                "dir=out",
                "action=allow",
                "remoteip=127.0.0.0/8",
                "enable=yes",
            ]
        )
        for subnet in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            self.system.run_cmd(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={self.RULE_PREFIX}_AllowLAN_{subnet.replace('/', '_')}",
                    "dir=out",
                    "action=allow",
                    f"remoteip={subnet}",
                    "enable=yes",
                ]
            )

    def _disable_windows(self) -> None:
        for suffix in (
            "_AllowVPN",
            "_AllowLoopback",
            "_AllowLAN_10.0.0.0_8",
            "_AllowLAN_172.16.0.0_12",
            "_AllowLAN_192.168.0.0_16",
        ):
            try:
                self.system.run_cmd(
                    [
                        "netsh",
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        f"name={self.RULE_PREFIX}{suffix}",
                    ]
                )
            except Exception:
                pass
        self.system.run_cmd(
            [
                "netsh",
                "advfirewall",
                "set",
                "allprofiles",
                "firewallpolicy",
                "blockinbound,allowoutbound",
            ]
        )

    # --- Linux (iptables) ---------------------------------------------------

    def _enable_linux(
        self, vpn_interface: str, vpn_server_ip: str, vpn_port: int, protocol_name: str
    ) -> None:
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
            self.system.run_cmd(
                [ipt, "-A", self.RULE_PREFIX, "-d", subnet, "-j", "ACCEPT"]
            )
        self.system.run_cmd(
            [
                ipt,
                "-A",
                self.RULE_PREFIX,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
        )
        if vpn_server_ip:
            cmd = [ipt, "-A", self.RULE_PREFIX, "-d", vpn_server_ip]
            if protocol_name:
                cmd += ["-p", protocol_name]
            if vpn_port:
                cmd += ["--dport", str(vpn_port)]
            cmd += ["-j", "ACCEPT"]
            self.system.run_cmd(cmd)
        if vpn_interface:
            self.system.run_cmd(
                [ipt, "-A", self.RULE_PREFIX, "-o", vpn_interface, "-j", "ACCEPT"]
            )
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
                raise RuntimeError(
                    "wg-quick not found. Install: sudo apt install wireguard"
                )

            # wg-quick derives interface from filename stem. Ensure compatibility.
            runtime_conf = conf
            if not WG_IFACE_PATTERN.match(conf.stem):
                fixed_stem = sanitize_wg_interface_name(conf.stem)
                runtime_conf = conf.with_name(f"{fixed_stem}.conf")
                shutil.copy2(conf, runtime_conf)
                try:
                    runtime_conf.chmod(0o600)
                except Exception:
                    pass
                self.profile.config_path = runtime_conf
                logger.warning(
                    "WireGuard config filename '%s' is incompatible with wg-quick; using '%s'.",
                    conf.name,
                    runtime_conf.name,
                )

            if not self.system.check_binary("resolvconf"):
                conf_text = runtime_conf.read_text(encoding="utf-8")
                if re.search(r"^\s*DNS\s*=", conf_text, flags=re.MULTILINE):
                    runtime_conf.write_text(
                        strip_wireguard_dns_directives(conf_text), encoding="utf-8"
                    )
                    try:
                        runtime_conf.chmod(0o600)
                    except Exception:
                        pass
                    self.profile.config_path = runtime_conf
                    logger.warning(
                        "resolvconf not found on local machine. Proceeding without DNS directive. "
                        "Install 'openresolv' (or resolvconf package) to auto-apply VPN DNS."
                    )

            self.system.run_cmd(
                [wg_quick, "up", str(runtime_conf)], timeout=30, check=True
            )
        elif self.system.os_type == OSType.WINDOWS:
            wg_exe = self.system.check_binary("wireguard.exe")
            if not wg_exe:
                wg_exe = r"C:\Program Files\WireGuard\wireguard.exe"
                if not Path(wg_exe).exists():
                    raise RuntimeError("wireguard.exe not found.")
            self.system.run_cmd(
                [wg_exe, "/installtunnelservice", str(conf)], timeout=30, check=True
            )
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
                    self.system.run_cmd(
                        [
                            self.system.check_binary("wg-quick") or "wg-quick",
                            "down",
                            str(conf),
                        ],
                        timeout=30,
                    )
                except Exception as exc:
                    logger.error("wg-quick down failed: %s", exc)
            elif self.system.os_type == OSType.WINDOWS:
                try:
                    self.system.run_cmd(
                        [
                            self.system.check_binary("wireguard.exe")
                            or "wireguard.exe",
                            "/uninstalltunnelservice",
                            conf.stem,
                        ],
                        timeout=30,
                    )
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
                return (
                    self.system.run_cmd(
                        [self.system.check_binary("wg") or "wg", "show", iface],
                        timeout=10,
                    ).returncode
                    == 0
                )
            except Exception:
                return False
        elif self.system.os_type == OSType.WINDOWS:
            try:
                r = self.system.run_cmd(
                    ["sc", "query", f"WireGuardTunnel${iface}"], timeout=10
                )
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
        args = [
            openvpn,
            "--config",
            str(conf),
            "--management",
            "127.0.0.1",
            "7505",
            "--verb",
            "4",
        ]
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
            for c in (
                r"C:\Program Files\OpenVPN\bin\openvpn.exe",
                r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
            ):
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
        logger.info(
            "Starting SSH SOCKS5: %s@%s:%d -> :%d",
            p.ssh_user or "user",
            p.ssh_host,
            p.ssh_port,
            p.socks_port,
        )
        ssh_bin = self.system.check_binary("ssh")
        if not ssh_bin:
            raise RuntimeError("ssh binary not found.")
        args = [
            ssh_bin,
            "-D",
            str(p.socks_port),
            "-N",
            "-C",
            "-q",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "ExitOnForwardFailure=yes",
            "-p",
            str(p.ssh_port),
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
        logger.info(
            "SSH SOCKS5 CONNECTED (PID %d). Proxy: 127.0.0.1:%d",
            self._process.pid,
            p.socks_port,
        )

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
    def __init__(
        self,
        tunnel: BaseTunnel,
        on_state_change: Optional[Callable[[TunnelState], None]] = None,
    ) -> None:
        self.tunnel = tunnel
        self.on_state_change = on_state_change
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._retries = 0

    def start(self) -> None:
        self._stop_event.clear()
        self._retries = 0
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="ReconnectManager"
        )
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
            logger.info(
                "Reconnect %d/%d in %ds …", self._retries, RECONNECT_MAX_RETRIES, delay
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
            logger.error("Max reconnect retries reached.")
            self.tunnel.state = TunnelState.ERROR
            if self.on_state_change:
                self.on_state_change(TunnelState.ERROR)


# ═══════════════════════════════════════════════════════════════════════════
#  IP Info
# ═══════════════════════════════════════════════════════════════════════════


def fetch_ip_info() -> IPInfo:
    try:
        req = Request(
            IP_API_URL, headers={"Accept": "application/json", "User-Agent": APP_NAME}
        )
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
    WIDTH = 1060
    HEIGHT = 740

    def __init__(self) -> None:
        super().__init__()

        # Core modules
        self.system = SystemHandler()
        if self.system.os_type == OSType.LINUX and not self.system.is_admin():
            self._repair_app_dir_permissions_if_needed()
        self.settings = AppSettings()
        self.profile_mgr = ProfileManager(self.settings)
        self.security = SecurityGuard(self.system)
        self.tunnel: Optional[BaseTunnel] = None
        self.reconnect_mgr: Optional[ReconnectManager] = None

        # State
        self._tunnel_state = TunnelState.DISCONNECTED
        self._ip_info = IPInfo()
        self._kill_switch_var = ctk.BooleanVar(value=False)
        self._install_deps_status_text = ctk.StringVar(value="")
        self._prereq_notice_text = ctk.StringVar(value="")
        self._prereq_spinner_index = 0
        self._prereq_spinner_job: Optional[str] = None

        # Wizard state
        self._wizard_ssh_key_path: Optional[Path] = None
        self._wizard_ssh_pubkey: str = ""
        self._wiz_step3_test_ok = False
        self._wiz_step3_setup_ok = False
        self._connect_start_time = 0.0

        # Window
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.minsize(900, 640)
        ctk.set_appearance_mode(self.settings.theme)
        ctk.set_default_color_theme("blue")
        self._set_app_icon()

        self._build_ui()
        self._install_text_edit_shortcuts()
        self._check_privileges()
        self._poll_log_queue()
        self._refresh_ip_info()
        self._refresh_prereq_notice()
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
            row=0, column=0, padx=20, pady=(20, 2)
        )
        ctk.CTkLabel(sb, text=f"v{APP_VERSION}", font=ctk.CTkFont(size=11)).grid(
            row=1, column=0, padx=20, pady=(0, 16)
        )

        # --- Saved Profiles ---
        ctk.CTkLabel(sb, text="Saved Profiles", anchor="w").grid(
            row=2, column=0, padx=20, pady=(8, 0), sticky="w"
        )

        profile_frame = ctk.CTkFrame(sb, fg_color="transparent")
        profile_frame.grid(row=3, column=0, padx=20, pady=(4, 4), sticky="ew")
        profile_frame.grid_columnconfigure(0, weight=1)

        self._profile_var = ctk.StringVar(value="(new profile)")
        self._profile_menu = ctk.CTkOptionMenu(
            profile_frame,
            variable=self._profile_var,
            values=["(new profile)"],
            command=self._on_profile_select,
        )
        self._profile_menu.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        self._delete_profile_btn = ctk.CTkButton(
            profile_frame,
            text="X",
            width=32,
            fg_color="#c0392b",
            hover_color="#a93226",
            command=self._on_delete_profile,
        )
        self._delete_profile_btn.grid(row=0, column=1)

        # --- Protocol selector ---
        ctk.CTkLabel(sb, text="Protocol", anchor="w").grid(
            row=4, column=0, padx=20, pady=(12, 0), sticky="w"
        )
        self._protocol_var = ctk.StringVar(value=Protocol.WIREGUARD.value)
        self._protocol_menu = ctk.CTkOptionMenu(
            sb,
            values=[p.value for p in Protocol],
            variable=self._protocol_var,
            command=self._on_protocol_change,
        )
        self._protocol_menu.grid(row=5, column=0, padx=20, pady=(4, 4), sticky="ew")

        # --- Import from file (alternative) ---
        self._import_btn = ctk.CTkButton(
            sb, text="Import from File…", command=self._import_config
        )
        self._import_btn.grid(row=6, column=0, padx=20, pady=(4, 4), sticky="ew")

        # --- Export to file ---
        self._export_btn = ctk.CTkButton(
            sb, text="Export Profile…", command=self._export_profile
        )
        self._export_btn.grid(row=7, column=0, padx=20, pady=(4, 4), sticky="ew")

        # Kill-switch
        self._kill_switch_check = ctk.CTkCheckBox(
            sb, text="Kill-Switch", variable=self._kill_switch_var
        )
        self._kill_switch_check.grid(row=8, column=0, padx=20, pady=(12, 4), sticky="w")

        # Connect / Disconnect
        self._connect_btn = ctk.CTkButton(
            sb,
            text="Connect",
            fg_color="green",
            hover_color="#2d8a2d",
            command=self._on_connect,
        )
        self._connect_btn.grid(row=21, column=0, padx=20, pady=(10, 4), sticky="ew")

        self._disconnect_btn = ctk.CTkButton(
            sb,
            text="Disconnect",
            fg_color="#c0392b",
            hover_color="#a93226",
            command=self._on_disconnect,
            state="disabled",
        )
        self._disconnect_btn.grid(row=22, column=0, padx=20, pady=(4, 10), sticky="ew")

        # Theme selector
        ctk.CTkLabel(sb, text="Theme", anchor="w").grid(
            row=23, column=0, padx=20, pady=(10, 0), sticky="w"
        )
        ctk.CTkOptionMenu(
            sb,
            values=["Dark", "Light", "System"],
            command=self._on_theme_change,
        ).grid(row=24, column=0, padx=20, pady=(4, 10), sticky="ew")

        # Configs directory
        ctk.CTkLabel(sb, text="Configs Folder", anchor="w").grid(
            row=25, column=0, padx=20, pady=(6, 0), sticky="w"
        )
        self._configs_dir_label = ctk.CTkLabel(
            sb,
            text=str(self.settings.configs_dir),
            anchor="w",
            font=ctk.CTkFont(size=10),
            text_color="gray",
            wraplength=220,
        )
        self._configs_dir_label.grid(row=26, column=0, padx=20, pady=(2, 2), sticky="w")
        ctk.CTkButton(
            sb,
            text="Change…",
            width=80,
            command=self._change_configs_dir,
        ).grid(row=27, column=0, padx=20, pady=(2, 16), sticky="w")

    def _build_main_area(self) -> None:
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, padx=16, pady=16, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(3, weight=1)  # Log expands

        # --- Startup prerequisite notice ---
        self._build_prereq_notice(main)

        # --- Status & Location card ---
        self._build_status_card(main)

        # --- Config Editor (tabview for each protocol) ---
        self._build_config_editor(main)

        # --- Activity Log ---
        self._build_log_area(main)

    def _build_prereq_notice(self, parent: ctk.CTkFrame) -> None:
        self._prereq_notice_card = ctk.CTkFrame(parent)
        self._prereq_notice_card.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self._prereq_notice_card.grid_columnconfigure(0, weight=1)

        self._prereq_notice_label = ctk.CTkLabel(
            self._prereq_notice_card,
            textvariable=self._prereq_notice_text,
            anchor="center",
            justify="center",
            text_color="#f39c12",
            font=ctk.CTkFont(size=13, weight="bold"),
            wraplength=700,
        )
        self._prereq_notice_label.grid(
            row=0, column=0, padx=12, pady=(10, 6), sticky="ew"
        )

        self._prereq_notice_btn = ctk.CTkButton(
            self._prereq_notice_card,
            text="Install Required Components",
            width=240,
            fg_color="#d35400",
            hover_color="#ba4a00",
            command=self._install_missing_local_dependencies,
        )
        self._prereq_notice_btn.grid(row=1, column=0, padx=12, pady=(0, 10))
        # Reuse the existing install flow handlers with the notice button as the single trigger.
        self._install_deps_btn = self._prereq_notice_btn

        self._prereq_notice_card.grid_remove()

    def _build_status_card(self, parent: ctk.CTkFrame) -> None:
        card = ctk.CTkFrame(parent)
        card.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            card, text="Status & Location", font=ctk.CTkFont(size=15, weight="bold")
        ).grid(row=0, column=0, columnspan=3, padx=14, pady=(10, 6), sticky="w")

        self._status_label = ctk.CTkLabel(
            card, text="● Disconnected", font=ctk.CTkFont(size=13), text_color="#e74c3c"
        )
        self._status_label.grid(row=1, column=0, padx=14, pady=3, sticky="w")

        for i, (text, attr) in enumerate(
            [
                ("IP:", "_ip_val"),
                ("Location:", "_loc_val"),
                ("ISP:", "_org_val"),
                ("Timezone:", "_tz_val"),
            ],
            start=2,
        ):
            ctk.CTkLabel(card, text=text, anchor="w").grid(
                row=i, column=0, padx=(14, 4), pady=1, sticky="w"
            )
            lbl = ctk.CTkLabel(card, text="N/A", anchor="w")
            lbl.grid(row=i, column=1, padx=(4, 14), pady=1, sticky="w")
            setattr(self, attr, lbl)

        self._refresh_ip_btn = ctk.CTkButton(
            card, text="Refresh IP", width=90, command=self._refresh_ip_info
        )
        self._refresh_ip_btn.grid(
            row=2, column=2, rowspan=2, padx=14, pady=3, sticky="e"
        )

        self._uptime_label = ctk.CTkLabel(card, text="Uptime: --:--:--", anchor="e")
        self._uptime_label.grid(row=1, column=2, padx=14, pady=3, sticky="e")

        self._killswitch_info = ctk.CTkLabel(
            card, text="Kill-Switch: OFF", text_color="gray"
        )
        self._killswitch_info.grid(row=4, column=2, padx=14, pady=3, sticky="e")

        ctk.CTkLabel(card, text="").grid(row=6, column=0, pady=(0, 6))

    def _build_config_editor(self, parent: ctk.CTkFrame) -> None:
        self._editor_tabview = ctk.CTkTabview(parent, height=220)
        self._editor_tabview.grid(row=2, column=0, sticky="ew", pady=(0, 8))

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
            ctk.CTkLabel(wg, text=label, anchor="w").grid(
                row=row, column=0, padx=(8, 4), pady=2, sticky="w"
            )
            entry = ctk.CTkEntry(wg, placeholder_text=placeholder)
            entry.grid(row=row, column=1, padx=(4, 8), pady=2, sticky="ew")
            self._wg_entries[key] = entry

        wg_btn_frame = ctk.CTkFrame(wg, fg_color="transparent")
        wg_btn_frame.grid(row=9, column=0, columnspan=2, pady=(6, 4))
        ctk.CTkButton(
            wg_btn_frame, text="Save Profile", command=self._save_wg_profile
        ).pack(side="left", padx=4)

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
            ctk.CTkLabel(ovpn, text=label, anchor="w").grid(
                row=row, column=0, padx=(8, 4), pady=2, sticky="w"
            )
            entry = ctk.CTkEntry(ovpn, placeholder_text=placeholder)
            entry.grid(row=row, column=1, padx=(4, 8), pady=2, sticky="ew")
            self._ovpn_entries[key] = entry

        # CA / Cert / Key — textbox fields
        cert_row = len(ovpn_fields)
        ctk.CTkLabel(ovpn, text="CA Cert (paste PEM):", anchor="w").grid(
            row=cert_row, column=0, padx=(8, 4), pady=2, sticky="nw"
        )
        self._ovpn_ca_text = ctk.CTkTextbox(ovpn, height=50)
        self._ovpn_ca_text.grid(
            row=cert_row, column=1, padx=(4, 8), pady=2, sticky="ew"
        )

        ctk.CTkLabel(ovpn, text="Extra directives:", anchor="w").grid(
            row=cert_row + 1, column=0, padx=(8, 4), pady=2, sticky="nw"
        )
        self._ovpn_extra_text = ctk.CTkTextbox(ovpn, height=40)
        self._ovpn_extra_text.grid(
            row=cert_row + 1, column=1, padx=(4, 8), pady=2, sticky="ew"
        )

        ovpn_btn_frame = ctk.CTkFrame(ovpn, fg_color="transparent")
        ovpn_btn_frame.grid(row=cert_row + 2, column=0, columnspan=2, pady=(6, 4))
        ctk.CTkButton(
            ovpn_btn_frame, text="Save Profile", command=self._save_ovpn_profile
        ).pack(side="left", padx=4)

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
            ctk.CTkLabel(ssh, text=label, anchor="w").grid(
                row=row, column=0, padx=(8, 4), pady=2, sticky="w"
            )
            entry = ctk.CTkEntry(ssh, placeholder_text=placeholder)
            entry.grid(row=row, column=1, padx=(4, 8), pady=2, sticky="ew")
            self._ssh_entries[key] = entry

        # SSH key import
        ssh_key_frame = ctk.CTkFrame(ssh, fg_color="transparent")
        ssh_key_frame.grid(row=5, column=0, columnspan=2, padx=8, pady=2, sticky="ew")
        ssh_key_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(ssh_key_frame, text="SSH Key:", anchor="w").grid(
            row=0, column=0, padx=(0, 4), sticky="w"
        )
        self._ssh_key_label = ctk.CTkLabel(
            ssh_key_frame, text="(none)", text_color="gray", anchor="w"
        )
        self._ssh_key_label.grid(row=0, column=1, sticky="w")
        ctk.CTkButton(
            ssh_key_frame, text="Browse .pem", width=100, command=self._import_ssh_key
        ).grid(row=0, column=2, padx=(8, 0))
        self._ssh_key_path: Optional[Path] = None

        ssh_btn_frame = ctk.CTkFrame(ssh, fg_color="transparent")
        ssh_btn_frame.grid(row=6, column=0, columnspan=2, pady=(6, 4))
        ctk.CTkButton(
            ssh_btn_frame, text="Save Profile", command=self._save_ssh_profile
        ).pack(side="left", padx=4)

        # --- Setup Wizard tab ---
        self._build_setup_wizard()

        # Sync the tab to the protocol selector
        self._on_protocol_change(self._protocol_var.get())

    def _build_setup_wizard(self) -> None:
        """Build the guided Setup wizard tab as step-based pages."""
        setup = self._editor_tabview.add("Setup")
        setup.grid_columnconfigure(0, weight=1)
        setup.grid_rowconfigure(1, weight=1)

        self._wiz_step_order = [
            "1. SSH Key",
            "2. Server Info",
            "3. Server Connection",
            "4. Protocol Setup",
            "5. Create Profile",
        ]
        self._wiz_step_hints = {
            "1. SSH Key": "Generate or load your SSH key and copy its public key.",
            "2. Server Info": "Enter provider and server details.",
            "3. Server Connection": "Test SSH and run initial server setup commands.",
            "4. Protocol Setup": "Install protocol components and fill protocol fields.",
            "5. Create Profile": "Create and save the final profile.",
        }

        head = ctk.CTkFrame(setup, fg_color="transparent")
        head.grid(row=0, column=0, padx=8, pady=(8, 2), sticky="ew")
        head.grid_columnconfigure(0, weight=1)
        self._wiz_step_title = ctk.CTkLabel(
            head, text="", anchor="w", font=ctk.CTkFont(size=14, weight="bold")
        )
        self._wiz_step_title.grid(row=0, column=0, sticky="w")
        self._wiz_step_hint = ctk.CTkLabel(head, text="", anchor="w", text_color="gray")
        self._wiz_step_hint.grid(row=1, column=0, sticky="w")

        self._wiz_tabs = ctk.CTkTabview(setup)
        self._wiz_tabs.grid(row=1, column=0, padx=8, pady=(2, 4), sticky="nsew")

        step1 = self._wiz_tabs.add("1. SSH Key")
        step1.grid_columnconfigure(0, weight=1)
        step2 = self._wiz_tabs.add("2. Server Info")
        step2.grid_columnconfigure(0, weight=1)
        step3 = self._wiz_tabs.add("3. Server Connection")
        step3.grid_columnconfigure(0, weight=1)
        step3.grid_rowconfigure(6, weight=1)
        step4 = self._wiz_tabs.add("4. Protocol Setup")
        step4.grid_columnconfigure(0, weight=1)
        step4.grid_rowconfigure(1, weight=1)
        step5 = self._wiz_tabs.add("5. Create Profile")
        step5.grid_columnconfigure(0, weight=1)

        self._wiz_ssh_status = ctk.CTkLabel(step1, text="Checking...", anchor="w")
        self._wiz_ssh_status.grid(row=0, column=0, padx=8, pady=(6, 2), sticky="w")
        self._wiz_ssh_pubkey_box = ctk.CTkTextbox(step1, height=70, state="disabled")
        self._wiz_ssh_pubkey_box.grid(row=1, column=0, padx=8, pady=(2, 2), sticky="ew")

        ssh_btn_row = ctk.CTkFrame(step1, fg_color="transparent")
        ssh_btn_row.grid(row=2, column=0, padx=8, pady=(2, 4), sticky="ew")
        self._wiz_ssh_browse_btn = ctk.CTkButton(
            ssh_btn_row,
            text="Use Existing Key...",
            width=150,
            command=self._wizard_browse_ssh_key,
        )
        self._wiz_ssh_browse_btn.pack(side="left", padx=(0, 8))
        self._wiz_ssh_copy_btn = ctk.CTkButton(
            ssh_btn_row,
            text="Copy Public Key",
            width=130,
            command=lambda: self._wizard_copy_to_clipboard(self._wizard_ssh_pubkey),
        )
        self._wiz_ssh_copy_btn.pack(side="left", padx=(0, 8))

        ssh_gen_row = ctk.CTkFrame(step1, fg_color="transparent")
        ssh_gen_row.grid(row=3, column=0, padx=8, pady=(0, 8), sticky="ew")
        self._wiz_ssh_gen_btn = ctk.CTkButton(
            ssh_gen_row,
            text="Generate New Key",
            width=150,
            command=self._wizard_generate_ssh_key,
        )
        self._wiz_ssh_gen_btn.pack(side="left", padx=(0, 8))
        ctk.CTkLabel(ssh_gen_row, text="Name:", anchor="w").pack(
            side="left", padx=(8, 4)
        )
        self._wiz_ssh_keyname_entry = ctk.CTkEntry(
            ssh_gen_row, placeholder_text="id_ed25519", width=160
        )
        self._wiz_ssh_keyname_entry.pack(side="left")

        self._wiz_provider_var = ctk.StringVar(value="DigitalOcean")
        provider_seg = ctk.CTkSegmentedButton(
            step2,
            values=["DigitalOcean", "Azure", "Other"],
            variable=self._wiz_provider_var,
            command=self._wizard_on_provider_change,
        )
        provider_seg.grid(row=0, column=0, padx=8, pady=(6, 4), sticky="ew")
        self._wiz_provider_info = ctk.CTkTextbox(step2, height=80, state="disabled")
        self._wiz_provider_info.grid(row=1, column=0, padx=8, pady=(2, 4), sticky="ew")

        srv_frame = ctk.CTkFrame(step2, fg_color="transparent")
        srv_frame.grid(row=2, column=0, padx=8, pady=(2, 8), sticky="ew")
        srv_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(srv_frame, text="Server IP:", anchor="w").grid(
            row=0, column=0, padx=(0, 4), pady=2, sticky="w"
        )
        self._wiz_server_ip = ctk.CTkEntry(srv_frame, placeholder_text="203.0.113.10")
        self._wiz_server_ip.grid(row=0, column=1, pady=2, sticky="ew")
        ctk.CTkLabel(srv_frame, text="SSH User:", anchor="w").grid(
            row=1, column=0, padx=(0, 4), pady=2, sticky="w"
        )
        self._wiz_ssh_user = ctk.CTkEntry(srv_frame, placeholder_text="root")
        self._wiz_ssh_user.grid(row=1, column=1, pady=2, sticky="ew")
        ctk.CTkLabel(srv_frame, text="SSH Port:", anchor="w").grid(
            row=2, column=0, padx=(0, 4), pady=2, sticky="w"
        )
        self._wiz_ssh_port = ctk.CTkEntry(srv_frame, placeholder_text="22")
        self._wiz_ssh_port.grid(row=2, column=1, pady=2, sticky="ew")

        test_row = ctk.CTkFrame(step3, fg_color="transparent")
        test_row.grid(row=0, column=0, padx=8, pady=(6, 2), sticky="ew")
        self._wiz_test_btn = ctk.CTkButton(
            test_row,
            text="Test Connection",
            width=150,
            command=self._wizard_test_connection,
        )
        self._wiz_test_btn.pack(side="left", padx=(0, 8))
        self._wiz_test_status = ctk.CTkLabel(test_row, text="", anchor="w")
        self._wiz_test_status.pack(side="left", fill="x", expand=True)
        self._wiz_test_detail = ctk.CTkLabel(
            step3, text="", anchor="w", font=ctk.CTkFont(size=11), wraplength=700
        )
        self._wiz_test_detail.grid(row=1, column=0, padx=8, pady=(0, 4), sticky="w")

        ssh_cmd_row = ctk.CTkFrame(step3, fg_color="transparent")
        ssh_cmd_row.grid(row=2, column=0, padx=8, pady=(0, 2), sticky="ew")
        self._wiz_copy_ssh_btn = ctk.CTkButton(
            ssh_cmd_row,
            text="Copy SSH Command",
            width=160,
            command=self._wizard_copy_ssh_command,
        )
        self._wiz_copy_ssh_btn.pack(side="left", padx=(0, 8))
        self._wiz_ssh_cmd_status = ctk.CTkLabel(ssh_cmd_row, text="", anchor="w")
        self._wiz_ssh_cmd_status.pack(side="left")

        setup_row = ctk.CTkFrame(step3, fg_color="transparent")
        setup_row.grid(row=3, column=0, padx=8, pady=(0, 2), sticky="ew")
        self._wiz_initial_setup_btn = ctk.CTkButton(
            setup_row,
            text="Run Initial Server Setup",
            width=190,
            command=self._wizard_run_initial_server_setup,
        )
        self._wiz_initial_setup_btn.pack(side="left", padx=(0, 8))
        self._wiz_initial_setup_status = ctk.CTkLabel(setup_row, text="", anchor="w")
        self._wiz_initial_setup_status.pack(side="left")

        ctk.CTkLabel(
            step3, text="Run command on server:", anchor="w", font=ctk.CTkFont(size=12)
        ).grid(row=4, column=0, padx=8, pady=(4, 2), sticky="w")
        cmd_row = ctk.CTkFrame(step3, fg_color="transparent")
        cmd_row.grid(row=5, column=0, padx=8, pady=(0, 2), sticky="ew")
        cmd_row.grid_columnconfigure(0, weight=1)
        self._wiz_remote_cmd = ctk.CTkEntry(
            cmd_row, placeholder_text="e.g. apt update && apt upgrade -y"
        )
        self._wiz_remote_cmd.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._wiz_remote_run_btn = ctk.CTkButton(
            cmd_row, text="Run", width=80, command=self._wizard_run_remote_cmd
        )
        self._wiz_remote_run_btn.grid(row=0, column=1)
        self._wiz_remote_output = ctk.CTkTextbox(
            step3,
            height=220,
            state="disabled",
            font=ctk.CTkFont(
                family="Consolas"
                if self.system.os_type == OSType.WINDOWS
                else "monospace",
                size=11,
            ),
        )
        self._wiz_remote_output.grid(
            row=6, column=0, padx=8, pady=(2, 6), sticky="nsew"
        )
        self._wiz_remote_cmd.bind("<Return>", lambda e: self._wizard_run_remote_cmd())

        self._wiz_proto_var = ctk.StringVar(value="WireGuard")
        proto_seg = ctk.CTkSegmentedButton(
            step4,
            values=["WireGuard", "OpenVPN", "SSH SOCKS5"],
            variable=self._wiz_proto_var,
            command=self._wizard_on_proto_change,
        )
        proto_seg.grid(row=0, column=0, padx=8, pady=(6, 4), sticky="ew")
        self._wiz_proto_container = ctk.CTkFrame(step4, fg_color="transparent")
        self._wiz_proto_container.grid(
            row=1, column=0, padx=8, pady=(2, 4), sticky="nsew"
        )
        self._wiz_proto_container.grid_columnconfigure(0, weight=1)

        self._wiz_wg_frame = ctk.CTkFrame(
            self._wiz_proto_container, fg_color="transparent"
        )
        self._wiz_wg_frame.grid_columnconfigure(0, weight=1)
        wg_btn_row = ctk.CTkFrame(self._wiz_wg_frame, fg_color="transparent")
        wg_btn_row.grid(row=0, column=0, sticky="w", pady=(0, 4))
        self._wiz_wg_install_btn = ctk.CTkButton(
            wg_btn_row,
            text="Install WireGuard on Server",
            width=220,
            fg_color="#2980b9",
            hover_color="#2471a3",
            command=self._wizard_wg_install_remote,
        )
        self._wiz_wg_install_btn.pack(side="left", padx=(0, 8))
        self._wiz_wg_install_status = ctk.CTkLabel(wg_btn_row, text="", anchor="w")
        self._wiz_wg_install_status.pack(side="left")
        self._wiz_wg_prereq_label = ctk.CTkLabel(
            self._wiz_wg_frame,
            text="Complete Step 1, 2, and 3 first (key + server info + test + initial setup).",
            anchor="w",
            text_color="#f39c12",
            font=ctk.CTkFont(size=11),
        )
        self._wiz_wg_prereq_label.grid(row=1, column=0, sticky="w", pady=(0, 2))
        ctk.CTkLabel(
            self._wiz_wg_frame,
            text="After install completes, keys are fetched automatically. Or paste manually:",
            anchor="w",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).grid(row=2, column=0, sticky="w", pady=(0, 4))
        wg_fields = ctk.CTkFrame(self._wiz_wg_frame, fg_color="transparent")
        wg_fields.grid(row=3, column=0, sticky="ew")
        wg_fields.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(wg_fields, text="Server Public Key:", anchor="w").grid(
            row=0, column=0, padx=(0, 4), pady=2, sticky="w"
        )
        self._wiz_wg_server_pubkey = ctk.CTkEntry(
            wg_fields, placeholder_text="Auto-filled or paste server_public.key"
        )
        self._wiz_wg_server_pubkey.grid(row=0, column=1, pady=2, sticky="ew")
        ctk.CTkLabel(wg_fields, text="Client Private Key:", anchor="w").grid(
            row=1, column=0, padx=(0, 4), pady=2, sticky="w"
        )
        self._wiz_wg_client_privkey = ctk.CTkEntry(
            wg_fields, placeholder_text="Auto-filled or paste client_private.key"
        )
        self._wiz_wg_client_privkey.grid(row=1, column=1, pady=2, sticky="ew")
        ctk.CTkLabel(wg_fields, text="Tunnel Address:", anchor="w").grid(
            row=2, column=0, padx=(0, 4), pady=2, sticky="w"
        )
        self._wiz_wg_address = ctk.CTkEntry(wg_fields, placeholder_text="10.0.0.2/24")
        self._wiz_wg_address.grid(row=2, column=1, pady=2, sticky="ew")
        ctk.CTkLabel(wg_fields, text="DNS:", anchor="w").grid(
            row=3, column=0, padx=(0, 4), pady=2, sticky="w"
        )
        self._wiz_wg_dns = ctk.CTkEntry(wg_fields, placeholder_text="1.1.1.1")
        self._wiz_wg_dns.grid(row=3, column=1, pady=2, sticky="ew")

        self._wiz_ovpn_frame = ctk.CTkFrame(
            self._wiz_proto_container, fg_color="transparent"
        )
        self._wiz_ovpn_frame.grid_columnconfigure(0, weight=1)
        ovpn_btn_row = ctk.CTkFrame(self._wiz_ovpn_frame, fg_color="transparent")
        ovpn_btn_row.grid(row=0, column=0, sticky="w", pady=(0, 4))
        self._wiz_ovpn_install_btn = ctk.CTkButton(
            ovpn_btn_row,
            text="Install OpenVPN on Server",
            width=220,
            fg_color="#2980b9",
            hover_color="#2471a3",
            command=self._wizard_ovpn_install_remote,
        )
        self._wiz_ovpn_install_btn.pack(side="left", padx=(0, 8))
        self._wiz_ovpn_install_status = ctk.CTkLabel(ovpn_btn_row, text="", anchor="w")
        self._wiz_ovpn_install_status.pack(side="left")
        ctk.CTkLabel(
            self._wiz_ovpn_frame,
            text="Or import an existing .ovpn file:",
            anchor="w",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).grid(row=1, column=0, sticky="w", pady=(4, 2))
        ovpn_import_row = ctk.CTkFrame(self._wiz_ovpn_frame, fg_color="transparent")
        ovpn_import_row.grid(row=2, column=0, sticky="w", pady=(0, 4))
        ctk.CTkButton(
            ovpn_import_row,
            text="Import .ovpn File",
            width=150,
            command=self._wizard_import_ovpn,
        ).pack(side="left", padx=(0, 8))
        self._wiz_ovpn_file_label = ctk.CTkLabel(
            ovpn_import_row,
            text="",
            anchor="w",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        )
        self._wiz_ovpn_file_label.pack(side="left")

        self._wiz_ssh_frame = ctk.CTkFrame(
            self._wiz_proto_container, fg_color="transparent"
        )
        self._wiz_ssh_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            self._wiz_ssh_frame,
            text="No server-side setup needed. Just pick a SOCKS port:",
            anchor="w",
            font=ctk.CTkFont(size=12),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
        ctk.CTkLabel(self._wiz_ssh_frame, text="SOCKS5 Port:", anchor="w").grid(
            row=1, column=0, padx=(0, 4), pady=2, sticky="w"
        )
        self._wiz_socks_port = ctk.CTkEntry(
            self._wiz_ssh_frame, placeholder_text="1080"
        )
        self._wiz_socks_port.grid(row=1, column=1, pady=2, sticky="ew")

        profile_row = ctk.CTkFrame(step5, fg_color="transparent")
        profile_row.grid(row=0, column=0, padx=8, pady=(6, 8), sticky="ew")
        profile_row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(profile_row, text="Profile Name:", anchor="w").grid(
            row=0, column=0, padx=(0, 4), pady=2, sticky="w"
        )
        self._wiz_profile_name = ctk.CTkEntry(
            profile_row, placeholder_text="my-vpn-server"
        )
        self._wiz_profile_name.grid(row=0, column=1, pady=2, sticky="ew")
        self._wiz_create_btn = ctk.CTkButton(
            profile_row,
            text="Create Profile",
            width=140,
            fg_color="green",
            hover_color="#2d8a2d",
            command=self._wizard_create_profile,
        )
        self._wiz_create_btn.grid(row=0, column=2, padx=(8, 0), pady=2)
        self._wiz_result_label = ctk.CTkLabel(step5, text="", anchor="w")
        self._wiz_result_label.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="w")

        nav = ctk.CTkFrame(setup, fg_color="transparent")
        nav.grid(row=2, column=0, padx=8, pady=(0, 8), sticky="ew")
        nav.grid_columnconfigure(1, weight=1)
        self._wiz_prev_btn = ctk.CTkButton(
            nav, text="Back", width=90, command=self._wizard_prev_step
        )
        self._wiz_prev_btn.grid(row=0, column=0, sticky="w")
        self._wiz_nav_status = ctk.CTkLabel(nav, text="", anchor="w")
        self._wiz_nav_status.grid(row=0, column=1, padx=8, sticky="w")
        self._wiz_next_btn = ctk.CTkButton(
            nav, text="Next", width=90, command=self._wizard_next_step
        )
        self._wiz_next_btn.grid(row=0, column=2, sticky="e")

        self.after(300, self._wizard_check_ssh_key)
        self.after(350, lambda: self._wizard_on_provider_change("DigitalOcean"))
        self._wizard_on_proto_change("WireGuard")
        self._wizard_refresh_wg_prereq_state()
        self._wiz_step_index = 0
        self._wizard_set_step(0)

        self._wiz_server_ip.bind(
            "<KeyRelease>", lambda _e: self._wizard_invalidate_step3()
        )
        self._wiz_ssh_user.bind(
            "<KeyRelease>", lambda _e: self._wizard_invalidate_step3()
        )
        self._wiz_ssh_port.bind(
            "<KeyRelease>", lambda _e: self._wizard_invalidate_step3()
        )

    def _wizard_set_step(self, step_index: int) -> None:
        """Set active wizard step and update title/navigation."""
        step_index = max(0, min(len(self._wiz_step_order) - 1, step_index))
        self._wiz_step_index = step_index
        name = self._wiz_step_order[step_index]
        self._wiz_tabs.set(name)
        self._wiz_step_title.configure(
            text=f"Step {step_index + 1}/5 - {name.split('. ', 1)[1]}"
        )
        self._wiz_step_hint.configure(text=self._wiz_step_hints.get(name, ""))
        self._wiz_prev_btn.configure(state="normal" if step_index > 0 else "disabled")
        self._wiz_next_btn.configure(
            state="normal" if step_index < len(self._wiz_step_order) - 1 else "disabled"
        )

    def _wizard_validate_step(self, step_index: int) -> bool:
        """Validate current step before advancing."""
        if step_index == 0 and not self._wizard_ssh_key_path:
            self._wiz_nav_status.configure(
                text="Step 1: SSH key is required.", text_color="#e74c3c"
            )
            return False
        if step_index == 1 and not self._wiz_server_ip.get().strip():
            self._wiz_nav_status.configure(
                text="Step 2: Server IP is required.", text_color="#e74c3c"
            )
            return False
        self._wiz_nav_status.configure(text="", text_color="gray")
        return True

    def _wizard_prev_step(self) -> None:
        """Move to previous wizard step."""
        self._wizard_set_step(self._wiz_step_index - 1)

    def _wizard_next_step(self) -> None:
        """Move to next wizard step after validation."""
        if not self._wizard_validate_step(self._wiz_step_index):
            return
        self._wizard_set_step(self._wiz_step_index + 1)

    def _wizard_invalidate_step3(self) -> None:
        """Invalidate step 3 completion when upstream inputs change."""
        self._wiz_step3_test_ok = False
        self._wiz_step3_setup_ok = False
        self._wizard_refresh_wg_prereq_state()

    def _wizard_refresh_wg_prereq_state(self) -> None:
        """Enable Step 4 WireGuard install only after Step 1-3 prerequisites are complete."""
        has_key = self._wizard_ssh_key_path is not None
        has_server = bool(self._wiz_server_ip.get().strip())
        ready = (
            has_key
            and has_server
            and self._wiz_step3_test_ok
            and self._wiz_step3_setup_ok
        )

        self._wiz_wg_install_btn.configure(state="normal" if ready else "disabled")
        if ready:
            self._wiz_wg_prereq_label.configure(
                text="Prerequisites complete. You can install WireGuard on the server.",
                text_color="#2ecc71",
            )
        else:
            self._wiz_wg_prereq_label.configure(
                text="Complete Step 1, 2, and 3 first (key + server info + test + initial setup).",
                text_color="#f39c12",
            )

    @staticmethod
    def _wizard_build_header(parent: ctk.CTkFrame, title: str, row: int) -> int:
        """Add a step header label and return the next row."""
        ctk.CTkLabel(
            parent, text=title, font=ctk.CTkFont(size=13, weight="bold"), anchor="w"
        ).grid(row=row, column=0, padx=8, pady=(10, 2), sticky="w")
        return row + 1

    # -----------------------------------------------------------------------
    # Wizard Actions
    # -----------------------------------------------------------------------

    def _wizard_check_ssh_key(self) -> None:
        """Auto-detect common SSH keys and show the first one found."""
        ssh_dir = Path.home() / ".ssh"
        candidates = ["id_ed25519", "id_rsa", "id_ecdsa", "vpn_key"]
        for name in candidates:
            priv = ssh_dir / name
            pub = ssh_dir / f"{name}.pub"
            if priv.exists() and pub.exists():
                self._wizard_load_key(priv)
                return

        self._wiz_ssh_status.configure(
            text="No SSH key auto-detected. Use 'Use Existing Key' to browse or 'Generate New Key' to create one.",
            text_color="#f39c12",
        )

    def _wizard_load_key(self, priv_path: Path) -> None:
        """Load and display an SSH key pair."""
        pub_path = (
            priv_path.with_suffix(".pub") if priv_path.suffix != ".pub" else priv_path
        )
        if priv_path.suffix == ".pub":
            priv_path = priv_path.with_suffix("")

        if not pub_path.exists():
            self._wiz_ssh_status.configure(
                text=f"Public key not found: {pub_path}", text_color="#e74c3c"
            )
            return

        try:
            pubkey = pub_path.read_text(encoding="utf-8").strip()
        except Exception as exc:
            self._wiz_ssh_status.configure(
                text=f"Cannot read key: {exc}", text_color="#e74c3c"
            )
            return

        self._wizard_ssh_key_path = priv_path
        self._wizard_ssh_pubkey = pubkey
        self._wiz_ssh_status.configure(text=f"Using: {priv_path}", text_color="#2ecc71")
        self._wiz_ssh_pubkey_box.configure(state="normal")
        self._wiz_ssh_pubkey_box.delete("1.0", "end")
        self._wiz_ssh_pubkey_box.insert("1.0", pubkey)
        self._wiz_ssh_pubkey_box.configure(state="disabled")
        self._wizard_invalidate_step3()
        logger.info("Wizard: SSH key loaded — %s", priv_path)

    def _wizard_browse_ssh_key(self) -> None:
        """Let the user pick any existing private key file."""
        ssh_dir = Path.home() / ".ssh"
        initial = str(ssh_dir) if ssh_dir.exists() else str(Path.home())
        path = filedialog.askopenfilename(
            title="Select SSH Private Key",
            initialdir=initial,
            filetypes=[("SSH Keys", "*.pem *.key"), ("All Files", "*.*")],
        )
        if path:
            self._wizard_load_key(Path(path))

    def _wizard_generate_ssh_key(self) -> None:
        """Generate a new Ed25519 SSH key pair with user-specified name."""
        keygen = shutil.which("ssh-keygen")
        if not keygen:
            self._wiz_ssh_status.configure(
                text="ssh-keygen not found. Install OpenSSH first.",
                text_color="#e74c3c",
            )
            return

        key_name = self._wiz_ssh_keyname_entry.get().strip() or "id_ed25519"
        # Sanitize: only allow filename-safe characters
        key_name = re.sub(r"[^\w\-.]", "_", key_name)
        ssh_dir = Path.home() / ".ssh"
        ssh_dir.mkdir(parents=True, exist_ok=True)
        key_path = ssh_dir / key_name

        if key_path.exists():
            # Key already exists — just load it instead of overwriting
            self._wiz_ssh_status.configure(
                text=f"Key '{key_name}' already exists — loaded it.",
                text_color="#f39c12",
            )
            self._wizard_load_key(key_path)
            return

        self._wiz_ssh_gen_btn.configure(state="disabled", text="Generating…")
        self._wiz_ssh_status.configure(
            text=f"Generating ~/.ssh/{key_name} …", text_color="gray"
        )

        def _worker() -> None:
            try:
                result = subprocess.run(
                    [
                        keygen,
                        "-t",
                        "ed25519",
                        "-C",
                        "privatecrossvpn",
                        "-f",
                        str(key_path),
                        "-N",
                        "",
                    ],
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    logger.info("Wizard: SSH key generated at %s", key_path)
                    self.after(0, lambda: self._wizard_load_key(key_path))
                else:
                    err = result.stderr.strip()
                    logger.error("ssh-keygen failed: %s", err)
                    self.after(
                        0,
                        lambda: self._wiz_ssh_status.configure(
                            text=f"Generation failed: {err}", text_color="#e74c3c"
                        ),
                    )
            except Exception as exc:
                error_message = f"Error: {exc}"
                logger.error("ssh-keygen error: %s", exc)
                self.after(
                    0,
                    lambda: self._wiz_ssh_status.configure(
                        text=error_message, text_color="#e74c3c"
                    ),
                )
            finally:
                self.after(
                    0,
                    lambda: self._wiz_ssh_gen_btn.configure(
                        state="normal", text="Generate New Key"
                    ),
                )

        threading.Thread(target=_worker, daemon=True).start()

    def _wizard_on_provider_change(self, provider: str) -> None:
        """Update the provider instruction text."""
        instructions = {
            "DigitalOcean": (
                "1. Go to cloud.digitalocean.com → Create → Droplets\n"
                "2. Choose Ubuntu 24.04, Basic $6/mo (or cheapest)\n"
                "3. Under Authentication, select SSH Key and add the public key from Step 1\n"
                "4. Create Droplet and copy its IP address below"
            ),
            "Azure": (
                "1. Go to portal.azure.com → Create a resource → Virtual machine\n"
                "2. Choose Ubuntu 24.04, Size: Standard_B1s (~$7.59/mo)\n"
                "3. Authentication: SSH public key, paste the key from Step 1\n"
                "4. Create and copy the VM's public IP address below"
            ),
            "Other": (
                "Ensure you have a Linux server (Ubuntu/Debian recommended) with:\n"
                "- SSH access enabled\n"
                "- Your public key from Step 1 added to ~/.ssh/authorized_keys\n"
                "- Enter the server details below"
            ),
        }
        text = instructions.get(provider, instructions["Other"])
        self._wiz_provider_info.configure(state="normal")
        self._wiz_provider_info.delete("1.0", "end")
        self._wiz_provider_info.insert("1.0", text)
        self._wiz_provider_info.configure(state="disabled")

    def _wizard_test_connection(self) -> None:
        """Test SSH connection to the server in a background thread."""
        ip = self._wiz_server_ip.get().strip()
        user = self._wiz_ssh_user.get().strip() or "root"
        port = self._wiz_ssh_port.get().strip() or "22"

        if not ip:
            self._wiz_test_status.configure(
                text="Enter a server IP first.", text_color="#e74c3c"
            )
            return

        if not self._wizard_ssh_key_path:
            self._wiz_test_status.configure(
                text="Generate or locate an SSH key first (Step 1).",
                text_color="#e74c3c",
            )
            return

        ssh_bin = shutil.which("ssh")
        if not ssh_bin:
            self._wiz_test_status.configure(
                text="ssh binary not found.", text_color="#e74c3c"
            )
            return

        self._wiz_test_btn.configure(state="disabled", text="Testing…")
        self._wiz_test_status.configure(text="Connecting…", text_color="#f39c12")
        self._wiz_test_detail.configure(text="")

        def _worker() -> None:
            try:
                result = subprocess.run(
                    [
                        ssh_bin,
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "ConnectTimeout=10",
                        "-o",
                        "StrictHostKeyChecking=accept-new",
                        "-i",
                        str(self._wizard_ssh_key_path),
                        "-p",
                        port,
                        f"{user}@{ip}",
                        "uname -a",
                    ],
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                if result.returncode == 0:
                    info = result.stdout.strip()
                    self._wiz_step3_test_ok = True
                    self.after(
                        0,
                        lambda: self._wiz_test_status.configure(
                            text="Connected successfully!", text_color="#2ecc71"
                        ),
                    )
                    self.after(
                        0,
                        lambda: self._wiz_test_detail.configure(text=f"Server: {info}"),
                    )
                    self.after(0, self._wizard_refresh_wg_prereq_state)
                    logger.info("Wizard: SSH test OK — %s", info)
                else:
                    self._wiz_step3_test_ok = False
                    err = result.stderr.strip() or "Connection failed"
                    self.after(
                        0,
                        lambda: self._wiz_test_status.configure(
                            text="Connection failed.", text_color="#e74c3c"
                        ),
                    )
                    self.after(0, lambda: self._wiz_test_detail.configure(text=err))
                    self.after(0, self._wizard_refresh_wg_prereq_state)
                    logger.warning("Wizard: SSH test failed — %s", err)
            except subprocess.TimeoutExpired:
                self._wiz_step3_test_ok = False
                timeout_message = "Connection timed out."
                self.after(
                    0,
                    lambda: self._wiz_test_status.configure(
                        text=timeout_message, text_color="#e74c3c"
                    ),
                )
                self.after(0, self._wizard_refresh_wg_prereq_state)
            except Exception as exc:
                self._wiz_step3_test_ok = False
                error_message = f"Error: {exc}"
                self.after(
                    0,
                    lambda: self._wiz_test_status.configure(
                        text=error_message, text_color="#e74c3c"
                    ),
                )
                self.after(0, self._wizard_refresh_wg_prereq_state)
            finally:
                self.after(
                    0,
                    lambda: self._wiz_test_btn.configure(
                        state="normal", text="Test Connection"
                    ),
                )

        threading.Thread(target=_worker, daemon=True).start()

    def _wizard_build_ssh_command(self) -> Optional[str]:
        """Build SSH login command from current wizard fields."""
        ip = self._wiz_server_ip.get().strip()
        user = self._wiz_ssh_user.get().strip() or "root"
        port = self._wiz_ssh_port.get().strip() or "22"

        if not ip:
            self._wiz_ssh_cmd_status.configure(
                text="Enter a server IP in Step 2.", text_color="#e74c3c"
            )
            return None
        if not self._wizard_ssh_key_path:
            self._wiz_ssh_cmd_status.configure(
                text="Generate or locate an SSH key first (Step 1).",
                text_color="#e74c3c",
            )
            return None

        return build_ssh_login_command(self._wizard_ssh_key_path, ip, user, port)

    def _wizard_copy_ssh_command(self) -> None:
        """Copy SSH login command to clipboard."""
        command = self._wizard_build_ssh_command()
        if not command:
            return
        self._wizard_copy_to_clipboard(command)
        self._wiz_ssh_cmd_status.configure(
            text="SSH command copied to clipboard.", text_color="#2ecc71"
        )

    def _wizard_run_initial_server_setup(self) -> None:
        """Run initial server setup on remote host via SSH."""
        self._wiz_initial_setup_btn.configure(state="disabled", text="Running...")
        self._wiz_initial_setup_status.configure(
            text="Applying initial server setup...", text_color="#f39c12"
        )

        setup_cmd = (
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt update && apt upgrade -y && "
            "ufw allow OpenSSH && ufw --force enable && "
            'id -u vpnuser >/dev/null 2>&1 || adduser --disabled-password --gecos "" vpnuser && '
            "usermod -aG sudo vpnuser"
        )

        def _on_output(line: str) -> None:
            self._wiz_remote_output.configure(state="normal")
            self._wiz_remote_output.insert("end", line + "\n")
            self._wiz_remote_output.see("end")
            self._wiz_remote_output.configure(state="disabled")

        def _on_done(rc: int, stdout: str, stderr: str) -> None:
            self._wiz_initial_setup_btn.configure(
                state="normal", text="Run Initial Server Setup"
            )
            self._wiz_step3_setup_ok = rc == 0
            self._wiz_initial_setup_status.configure(
                text="Initial server setup completed."
                if rc == 0
                else f"Setup failed (exit {rc}).",
                text_color="#2ecc71" if rc == 0 else "#e74c3c",
            )
            self._wizard_refresh_wg_prereq_state()
            if stderr:
                self._wiz_remote_output.configure(state="normal")
                self._wiz_remote_output.insert("end", stderr + "\n")
                self._wiz_remote_output.configure(state="disabled")

        self._wiz_remote_output.configure(state="normal")
        self._wiz_remote_output.delete("1.0", "end")
        self._wiz_remote_output.insert("1.0", "$ Running initial server setup...\n")
        self._wiz_remote_output.configure(state="disabled")

        self._wizard_ssh_exec(
            setup_cmd, on_output=_on_output, on_done=_on_done, timeout=120
        )

    # -----------------------------------------------------------------------
    # Wizard — Remote Command Execution
    # -----------------------------------------------------------------------

    def _wizard_get_ssh_args(self) -> Optional[list[str]]:
        """Build the base SSH argument list from wizard fields. Returns None on validation failure."""
        ip = self._wiz_server_ip.get().strip()
        user = self._wiz_ssh_user.get().strip() or "root"
        port = self._wiz_ssh_port.get().strip() or "22"

        if not ip:
            self._wiz_test_status.configure(
                text="Enter server IP in Step 2.", text_color="#e74c3c"
            )
            return None
        if not self._wizard_ssh_key_path:
            self._wiz_test_status.configure(
                text="Set up an SSH key in Step 1.", text_color="#e74c3c"
            )
            return None

        ssh_bin = shutil.which("ssh")
        if not ssh_bin:
            self._wiz_test_status.configure(text="ssh not found.", text_color="#e74c3c")
            return None

        return [
            ssh_bin,
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-i",
            str(self._wizard_ssh_key_path),
            "-p",
            port,
            f"{user}@{ip}",
        ]

    def _wizard_ssh_exec(
        self,
        command: str,
        *,
        on_output: Optional[Callable[[str], None]] = None,
        on_done: Optional[Callable[[int, str, str], None]] = None,
        timeout: int = 120,
    ) -> None:
        """
        Execute a command on the remote server via SSH in a background thread.

        on_output(line) is called for each stdout line (real-time).
        on_done(returncode, stdout, stderr) is called when the command finishes.
        """
        base_args = self._wizard_get_ssh_args()
        if base_args is None:
            return

        args = base_args + [command]
        logger.info("Wizard SSH exec: %s", command)

        def _worker() -> None:
            try:
                proc = subprocess.Popen(
                    args,
                    shell=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                stdout_lines: list[str] = []
                if proc.stdout:
                    for line in iter(proc.stdout.readline, ""):
                        stripped = line.rstrip()
                        stdout_lines.append(stripped)
                        if on_output:
                            self.after(0, lambda text=stripped: on_output(text))

                proc.wait(timeout=timeout)
                stderr = proc.stderr.read() if proc.stderr else ""
                full_stdout = "\n".join(stdout_lines)

                if on_done:
                    self.after(0, lambda: on_done(proc.returncode, full_stdout, stderr))

            except subprocess.TimeoutExpired:
                proc.kill()
                if on_done:
                    self.after(0, lambda: on_done(-1, "", "Command timed out"))
            except Exception as exc:
                error_message = str(exc)
                if on_done:
                    self.after(0, lambda: on_done(-1, "", error_message))

        threading.Thread(target=_worker, daemon=True).start()

    def _wizard_run_remote_cmd(self) -> None:
        """Run the user-typed command from the remote command entry."""
        cmd = self._wiz_remote_cmd.get().strip()
        if not cmd:
            return

        self._wiz_remote_run_btn.configure(state="disabled", text="Running…")
        self._wiz_remote_output.configure(state="normal")
        self._wiz_remote_output.delete("1.0", "end")
        self._wiz_remote_output.insert("1.0", f"$ {cmd}\n")
        self._wiz_remote_output.configure(state="disabled")

        def _on_output(line: str) -> None:
            self._wiz_remote_output.configure(state="normal")
            self._wiz_remote_output.insert("end", line + "\n")
            self._wiz_remote_output.see("end")
            self._wiz_remote_output.configure(state="disabled")

        def _on_done(rc: int, stdout: str, stderr: str) -> None:
            self._wiz_remote_output.configure(state="normal")
            if stderr:
                self._wiz_remote_output.insert("end", stderr + "\n")
            status = "OK" if rc == 0 else f"Exit code: {rc}"
            self._wiz_remote_output.insert("end", f"[{status}]\n")
            self._wiz_remote_output.see("end")
            self._wiz_remote_output.configure(state="disabled")
            self._wiz_remote_run_btn.configure(state="normal", text="Run")

        self._wizard_ssh_exec(cmd, on_output=_on_output, on_done=_on_done)

    def _wizard_wg_install_remote(self) -> None:
        """Install WireGuard on the remote server, generate keys, and fetch them back."""
        self._wiz_wg_install_btn.configure(state="disabled", text="Installing…")
        self._wiz_wg_install_status.configure(
            text="Installing WireGuard…", text_color="#f39c12"
        )

        client_address = self._wiz_wg_address.get().strip() or "10.0.0.2/24"
        client_ip = "10.0.0.2"
        server_cidr = "10.0.0.1/24"
        try:
            iface = ipaddress.ip_interface(client_address)
            if isinstance(iface.ip, ipaddress.IPv4Address):
                client_ip = str(iface.ip)
                hosts = list(iface.network.hosts())
                if hosts:
                    server_cidr = f"{hosts[0]}/{iface.network.prefixlen}"
        except ValueError:
            pass

        install_cmd = (
            "export DEBIAN_FRONTEND=noninteractive && "
            "apt-get update -qq && apt-get install -y -qq wireguard > /dev/null 2>&1 && "
            "cd /etc/wireguard && umask 077 && "
            "wg genkey | tee server_private.key | wg pubkey > server_public.key && "
            "wg genkey | tee client_private.key | wg pubkey > client_public.key && "
            "SERVER_PRIV=$(cat server_private.key) && CLIENT_PUB=$(cat client_public.key) && "
            "EXT_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i==\"dev\") {print $(i+1); exit}}') && "
            '[ -n "$EXT_IF" ] || EXT_IF=eth0 && '
            "cat > /etc/wireguard/wg0.conf <<EOF\n"
            "[Interface]\n"
            "PrivateKey = $SERVER_PRIV\n"
            f"Address = {server_cidr}\n"
            "ListenPort = 51820\n"
            "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $EXT_IF -j MASQUERADE\n"
            "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $EXT_IF -j MASQUERADE\n"
            "\n"
            "[Peer]\n"
            "PublicKey = $CLIENT_PUB\n"
            f"AllowedIPs = {client_ip}/32\n"
            "EOF\n"
            "chmod 600 /etc/wireguard/wg0.conf && "
            "echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-privatecrossvpn.conf && "
            "sysctl --system > /dev/null 2>&1 && "
            "ufw allow 51820/udp > /dev/null 2>&1 || true && "
            "systemctl enable wg-quick@wg0 > /dev/null 2>&1 && "
            "systemctl restart wg-quick@wg0 && "
            "echo '===SERVER_PUBKEY===' && cat server_public.key && "
            "echo '===CLIENT_PRIVKEY===' && cat client_private.key && "
            "echo '===DONE==='"
        )

        collected: list[str] = []

        def _on_output(line: str) -> None:
            collected.append(line)
            # Show progress in remote output box
            self._wiz_remote_output.configure(state="normal")
            self._wiz_remote_output.insert("end", line + "\n")
            self._wiz_remote_output.see("end")
            self._wiz_remote_output.configure(state="disabled")

        def _on_done(rc: int, stdout: str, stderr: str) -> None:
            self._wiz_wg_install_btn.configure(
                state="normal", text="Install WireGuard on Server"
            )

            if rc != 0:
                self._wiz_wg_install_status.configure(
                    text=f"Install failed (exit {rc}). Check output above.",
                    text_color="#e74c3c",
                )
                if stderr:
                    self._wiz_remote_output.configure(state="normal")
                    self._wiz_remote_output.insert("end", stderr + "\n")
                    self._wiz_remote_output.configure(state="disabled")
                return

            # Parse keys from output
            full = "\n".join(collected)
            server_pubkey = ""
            client_privkey = ""

            if "===SERVER_PUBKEY===" in full and "===CLIENT_PRIVKEY===" in full:
                parts = full.split("===SERVER_PUBKEY===")
                if len(parts) > 1:
                    after_spk = parts[1].split("===CLIENT_PRIVKEY===")
                    server_pubkey = after_spk[0].strip()
                    if len(after_spk) > 1:
                        client_privkey = after_spk[1].split("===DONE===")[0].strip()

            if server_pubkey and client_privkey:
                # Auto-fill the key fields
                self._wiz_wg_server_pubkey.delete(0, "end")
                self._wiz_wg_server_pubkey.insert(0, server_pubkey)
                self._wiz_wg_client_privkey.delete(0, "end")
                self._wiz_wg_client_privkey.insert(0, client_privkey)
                self._wiz_wg_install_status.configure(
                    text="WireGuard server configured. Keys auto-filled below.",
                    text_color="#2ecc71",
                )
                logger.info("Wizard: WireGuard server configured, keys fetched.")
            else:
                self._wiz_wg_install_status.configure(
                    text="Installed but couldn't parse keys. Paste them manually.",
                    text_color="#f39c12",
                )

        self._wiz_remote_output.configure(state="normal")
        self._wiz_remote_output.delete("1.0", "end")
        self._wiz_remote_output.insert(
            "1.0", "$ Installing WireGuard & generating keys…\n"
        )
        self._wiz_remote_output.configure(state="disabled")

        self._wizard_ssh_exec(
            install_cmd, on_output=_on_output, on_done=_on_done, timeout=120
        )

    def _wizard_ovpn_install_remote(self) -> None:
        """Install OpenVPN on the remote server using the non-interactive script."""
        self._wiz_ovpn_install_btn.configure(state="disabled", text="Installing…")
        self._wiz_ovpn_install_status.configure(
            text="Installing OpenVPN (this takes 1-2 min)…", text_color="#f39c12"
        )

        ip = self._wiz_server_ip.get().strip()
        # Non-interactive OpenVPN install
        install_cmd = (
            "export DEBIAN_FRONTEND=noninteractive AUTO_INSTALL=y "
            "APPROVE_INSTALL=y APPROVE_IP=y "
            f'ENDPOINT="{ip}" '
            "PORT_CHOICE=1 PROTOCOL_CHOICE=1 DNS=9 COMPRESSION_ENABLED=n CUSTOMIZE_ENC=n "
            'CLIENT="privatecrossvpn" PASS=1 && '
            "curl -sO https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh && "
            "chmod +x openvpn-install.sh && "
            "bash openvpn-install.sh && "
            "cat /root/privatecrossvpn.ovpn"
        )

        ovpn_content: list[str] = []
        capture_ovpn = [False]  # mutable flag

        def _on_output(line: str) -> None:
            # Detect when .ovpn content starts
            if line.strip().startswith("client") or capture_ovpn[0]:
                capture_ovpn[0] = True
                ovpn_content.append(line)
            self._wiz_remote_output.configure(state="normal")
            self._wiz_remote_output.insert("end", line + "\n")
            self._wiz_remote_output.see("end")
            self._wiz_remote_output.configure(state="disabled")

        def _on_done(rc: int, stdout: str, stderr: str) -> None:
            self._wiz_ovpn_install_btn.configure(
                state="normal", text="Install OpenVPN on Server"
            )

            if rc != 0 and not ovpn_content:
                self._wiz_ovpn_install_status.configure(
                    text=f"Install failed (exit {rc}).", text_color="#e74c3c"
                )
                return

            if ovpn_content:
                # Save the .ovpn file locally
                ovpn_text = "\n".join(ovpn_content)
                dest = self.settings.configs_dir / "privatecrossvpn.ovpn"
                dest.write_text(ovpn_text, encoding="utf-8")
                self._wiz_ovpn_import_path = dest
                self._wiz_ovpn_file_label.configure(
                    text=f"Downloaded: {dest.name}", text_color="#2ecc71"
                )
                self._wiz_ovpn_install_status.configure(
                    text="Installed! Config downloaded.", text_color="#2ecc71"
                )
                logger.info("Wizard: OpenVPN installed, config saved to %s", dest)
            else:
                self._wiz_ovpn_install_status.configure(
                    text="Installed but couldn't download config. Use 'Import .ovpn File' manually.",
                    text_color="#f39c12",
                )

        self._wiz_remote_output.configure(state="normal")
        self._wiz_remote_output.delete("1.0", "end")
        self._wiz_remote_output.insert(
            "1.0", "$ Installing OpenVPN (non-interactive)…\n"
        )
        self._wiz_remote_output.configure(state="disabled")

        self._wizard_ssh_exec(
            install_cmd, on_output=_on_output, on_done=_on_done, timeout=180
        )

    def _wizard_on_proto_change(self, proto: str) -> None:
        """Show/hide protocol-specific frames."""
        for frame in (self._wiz_wg_frame, self._wiz_ovpn_frame, self._wiz_ssh_frame):
            frame.grid_forget()

        if proto == "WireGuard":
            self._wiz_wg_frame.grid(row=0, column=0, sticky="ew")
        elif proto == "OpenVPN":
            self._wiz_ovpn_frame.grid(row=0, column=0, sticky="ew")
        elif proto == "SSH SOCKS5":
            self._wiz_ssh_frame.grid(row=0, column=0, sticky="ew")

        # Auto-fill profile name
        provider = (
            self._wiz_provider_var.get().lower().replace(" ", "").replace("/", "")
        )
        proto_short = proto.lower().replace(" ", "-")
        suggested = f"{provider}-{proto_short}"
        self._wiz_profile_name.delete(0, "end")
        self._wiz_profile_name.insert(0, suggested)

    def _wizard_import_ovpn(self) -> None:
        """Import an .ovpn file for the OpenVPN wizard path."""
        path = filedialog.askopenfilename(
            title="Import .ovpn Configuration",
            filetypes=[("OpenVPN Config", "*.ovpn"), ("All Files", "*.*")],
        )
        if path:
            self._wiz_ovpn_import_path = Path(path)
            self._wiz_ovpn_file_label.configure(
                text=f"Imported: {Path(path).name}", text_color="#2ecc71"
            )
            logger.info("Wizard: Imported .ovpn file: %s", path)

    def _wizard_create_profile(self) -> None:
        """Assemble wizard data into a profile and save it."""
        name = self._wiz_profile_name.get().strip()
        if not name:
            self._wiz_result_label.configure(
                text="Enter a profile name.", text_color="#e74c3c"
            )
            return

        proto = self._wiz_proto_var.get()
        ip = self._wiz_server_ip.get().strip()
        user = self._wiz_ssh_user.get().strip() or "root"
        port = self._wiz_ssh_port.get().strip() or "22"

        if proto == "WireGuard":
            server_pubkey = self._wiz_wg_server_pubkey.get().strip()
            client_privkey = self._wiz_wg_client_privkey.get().strip()
            address = self._wiz_wg_address.get().strip() or "10.0.0.2/24"
            dns = self._wiz_wg_dns.get().strip() or "1.1.1.1"

            if not server_pubkey or not client_privkey:
                self._wiz_result_label.configure(
                    text="Server public key and client private key are required.",
                    text_color="#e74c3c",
                )
                return

            endpoint = f"{ip}:51820" if ip else ""
            data = {
                "protocol": Protocol.WIREGUARD.value,
                "name": name,
                "wg_private_key": client_privkey,
                "wg_address": address,
                "wg_dns": dns,
                "wg_public_key": server_pubkey,
                "wg_endpoint": endpoint,
                "wg_allowed_ips": "0.0.0.0/0, ::/0",
                "wg_keepalive": "25",
            }
            conf_path = self.profile_mgr.generate_wireguard_conf(name, data)
            data["config_file"] = str(conf_path)

        elif proto == "OpenVPN":
            ovpn_path = getattr(self, "_wiz_ovpn_import_path", None)
            if not ovpn_path or not ovpn_path.exists():
                self._wiz_result_label.configure(
                    text="Import an .ovpn file first.", text_color="#e74c3c"
                )
                return
            # Copy to configs dir
            dest = self.settings.configs_dir / ovpn_path.name
            shutil.copy2(ovpn_path, dest)
            data = {
                "protocol": Protocol.OPENVPN.value,
                "name": name,
                "config_file": str(dest),
            }

        elif proto == "SSH SOCKS5":
            if not ip:
                self._wiz_result_label.configure(
                    text="Enter the server IP in Step 2.", text_color="#e74c3c"
                )
                return
            socks = self._wiz_socks_port.get().strip() or "1080"
            data = {
                "protocol": Protocol.SSH_SOCKS5.value,
                "name": name,
                "ssh_host": ip,
                "ssh_port": port,
                "ssh_user": user,
                "socks_port": socks,
                "ssh_key_path": str(self._wizard_ssh_key_path)
                if self._wizard_ssh_key_path
                else "",
            }
        else:
            return

        # Save profile
        self.profile_mgr.save_profile(name, data)
        self.settings.last_profile = name
        self._load_profile_list()
        self._profile_var.set(name)
        self._on_profile_select(name)

        # Switch to the protocol tab
        proto_tab_map = {
            "WireGuard": Protocol.WIREGUARD.value,
            "OpenVPN": Protocol.OPENVPN.value,
            "SSH SOCKS5": Protocol.SSH_SOCKS5.value,
        }
        proto_val = proto_tab_map.get(proto, Protocol.WIREGUARD.value)
        self._protocol_var.set(proto_val)
        self._on_protocol_change(proto_val)

        self._wiz_result_label.configure(
            text=f"Profile '{name}' created! Switch to the sidebar and click Connect.",
            text_color="#2ecc71",
        )
        logger.info("Wizard: Profile '%s' created (%s).", name, proto)

    def _wizard_copy_to_clipboard(self, text: str) -> None:
        """Copy text to the system clipboard."""
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        logger.info("Wizard: Copied to clipboard.")

    def _build_log_area(self, parent: ctk.CTkFrame) -> None:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=3, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text="Activity Log",
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(header, text="Copy", width=60, command=self._copy_log).grid(
            row=0, column=1, padx=(0, 6), sticky="e"
        )
        ctk.CTkButton(header, text="Clear", width=60, command=self._clear_log).grid(
            row=0, column=2, sticky="e"
        )

        mono = "Consolas" if self.system.os_type == OSType.WINDOWS else "monospace"
        self._log_textbox = ctk.CTkTextbox(
            frame, state="disabled", font=ctk.CTkFont(family=mono, size=11)
        )
        self._log_textbox.grid(row=1, column=0, sticky="nsew", pady=(4, 0))
        self._log_textbox.bind("<Control-c>", self._copy_log_event)
        self._log_textbox.bind("<Control-C>", self._copy_log_event)

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
                "wg_name": "name",
                "wg_private_key": "wg_private_key",
                "wg_address": "wg_address",
                "wg_dns": "wg_dns",
                "wg_public_key": "wg_public_key",
                "wg_preshared_key": "wg_preshared_key",
                "wg_endpoint": "wg_endpoint",
                "wg_allowed_ips": "wg_allowed_ips",
                "wg_keepalive": "wg_keepalive",
            }
            for ui_key, data_key in field_map.items():
                if ui_key in self._wg_entries:
                    self._wg_entries[ui_key].delete(0, "end")
                    self._wg_entries[ui_key].insert(0, data.get(data_key, ""))

        elif proto == Protocol.OPENVPN.value:
            field_map = {
                "ovpn_name": "name",
                "ovpn_remote": "ovpn_remote",
                "ovpn_port": "ovpn_port",
                "ovpn_proto": "ovpn_proto",
                "ovpn_dev": "ovpn_dev",
                "ovpn_cipher": "ovpn_cipher",
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
                "ssh_name": "name",
                "ssh_host": "ssh_host",
                "ssh_port": "ssh_port",
                "ssh_user": "ssh_user",
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

        path = filedialog.askopenfilename(
            title="Import Configuration", filetypes=filetypes
        )
        if not path:
            return

        src = Path(path)
        # Auto-create a profile for it
        name = src.stem
        if proto == Protocol.WIREGUARD:
            data: dict[str, Any] = {
                "protocol": proto.value,
                "name": name,
            }
            # Parse .conf file and merge parsed fields
            parsed = self.profile_mgr.parse_wireguard_conf(src)
            data.update(parsed)
        elif proto == Protocol.OPENVPN:
            data = {
                "protocol": proto.value,
                "name": name,
            }
            # Parse .ovpn file and merge parsed fields
            parsed = self.profile_mgr.parse_openvpn_conf(src)
            data.update(parsed)
        else:
            # SSH — import key
            dest = self.settings.configs_dir / src.name
            shutil.copy2(src, dest)
            _set_app_file_owner(dest)
            self._ssh_key_path = dest
            self._ssh_key_label.configure(text=dest.name)
            logger.info("SSH key imported: %s -> %s", src, dest)
            return

        logger.info("Imported config fields from: %s", src)

        self.profile_mgr.save_profile(name, data)
        self.settings.last_profile = name
        self._load_profile_list()
        self._profile_var.set(name)
        # Populate editor fields with imported data
        self._on_profile_select(name)

    def _import_ssh_key(self) -> None:
        path = filedialog.askopenfilename(
            title="Select SSH Key",
            filetypes=[("PEM Key", "*.pem"), ("All Files", "*.*")],
        )
        if path:
            self._ssh_key_path = Path(path)
            self._ssh_key_label.configure(text=Path(path).name)
            logger.info("SSH key selected: %s", path)

    def _change_configs_dir(self) -> None:
        d = filedialog.askdirectory(
            title="Select Configs Folder", initialdir=str(self.settings.configs_dir)
        )
        if d:
            self.settings.configs_dir = Path(d)
            self._configs_dir_label.configure(text=d)
            self._load_profile_list()
            logger.info("Configs directory changed to: %s", d)

    def _export_profile(self) -> None:
        """Export current profile as JSON into the configured configs directory."""
        name = self._profile_var.get()
        if name == "(new profile)":
            messagebox.showerror("Error", "Select or create a profile first.")
            return

        data = self.profile_mgr.load_profile(name)
        if not data:
            messagebox.showerror("Error", "Could not load profile.")
            return

        try:
            self.settings.configs_dir.mkdir(parents=True, exist_ok=True)
            safe_name = re.sub(r"[^\w\-. ]", "_", name)
            export_path = self.settings.configs_dir / f"{safe_name}.export.json"
            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            _set_app_file_owner(export_path)
            messagebox.showinfo("Success", f"Profile exported to:\n{export_path}")
            logger.info("Profile '%s' exported to %s", name, export_path)
        except Exception as exc:
            logger.error("Export failed: %s", exc)
            messagebox.showerror("Export Error", f"Failed to export profile:\n{exc}")

    def _install_text_edit_shortcuts(self) -> None:
        """Enable consistent Ctrl+A and selection-delete behavior on editable fields."""

        def _walk(widget: Any) -> None:
            for child in widget.winfo_children():
                if isinstance(child, ctk.CTkEntry):
                    self._bind_entry_shortcuts(child)
                elif isinstance(child, ctk.CTkTextbox):
                    self._bind_textbox_shortcuts(child)
                _walk(child)

        _walk(self)

    def _bind_entry_shortcuts(self, entry: ctk.CTkEntry) -> None:
        targets = [entry]
        inner = getattr(entry, "_entry", None)
        if inner is not None:
            targets.append(inner)

        for target in targets:
            target.bind("<Control-a>", self._select_all_entry_event, add="+")
            target.bind("<Control-A>", self._select_all_entry_event, add="+")
            target.bind("<Delete>", self._delete_selected_entry_event, add="+")
            target.bind("<BackSpace>", self._delete_selected_entry_event, add="+")

    def _bind_textbox_shortcuts(self, textbox: ctk.CTkTextbox) -> None:
        targets = [textbox]
        inner = getattr(textbox, "_textbox", None)
        if inner is not None:
            targets.append(inner)

        for target in targets:
            target.bind("<Control-a>", self._select_all_text_event, add="+")
            target.bind("<Control-A>", self._select_all_text_event, add="+")
            target.bind("<Delete>", self._delete_selected_text_event, add="+")
            target.bind("<BackSpace>", self._delete_selected_text_event, add="+")

    def _select_all_entry_event(self, event: Any) -> str:
        widget = event.widget
        try:
            widget.select_range(0, "end")
            widget.icursor("end")
            return "break"
        except Exception:
            return "break"

    def _delete_selected_entry_event(self, event: Any) -> Optional[str]:
        widget = event.widget
        try:
            if widget.selection_present():
                widget.delete("sel.first", "sel.last")
                return "break"
        except Exception:
            pass
        return None

    def _select_all_text_event(self, event: Any) -> str:
        widget = event.widget
        try:
            widget.tag_add("sel", "1.0", "end-1c")
            widget.mark_set("insert", "end-1c")
            return "break"
        except Exception:
            return "break"

    def _delete_selected_text_event(self, event: Any) -> Optional[str]:
        widget = event.widget
        try:
            if widget.tag_ranges("sel"):
                widget.delete("sel.first", "sel.last")
                return "break"
        except TclError:
            return None
        except Exception:
            return None
        return None

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
                profile.ssh_port = int(
                    self._ssh_entries["ssh_port"].get().strip() or "22"
                )
            except ValueError:
                profile.ssh_port = 22
            try:
                profile.socks_port = int(
                    self._ssh_entries["ssh_socks_port"].get().strip() or "1080"
                )
            except ValueError:
                profile.socks_port = 1080
            profile.ssh_key_path = self._ssh_key_path

        return profile

    def _local_dependency_error(self, profile: ConnectionProfile) -> Optional[str]:
        """Return a user-facing dependency error for local machine prerequisites, if any."""
        if profile.protocol == Protocol.WIREGUARD:
            if self.system.os_type == OSType.LINUX:
                if not self.system.check_binary("wg-quick"):
                    return (
                        "WireGuard client is missing on your local machine.\n\n"
                        "Install it locally with:\n"
                        "  sudo apt install wireguard\n\n"
                        "Note: This is required on this PC, not on the droplet."
                    )
            elif self.system.os_type == OSType.WINDOWS:
                has_wg = (
                    self.system.check_binary("wireguard.exe")
                    or Path(r"C:\\Program Files\\WireGuard\\wireguard.exe").exists()
                )
                if not has_wg:
                    return (
                        "WireGuard client is missing on your local machine.\n\n"
                        "Install WireGuard for Windows from:\n"
                        "  https://www.wireguard.com/install/\n\n"
                        "Note: This is required on this PC, not on the droplet."
                    )

        if profile.protocol == Protocol.OPENVPN:
            if self.system.os_type == OSType.LINUX:
                if not self.system.check_binary("openvpn"):
                    return (
                        "OpenVPN client is missing on your local machine.\n\n"
                        "Install it locally with:\n"
                        "  sudo apt install openvpn\n\n"
                        "Note: This is required on this PC, not on the droplet."
                    )
            elif self.system.os_type == OSType.WINDOWS:
                has_ovpn = self.system.check_binary("openvpn")
                if not has_ovpn:
                    has_ovpn = any(
                        Path(p).exists()
                        for p in (
                            r"C:\\Program Files\\OpenVPN\\bin\\openvpn.exe",
                            r"C:\\Program Files (x86)\\OpenVPN\\bin\\openvpn.exe",
                        )
                    )
                if not has_ovpn:
                    return (
                        "OpenVPN client is missing on your local machine.\n\n"
                        "Install it from:\n"
                        "  https://openvpn.net/community-downloads/\n\n"
                        "Note: This is required on this PC, not on the droplet."
                    )

        if profile.protocol == Protocol.SSH_SOCKS5:
            if not self.system.check_binary("ssh"):
                if self.system.os_type == OSType.LINUX:
                    return (
                        "SSH client is missing on your local machine.\n\n"
                        "Install it locally with:\n"
                        "  sudo apt install openssh-client"
                    )
                if self.system.os_type == OSType.WINDOWS:
                    return (
                        "SSH client is missing on your local machine.\n\n"
                        "Enable OpenSSH Client from Windows optional features."
                    )
                return "SSH client is missing on your local machine."

        return None

    def _on_connect(self) -> None:
        profile = self._build_profile_from_current()

        dep_error = self._local_dependency_error(profile)
        if dep_error:
            if messagebox.askyesno(
                "Local Dependency Missing",
                dep_error + "\n\nInstall the missing prerequisites automatically now?",
            ):
                self._install_deps_btn.configure(state="disabled")
                self._install_deps_status_text.set("Installing missing prerequisites …")
                self._start_prereq_spinner("Installing required components")
                threading.Thread(
                    target=self._install_missing_local_dependencies_then_connect,
                    args=(profile,),
                    daemon=True,
                ).start()
            else:
                messagebox.showerror("Local Dependency Missing", dep_error)
            return

        if profile.protocol in (Protocol.WIREGUARD, Protocol.OPENVPN):
            if not profile.config_path or not profile.config_path.exists():
                messagebox.showerror(
                    "Error",
                    "No valid config. Fill in the fields and save, or import a file.",
                )
                return
        elif profile.protocol == Protocol.SSH_SOCKS5:
            if not profile.ssh_host:
                messagebox.showerror("Error", "SSH host is required.")
                return

        self._connect_btn.configure(state="disabled")
        self._protocol_menu.configure(state="disabled")
        self._update_state(TunnelState.CONNECTING)
        self._connect_start_time = time.time()

        threading.Thread(
            target=self._connect_worker, args=(profile,), daemon=True
        ).start()

    def _install_missing_local_dependencies_then_connect(
        self, profile: ConnectionProfile
    ) -> None:
        try:
            missing = self._missing_local_dependency_items()
            has_pkexec = shutil.which("pkexec") is not None
            has_winget = self.system.check_binary("winget") is not None
            commands = build_local_dependency_install_commands(
                self.system.os_type,
                missing,
                elevated=self.system.is_admin(),
                has_pkexec=has_pkexec,
                has_winget=has_winget,
            )

            if missing and not commands:
                raise RuntimeError(
                    "Automatic installation is not available in this environment."
                )

            for command in commands:
                self.system.run_cmd(command, timeout=600, check=True)

            self.after(0, self._stop_prereq_spinner)
            self.after(
                0,
                lambda: self._install_deps_status_text.set(
                    "Prerequisites installed successfully. Connecting …"
                ),
            )
            self.after(0, lambda: self._install_deps_btn.configure(state="normal"))
            self.after(0, self._refresh_prereq_notice)
            self.after(0, self._on_connect)
        except subprocess.TimeoutExpired:
            logger.error("Dependency install timed out")
            self.after(0, self._stop_prereq_spinner)
            self.after(
                0, lambda: self._install_deps_status_text.set("Install timed out.")
            )
            self.after(0, lambda: self._install_deps_btn.configure(state="normal"))
            self.after(0, self._refresh_prereq_notice)
            if self.system.os_type == OSType.WINDOWS:
                self.after(0, self._show_timeout_retry_dialog)
            else:
                self.after(
                    0,
                    lambda: messagebox.showerror(
                        "Install Failed", "Installation timed out. Please try again."
                    ),
                )
        except Exception as exc:
            logger.error("Dependency install failed: %s", exc)
            self.after(0, self._stop_prereq_spinner)
            self.after(0, lambda: self._install_deps_status_text.set("Install failed."))
            self.after(0, lambda: self._install_deps_btn.configure(state="normal"))
            self.after(0, self._refresh_prereq_notice)
            self.after(0, lambda e=str(exc): messagebox.showerror("Install Failed", e))

    def _connect_worker(self, profile: ConnectionProfile) -> None:
        try:
            self.tunnel = TunnelEngine.create(self.system, profile)
            self.tunnel.connect()

            if self._kill_switch_var.get():
                self.security.enable()

            self.reconnect_mgr = ReconnectManager(
                self.tunnel, on_state_change=self._on_reconnect_state
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
            self.after(
                0, lambda e=str(exc): messagebox.showerror("Connection Failed", e)
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
            TunnelState.DISCONNECTED: "#e74c3c",
            TunnelState.CONNECTING: "#f39c12",
            TunnelState.CONNECTED: "#2ecc71",
            TunnelState.RECONNECTING: "#f39c12",
            TunnelState.DISCONNECTING: "#f39c12",
            TunnelState.ERROR: "#e74c3c",
        }
        self._status_label.configure(
            text=f"● {state.value}", text_color=colors.get(state, "gray")
        )
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

    def _copy_log(self) -> None:
        """Copy selected activity log text; if nothing is selected, copy all log text."""
        selected = ""
        try:
            selected = self._log_textbox.get("sel.first", "sel.last").strip()
        except Exception:
            selected = ""

        text = selected or self._log_textbox.get("1.0", "end").strip()
        if not text:
            return

        self.clipboard_clear()
        self.clipboard_append(text)
        logger.info("Activity log copied to clipboard.")

    def _copy_log_event(self, _event: Any) -> str:
        """Handle Ctrl+C in the activity log textbox."""
        self._copy_log()
        return "break"

    def _set_prereq_notice_message(self, text: str, *, warning: bool = True) -> None:
        self._prereq_notice_text.set(text)
        self._prereq_notice_label.configure(
            text_color="#f39c12" if warning else "#2ecc71"
        )

    def _refresh_prereq_notice(self) -> None:
        missing = self._missing_local_dependency_items()
        if missing:
            text = "Warning: missing local components: " + ", ".join(missing) + "."
            self._set_prereq_notice_message(text, warning=True)
            self._prereq_notice_btn.configure(state="normal")
            self._prereq_notice_card.grid()
        else:
            self._stop_prereq_spinner()
            self._prereq_notice_card.grid_remove()

    def _start_prereq_spinner(self, text_prefix: str) -> None:
        self._stop_prereq_spinner()
        self._prereq_spinner_index = 0
        self._set_prereq_notice_message(f"{text_prefix} [|]", warning=True)
        self._prereq_notice_btn.configure(state="disabled")
        self._prereq_notice_card.grid()
        self._tick_prereq_spinner(text_prefix)

    def _tick_prereq_spinner(self, text_prefix: str) -> None:
        frames = ["|", "/", "-", "\\"]
        frame = frames[self._prereq_spinner_index % len(frames)]
        self._prereq_spinner_index += 1
        self._set_prereq_notice_message(f"{text_prefix} [{frame}]", warning=True)
        self._prereq_spinner_job = self.after(
            140, lambda: self._tick_prereq_spinner(text_prefix)
        )

    def _stop_prereq_spinner(self) -> None:
        if self._prereq_spinner_job:
            self.after_cancel(self._prereq_spinner_job)
            self._prereq_spinner_job = None

    def _missing_local_dependency_items(self) -> list[str]:
        missing: list[str] = []

        if self.system.os_type == OSType.LINUX:
            if not self.system.check_binary("wg-quick"):
                missing.append("WireGuard")
            if not self.system.check_binary("openvpn"):
                missing.append("OpenVPN")
            if not self.system.check_binary("ssh"):
                missing.append("OpenSSH Client")
            return missing

        if self.system.os_type == OSType.WINDOWS:
            has_wg = (
                self.system.check_binary("wireguard.exe")
                or Path(r"C:\Program Files\WireGuard\wireguard.exe").exists()
            )
            if not has_wg:
                missing.append("WireGuard")

            has_ovpn = self.system.check_binary("openvpn")
            if not has_ovpn:
                has_ovpn = any(
                    Path(p).exists()
                    for p in (
                        r"C:\Program Files\OpenVPN\bin\openvpn.exe",
                        r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
                    )
                )
            if not has_ovpn:
                missing.append("OpenVPN")

            if not self.system.check_binary("ssh"):
                missing.append("OpenSSH Client")

        return missing

    def _install_missing_local_dependencies(self) -> None:
        missing = self._missing_local_dependency_items()
        if not missing:
            self._install_deps_status_text.set(
                "All local prerequisites are already installed."
            )
            self._refresh_prereq_notice()
            messagebox.showinfo(
                "Prerequisites", "All local prerequisites are already installed."
            )
            return

        if self.system.os_type == OSType.WINDOWS and not self.system.is_admin():
            messagebox.showwarning(
                "Elevated Privileges Required",
                "Installing local prerequisites on Windows requires Administrator privileges.\n\n"
                "Please restart the app as Administrator and try again.",
            )
            return

        if (
            self.system.os_type == OSType.LINUX
            and not self.system.is_admin()
            and not shutil.which("pkexec")
        ):
            messagebox.showwarning(
                "Elevated Privileges Required",
                "Installing local prerequisites on Linux requires root privileges or pkexec.\n\n"
                "Please run the app with sudo -E or install pkexec.",
            )
            return

        self._install_deps_btn.configure(state="disabled")
        self._install_deps_status_text.set(f"Installing: {', '.join(missing)} …")
        self._start_prereq_spinner("Installing required components")
        threading.Thread(
            target=self._install_missing_local_dependencies_worker, daemon=True
        ).start()

    def _install_missing_local_dependencies_worker(self) -> None:
        try:
            missing = self._missing_local_dependency_items()
            has_pkexec = shutil.which("pkexec") is not None
            has_winget = self.system.check_binary("winget") is not None
            commands = build_local_dependency_install_commands(
                self.system.os_type,
                missing,
                elevated=self.system.is_admin(),
                has_pkexec=has_pkexec,
                has_winget=has_winget,
            )

            if missing and not commands:
                unsupported = [
                    item
                    for item in missing
                    if self.system.os_type == OSType.WINDOWS
                    and item in {"WireGuard", "OpenVPN"}
                    and not has_winget
                ]
                detail = (
                    "Automatic installation is not available for: "
                    + ", ".join(unsupported)
                    + ".\n\n"
                    "Install Winget or use the official installers, then try again."
                    if unsupported
                    else "No automatic install command could be built for the current environment."
                )
                raise RuntimeError(detail)

            for command in commands:
                self.system.run_cmd(command, timeout=600, check=True)

            self.after(0, self._stop_prereq_spinner)
            self.after(
                0,
                lambda: self._install_deps_status_text.set(
                    "Prerequisites installed successfully."
                ),
            )
            self.after(0, lambda: self._install_deps_btn.configure(state="normal"))
            self.after(0, self._refresh_prereq_notice)
            self.after(
                0,
                lambda: messagebox.showinfo(
                    "Prerequisites", "Local prerequisites were installed successfully."
                ),
            )
        except subprocess.TimeoutExpired:
            logger.error("Dependency install timed out")
            self.after(0, self._stop_prereq_spinner)
            self.after(
                0, lambda: self._install_deps_status_text.set("Install timed out.")
            )
            self.after(0, lambda: self._install_deps_btn.configure(state="normal"))
            self.after(0, self._refresh_prereq_notice)
            if self.system.os_type == OSType.WINDOWS:
                self.after(0, self._show_timeout_retry_dialog)
            else:
                self.after(
                    0,
                    lambda: messagebox.showerror(
                        "Install Failed", "Installation timed out. Please try again."
                    ),
                )
        except Exception as exc:
            logger.error("Dependency install failed: %s", exc)
            self.after(0, self._stop_prereq_spinner)
            self.after(0, lambda: self._install_deps_status_text.set("Install failed."))
            self.after(0, lambda: self._install_deps_btn.configure(state="normal"))
            self.after(0, self._refresh_prereq_notice)
            self.after(0, lambda e=str(exc): messagebox.showerror("Install Failed", e))

    def _show_timeout_retry_dialog(self) -> None:
        """Show Retry / Exit dialog after a Windows dependency install timeout."""
        result = messagebox.askretrycancel(
            "Install Timed Out",
            "Component installation timed out.\n\n"
            "Windows Update service may be slow or busy.\n"
            "Would you like to retry?",
        )
        if result:
            self._install_missing_local_dependencies()
        else:
            self.destroy()

    # -----------------------------------------------------------------------
    # Privilege Check
    # -----------------------------------------------------------------------

    def _check_privileges(self) -> None:
        if self.system.os_type == OSType.UNSUPPORTED:
            messagebox.showwarning(
                "Unsupported OS", "Only Windows 11 and Ubuntu 20.04 are supported."
            )
            return
        if self.system.os_type == OSType.LINUX and not self.system.is_admin():
            logger.warning("Running WITHOUT elevated privileges.")
            if messagebox.askyesno(
                "Elevated Privileges Required",
                "Admin/root privileges are needed for VPN tunnels and firewall rules.\n\n"
                "Restart with elevated privileges?",
            ):
                # On Linux, request_elevation() uses os.execvpe which replaces
                # the current process entirely — it never returns on success.
                # On Windows, it spawns a new elevated process and returns True.
                if self.system.request_elevation():
                    self.destroy()
                    sys.exit(0)
                else:
                    messagebox.showwarning(
                        "Elevation Failed",
                        "Could not obtain elevated privileges.\n"
                        "Some features may require manual authentication.",
                    )
            # Fallback: privileged commands request elevation at runtime.
            logger.info(
                "Privileged operations will request authentication at runtime (pkexec/sudo)."
            )

    def _repair_app_dir_permissions_if_needed(self) -> None:
        """Repair root-owned app data created by previous elevated runs."""
        try:
            app_dir = APP_DIR
            app_dir.mkdir(parents=True, exist_ok=True)

            configs_dir = app_dir / "configs"
            configs_dir.mkdir(parents=True, exist_ok=True)

            def _needs_write_fix(path: Path) -> bool:
                if path.exists():
                    if path.is_dir():
                        return not os.access(path, os.W_OK | os.X_OK)
                    return not os.access(path, os.W_OK)
                parent = path.parent
                return not os.access(parent, os.W_OK | os.X_OK)

            needs_fix = False
            for critical in (app_dir, configs_dir, SETTINGS_FILE):
                if _needs_write_fix(critical):
                    needs_fix = True
                    break

            if not needs_fix:
                # Catch stale root-owned files inside configs/settings trees.
                for p in app_dir.rglob("*"):
                    if p.exists() and not os.access(p, os.W_OK):
                        needs_fix = True
                        break

            if not needs_fix:
                return

            uid = os.getuid()
            gid = os.getgid()
            self.system.run_cmd(
                ["chown", "-R", f"{uid}:{gid}", str(app_dir)], timeout=60, check=True
            )
            logger.info("Fixed ownership for %s", app_dir)
        except Exception as exc:
            logger.warning("Could not auto-fix app directory ownership: %s", exc)

    # -----------------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------------

    def _on_close(self) -> None:
        logger.info("Shutting down …")
        try:
            self._stop_prereq_spinner()
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
