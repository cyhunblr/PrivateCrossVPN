from __future__ import annotations

import importlib
import logging
import sys
from types import SimpleNamespace
from pathlib import Path


def load_module(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    logging.getLogger("PrivateCrossVPN").handlers.clear()
    sys.modules.pop("privatecrossvpn", None)
    return importlib.import_module("privatecrossvpn")


def test_profile_manager_save_load_and_generate_configs(monkeypatch, tmp_path):
    module = load_module(monkeypatch, tmp_path)

    settings = module.AppSettings()
    settings.configs_dir = tmp_path / "configs"
    manager = module.ProfileManager(settings)

    profile_data = {
        "protocol": "WireGuard",
        "wg_private_key": "private-key",
        "wg_address": "10.0.0.2/24",
        "wg_dns": "1.1.1.1",
        "wg_public_key": "public-key",
        "wg_endpoint": "vpn.example.com:51820",
        "wg_allowed_ips": "0.0.0.0/0, ::/0",
        "wg_keepalive": "25",
    }

    saved_path = manager.save_profile("demo/team-vpn", profile_data)
    assert saved_path.name == "demo_team-vpn.json"
    assert manager.load_profile("demo_team-vpn") == profile_data

    wg_conf = manager.generate_wireguard_conf("demo/team-vpn", profile_data)
    wg_text = wg_conf.read_text(encoding="utf-8")
    assert "[Interface]" in wg_text
    assert "PrivateKey = private-key" in wg_text
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in wg_text

    ovpn_data = {
        "ovpn_dev": "tun",
        "ovpn_proto": "udp",
        "ovpn_remote": "vpn.example.com",
        "ovpn_port": "1194",
        "ovpn_cipher": "AES-256-GCM",
        "ovpn_auth": "SHA256",
        "ovpn_ca": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
        "ovpn_extra": "remote-cert-tls server",
    }
    ovpn_conf = manager.generate_openvpn_conf("demo/team-vpn", ovpn_data)
    ovpn_text = ovpn_conf.read_text(encoding="utf-8")
    assert "client" in ovpn_text
    assert "remote vpn.example.com 1194" in ovpn_text
    assert "<ca>" in ovpn_text
    assert "remote-cert-tls server" in ovpn_text


def test_system_handler_detects_known_platforms(monkeypatch, tmp_path):
    module = load_module(monkeypatch, tmp_path)

    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    assert module.SystemHandler._detect_os() == module.OSType.WINDOWS

    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    assert module.SystemHandler._detect_os() == module.OSType.LINUX

    monkeypatch.setattr(module.platform, "system", lambda: "Darwin")
    assert module.SystemHandler._detect_os() == module.OSType.UNSUPPORTED


def test_tunnel_engine_maps_protocol_to_tunnel_class(monkeypatch, tmp_path):
    module = load_module(monkeypatch, tmp_path)

    system = SimpleNamespace(os_type=module.OSType.LINUX)

    wireguard = module.ConnectionProfile(protocol=module.Protocol.WIREGUARD)
    openvpn = module.ConnectionProfile(protocol=module.Protocol.OPENVPN)
    ssh = module.ConnectionProfile(protocol=module.Protocol.SSH_SOCKS5)

    assert isinstance(
        module.TunnelEngine.create(system, wireguard),
        module.WireGuardTunnel,
    )
    assert isinstance(
        module.TunnelEngine.create(system, openvpn),
        module.OpenVPNTunnel,
    )
    assert isinstance(
        module.TunnelEngine.create(system, ssh),
        module.SSHTunnel,
    )


def test_build_ssh_login_command_quotes_key_path(monkeypatch, tmp_path):
    module = load_module(monkeypatch, tmp_path)

    command = module.build_ssh_login_command(
        Path("/home/test/My Keys/vpn_key"),
        "203.0.113.10",
        "root",
        "22",
    )

    assert command == "ssh -i '/home/test/My Keys/vpn_key' -p 22 root@203.0.113.10"


def test_sanitize_wg_interface_name_enforces_linux_rules(monkeypatch, tmp_path):
    module = load_module(monkeypatch, tmp_path)

    assert (
        module.sanitize_wg_interface_name("digitalocean-wireguard") == "digitalocean_wi"
    )
    assert module.sanitize_wg_interface_name("demo/team-vpn") == "demo_team_vpn"


def test_generate_wireguard_conf_uses_compatible_filename(monkeypatch, tmp_path):
    module = load_module(monkeypatch, tmp_path)

    settings = module.AppSettings()
    settings.configs_dir = tmp_path / "configs"
    manager = module.ProfileManager(settings)

    conf = manager.generate_wireguard_conf(
        "digitalocean-wireguard",
        {
            "wg_private_key": "priv",
            "wg_address": "10.0.0.2/24",
            "wg_public_key": "pub",
            "wg_endpoint": "vpn.example.com:51820",
            "wg_allowed_ips": "0.0.0.0/0",
        },
    )

    assert conf.name == "digitalocean_wi.conf"


def test_strip_wireguard_dns_directives_removes_dns_lines(monkeypatch, tmp_path):
    module = load_module(monkeypatch, tmp_path)

    original = """[Interface]
PrivateKey = abc
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = def
AllowedIPs = 0.0.0.0/0
"""

    stripped = module.strip_wireguard_dns_directives(original)
    assert "DNS = 1.1.1.1" not in stripped
    assert "Address = 10.0.0.2/24" in stripped


def test_generate_wireguard_conf_sets_strict_permissions(monkeypatch, tmp_path):
    module = load_module(monkeypatch, tmp_path)

    settings = module.AppSettings()
    settings.configs_dir = tmp_path / "configs"
    manager = module.ProfileManager(settings)

    conf = manager.generate_wireguard_conf(
        "do-wg",
        {
            "wg_private_key": "priv",
            "wg_address": "10.0.0.2/24",
            "wg_public_key": "pub",
            "wg_endpoint": "vpn.example.com:51820",
            "wg_allowed_ips": "0.0.0.0/0",
        },
    )

    mode = conf.stat().st_mode & 0o777
    assert mode == 0o600


def test_build_local_dependency_install_commands_for_linux(monkeypatch, tmp_path):
    module = load_module(monkeypatch, tmp_path)

    commands = module.build_local_dependency_install_commands(
        module.OSType.LINUX,
        ["WireGuard", "OpenVPN", "OpenSSH Client"],
        elevated=True,
        has_pkexec=True,
        has_winget=False,
    )

    assert commands == [
        ["apt-get", "update"],
        ["apt-get", "install", "-y", "wireguard", "openvpn", "openssh-client"],
    ]


def test_build_local_dependency_install_commands_for_windows(monkeypatch, tmp_path):
    module = load_module(monkeypatch, tmp_path)

    commands = module.build_local_dependency_install_commands(
        module.OSType.WINDOWS,
        ["WireGuard", "OpenVPN", "OpenSSH Client"],
        elevated=True,
        has_pkexec=False,
        has_winget=True,
    )

    assert commands == [
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0",
        ],
        [
            "winget",
            "install",
            "-e",
            "--id",
            "WireGuard.WireGuard",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ],
        [
            "winget",
            "install",
            "-e",
            "--id",
            "OpenVPNTechnologies.OpenVPN",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ],
    ]


def test_parse_wireguard_conf_extracts_all_fields(monkeypatch, tmp_path):
    """Test that WireGuard .conf parser correctly extracts all configuration fields."""
    module = load_module(monkeypatch, tmp_path)

    settings = module.AppSettings()
    settings.configs_dir = tmp_path / "configs"
    manager = module.ProfileManager(settings)

    # Create a .conf file with all fields
    conf_content = """[Interface]
PrivateKey = WPJ0ecqJObjEcZhZqN9CTBP4Z0hT1I3t8W5qBJFfVWY=
Address = 10.0.0.2/24
DNS = 1.1.1.1, 8.8.8.8
ListenPort = 51820

[Peer]
PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
PresharedKey = EnlxN+OYoU4/9A3kNKxY5r/EsKQ4SbL0V1xLwybODkQ=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    conf_path = tmp_path / "configs" / "test.conf"
    conf_path.parent.mkdir(parents=True, exist_ok=True)
    conf_path.write_text(conf_content, encoding="utf-8")

    parsed = manager.parse_wireguard_conf(conf_path)

    assert parsed["wg_private_key"] == "WPJ0ecqJObjEcZhZqN9CTBP4Z0hT1I3t8W5qBJFfVWY="
    assert parsed["wg_address"] == "10.0.0.2/24"
    assert parsed["wg_dns"] == "1.1.1.1, 8.8.8.8"
    assert parsed["wg_listen_port"] == "51820"
    assert parsed["wg_public_key"] == "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
    assert parsed["wg_preshared_key"] == "EnlxN+OYoU4/9A3kNKxY5r/EsKQ4SbL0V1xLwybODkQ="
    assert parsed["wg_endpoint"] == "vpn.example.com:51820"
    assert parsed["wg_allowed_ips"] == "0.0.0.0/0, ::/0"
    assert parsed["wg_keepalive"] == "25"


def test_parse_openvpn_conf_extracts_all_fields(monkeypatch, tmp_path):
    """Test that OpenVPN .ovpn parser correctly extracts all configuration fields."""
    module = load_module(monkeypatch, tmp_path)

    settings = module.AppSettings()
    settings.configs_dir = tmp_path / "configs"
    manager = module.ProfileManager(settings)

    # Create an .ovpn file with all common fields
    ovpn_content = """client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
verb 3

<ca>
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJNbv6+DLg7oMA0GCSqGSIb3DQEBAQUAFDB7MQswCQYD
-----END CERTIFICATE-----
</ca>

remote-cert-tls server
script-security 2
"""
    ovpn_path = tmp_path / "configs" / "test.ovpn"
    ovpn_path.parent.mkdir(parents=True, exist_ok=True)
    ovpn_path.write_text(ovpn_content, encoding="utf-8")

    parsed = manager.parse_openvpn_conf(ovpn_path)

    assert parsed["ovpn_dev"] == "tun"
    assert parsed["ovpn_proto"] == "udp"
    assert parsed["ovpn_remote"] == "vpn.example.com"
    assert parsed["ovpn_port"] == "1194"
    assert parsed["ovpn_cipher"] == "AES-256-GCM"
    assert parsed["ovpn_auth"] == "SHA256"
    assert "BEGIN CERTIFICATE" in parsed.get("ovpn_ca", "")
    assert "remote-cert-tls server" in parsed.get("ovpn_extra", "")
