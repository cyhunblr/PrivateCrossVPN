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

    assert module.sanitize_wg_interface_name("digitalocean-wireguard") == "digitalocean_wi"
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