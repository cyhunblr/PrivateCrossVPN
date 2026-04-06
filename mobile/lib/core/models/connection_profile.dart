// JSON key names intentionally match the desktop Python app schema
// so that profile files are portable between desktop and mobile.

enum Protocol {
  wireguard('WireGuard'),
  openVPN('OpenVPN'),
  sshSocks5('SSH SOCKS5');

  const Protocol(this.value);
  final String value;

  static Protocol fromString(String v) =>
      Protocol.values.firstWhere((e) => e.value == v);
}

enum TunnelState { disconnected, connecting, connected, disconnecting, error }

// ---------------------------------------------------------------------------
// Sealed base — concrete types extend this directly

sealed class ConnectionProfile {
  String get name;
  Protocol get protocol;
  Map<String, dynamic> toJson();
  String? validate();

  static ConnectionProfile fromJson(Map<String, dynamic> j) {
    final proto = Protocol.fromString(j['protocol'] as String);
    return switch (proto) {
      Protocol.wireguard => WireGuardProfile.fromJson(j),
      Protocol.openVPN => OpenVPNProfile.fromJson(j),
      Protocol.sshSocks5 => SSHProfile.fromJson(j),
    };
  }
}

// ---------------------------------------------------------------------------
// WireGuard

final class WireGuardProfile extends ConnectionProfile {
  @override
  final String name;
  @override
  Protocol get protocol => Protocol.wireguard;

  final String privateKey;
  final String address;
  final String dns;
  final String publicKey;
  final String presharedKey;
  final String endpoint;
  final String allowedIps;
  final String keepalive;
  final String? configFile;

  WireGuardProfile({
    required this.name,
    required this.privateKey,
    required this.address,
    required this.dns,
    required this.publicKey,
    this.presharedKey = '',
    required this.endpoint,
    this.allowedIps = '0.0.0.0/0, ::/0',
    this.keepalive = '25',
    this.configFile,
  });

  factory WireGuardProfile.fromJson(Map<String, dynamic> j) => WireGuardProfile(
        name: j['name'] as String,
        privateKey: j['wg_private_key'] as String,
        address: j['wg_address'] as String,
        dns: j['wg_dns'] as String,
        publicKey: j['wg_public_key'] as String,
        presharedKey: (j['wg_preshared_key'] as String?) ?? '',
        endpoint: j['wg_endpoint'] as String,
        allowedIps: (j['wg_allowed_ips'] as String?) ?? '0.0.0.0/0, ::/0',
        keepalive: (j['wg_keepalive'] as String?) ?? '25',
        configFile: j['config_file'] as String?,
      );

  @override
  Map<String, dynamic> toJson() => {
        'protocol': protocol.value,
        'name': name,
        'wg_private_key': privateKey,
        'wg_address': address,
        'wg_dns': dns,
        'wg_public_key': publicKey,
        'wg_preshared_key': presharedKey,
        'wg_endpoint': endpoint,
        'wg_allowed_ips': allowedIps,
        'wg_keepalive': keepalive,
        if (configFile != null) 'config_file': configFile,
      };

  @override
  String? validate() {
    if (name.trim().isEmpty) {
      return 'Profile name is required';
    }
    if (privateKey.trim().isEmpty) {
      return 'WireGuard private key is required';
    }
    if (address.trim().isEmpty) {
      return 'WireGuard address is required';
    }
    if (publicKey.trim().isEmpty) {
      return 'WireGuard server public key is required';
    }
    if (endpoint.trim().isEmpty) {
      return 'WireGuard endpoint is required';
    }

    final endpointMatch = RegExp(r'^(?:\[[^\]]+\]|[^:]+):([0-9]{1,5})$')
        .firstMatch(endpoint.trim());
    if (endpointMatch == null) {
      return 'WireGuard endpoint must be host:port';
    }

    final port = int.tryParse(endpointMatch.group(1)!);
    if (port == null || port < 1 || port > 65535) {
      return 'WireGuard endpoint port must be between 1 and 65535';
    }

    return null;
  }

  /// Generates .conf file content compatible with wg-quick
  String toWireGuardConf() {
    final buf = StringBuffer()
      ..writeln('[Interface]')
      ..writeln('PrivateKey = $privateKey')
      ..writeln('Address = $address')
      ..writeln('DNS = $dns')
      ..writeln()
      ..writeln('[Peer]')
      ..writeln('PublicKey = $publicKey');
    if (presharedKey.isNotEmpty) buf.writeln('PresharedKey = $presharedKey');
    buf
      ..writeln('Endpoint = $endpoint')
      ..writeln('AllowedIPs = $allowedIps')
      ..writeln('PersistentKeepalive = $keepalive');
    return buf.toString();
  }

  WireGuardProfile copyWith({
    String? name,
    String? privateKey,
    String? address,
    String? dns,
    String? publicKey,
    String? presharedKey,
    String? endpoint,
    String? allowedIps,
    String? keepalive,
    String? configFile,
  }) =>
      WireGuardProfile(
        name: name ?? this.name,
        privateKey: privateKey ?? this.privateKey,
        address: address ?? this.address,
        dns: dns ?? this.dns,
        publicKey: publicKey ?? this.publicKey,
        presharedKey: presharedKey ?? this.presharedKey,
        endpoint: endpoint ?? this.endpoint,
        allowedIps: allowedIps ?? this.allowedIps,
        keepalive: keepalive ?? this.keepalive,
        configFile: configFile ?? this.configFile,
      );
}

// ---------------------------------------------------------------------------
// OpenVPN

final class OpenVPNProfile extends ConnectionProfile {
  @override
  final String name;
  @override
  Protocol get protocol => Protocol.openVPN;

  final String remote;
  final String port;
  final String proto;
  final String dev;
  final String cipher;
  final String auth;
  final String ca;
  final String extra;
  final String? configFile;

  OpenVPNProfile({
    required this.name,
    required this.remote,
    this.port = '1194',
    this.proto = 'udp',
    this.dev = 'tun',
    this.cipher = 'AES-256-GCM',
    this.auth = 'SHA256',
    this.ca = '',
    this.extra = '',
    this.configFile,
  });

  factory OpenVPNProfile.fromJson(Map<String, dynamic> j) => OpenVPNProfile(
        name: j['name'] as String,
        remote: j['ovpn_remote'] as String,
        port: (j['ovpn_port'] as String?) ?? '1194',
        proto: (j['ovpn_proto'] as String?) ?? 'udp',
        dev: (j['ovpn_dev'] as String?) ?? 'tun',
        cipher: (j['ovpn_cipher'] as String?) ?? 'AES-256-GCM',
        auth: (j['ovpn_auth'] as String?) ?? 'SHA256',
        ca: (j['ovpn_ca'] as String?) ?? '',
        extra: (j['ovpn_extra'] as String?) ?? '',
        configFile: j['config_file'] as String?,
      );

  @override
  Map<String, dynamic> toJson() => {
        'protocol': protocol.value,
        'name': name,
        'ovpn_remote': remote,
        'ovpn_port': port,
        'ovpn_proto': proto,
        'ovpn_dev': dev,
        'ovpn_cipher': cipher,
        'ovpn_auth': auth,
        'ovpn_ca': ca,
        'ovpn_extra': extra,
        if (configFile != null) 'config_file': configFile,
      };

  @override
  String? validate() {
    if (name.trim().isEmpty) {
      return 'Profile name is required';
    }
    if (remote.trim().isEmpty) {
      return 'OpenVPN remote host is required';
    }
    final portValue = int.tryParse(port);
    if (portValue == null || portValue < 1 || portValue > 65535) {
      return 'OpenVPN port must be between 1 and 65535';
    }
    if (proto.trim().isEmpty) {
      return 'OpenVPN protocol is required';
    }
    return null;
  }

  OpenVPNProfile copyWith({
    String? name,
    String? remote,
    String? port,
    String? proto,
    String? dev,
    String? cipher,
    String? auth,
    String? ca,
    String? extra,
    String? configFile,
  }) =>
      OpenVPNProfile(
        name: name ?? this.name,
        remote: remote ?? this.remote,
        port: port ?? this.port,
        proto: proto ?? this.proto,
        dev: dev ?? this.dev,
        cipher: cipher ?? this.cipher,
        auth: auth ?? this.auth,
        ca: ca ?? this.ca,
        extra: extra ?? this.extra,
        configFile: configFile ?? this.configFile,
      );
}

// ---------------------------------------------------------------------------
// SSH SOCKS5

final class SSHProfile extends ConnectionProfile {
  @override
  final String name;
  @override
  Protocol get protocol => Protocol.sshSocks5;

  final String host;
  final String port;
  final String user;
  final String socksPort;
  final String? keyPath;

  SSHProfile({
    required this.name,
    required this.host,
    this.port = '22',
    this.user = 'root',
    this.socksPort = '1080',
    this.keyPath,
  });

  factory SSHProfile.fromJson(Map<String, dynamic> j) => SSHProfile(
        name: j['name'] as String,
        host: j['ssh_host'] as String,
        port: (j['ssh_port'] as String?) ?? '22',
        user: (j['ssh_user'] as String?) ?? 'root',
        socksPort: (j['socks_port'] as String?) ?? '1080',
        keyPath: j['ssh_key_path'] as String?,
      );

  @override
  Map<String, dynamic> toJson() => {
        'protocol': protocol.value,
        'name': name,
        'ssh_host': host,
        'ssh_port': port,
        'ssh_user': user,
        'socks_port': socksPort,
        if (keyPath != null) 'ssh_key_path': keyPath,
      };

  @override
  String? validate() {
    if (name.trim().isEmpty) {
      return 'Profile name is required';
    }
    if (host.trim().isEmpty) {
      return 'SSH host is required';
    }
    final sshPort = int.tryParse(port);
    if (sshPort == null || sshPort < 1 || sshPort > 65535) {
      return 'SSH port must be between 1 and 65535';
    }
    final socks = int.tryParse(socksPort);
    if (socks == null || socks < 1 || socks > 65535) {
      return 'SOCKS5 port must be between 1 and 65535';
    }
    return null;
  }

  SSHProfile copyWith({
    String? name,
    String? host,
    String? port,
    String? user,
    String? socksPort,
    String? keyPath,
  }) =>
      SSHProfile(
        name: name ?? this.name,
        host: host ?? this.host,
        port: port ?? this.port,
        user: user ?? this.user,
        socksPort: socksPort ?? this.socksPort,
        keyPath: keyPath ?? this.keyPath,
      );
}
