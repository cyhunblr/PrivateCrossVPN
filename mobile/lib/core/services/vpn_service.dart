import 'dart:async';
import 'dart:io';
import 'package:flutter/services.dart';
import 'package:wireguard_flutter/wireguard_flutter.dart';
import 'package:openvpn_flutter/openvpn_flutter.dart';
import 'package:dartssh2/dartssh2.dart';
import '../models/connection_profile.dart';

/// Central VPN service. Delegates to protocol-specific implementations.
class VpnService {
  VpnService._();
  static final VpnService instance = VpnService._();

  TunnelState _state = TunnelState.disconnected;
  TunnelState get state => _state;

  final _stateController = StreamController<TunnelState>.broadcast();
  Stream<TunnelState> get stateStream => _stateController.stream;

  ConnectionProfile? _activeProfile;
  ConnectionProfile? get activeProfile => _activeProfile;

  DateTime? _connectedAt;
  DateTime? get connectedAt => _connectedAt;

  bool killSwitch = false;

  // Protocol-specific handles
  final _wg = WireGuardFlutter.instance;
  OpenVPN? _ovpn;
  _SshHandle? _sshHandle;

  // -------------------------------------------------------------------------

  Future<void> connect(ConnectionProfile profile) async {
    if (_state == TunnelState.connected || _state == TunnelState.connecting) return;
    _setState(TunnelState.connecting);
    _activeProfile = profile;
    try {
      switch (profile) {
        case WireGuardProfile p:
          await _connectWireGuard(p);
        case OpenVPNProfile p:
          await _connectOpenVPN(p);
        case SSHProfile p:
          await _connectSSH(p);
      }
      _setState(TunnelState.connected);
      _connectedAt = DateTime.now();
    } on PlatformException {
      _setState(TunnelState.error);
      _activeProfile = null;
      rethrow;
    } catch (_) {
      _setState(TunnelState.error);
      _activeProfile = null;
      rethrow;
    }
  }

  Future<void> disconnect() async {
    if (_state == TunnelState.disconnected) return;
    _setState(TunnelState.disconnecting);
    try {
      switch (_activeProfile) {
        case WireGuardProfile _:
          await _wg.stopVpn();
        case OpenVPNProfile _:
          _ovpn?.disconnect();
          _ovpn = null;
        case SSHProfile _:
          await _sshHandle?.close();
          _sshHandle = null;
        case null:
          break;
      }
    } finally {
      _activeProfile = null;
      _connectedAt = null;
      _setState(TunnelState.disconnected);
    }
  }

  // -------------------------------------------------------------------------
  // WireGuard

  Future<void> _connectWireGuard(WireGuardProfile profile) async {
    await _wg.initialize(interfaceName: 'wg0');
    await _wg.startVpn(
      serverAddress: profile.endpoint.split(':').first,
      wgQuickConfig: profile.toWireGuardConf(),
      providerBundleIdentifier: 'com.privatecrossvpn.app.tunnel',
    );

    // Listen for unexpected drops
    _wg.vpnStageSnapshot.listen((stage) {
      if (stage == VpnStage.disconnected && _state == TunnelState.connected) {
        _setState(TunnelState.disconnected);
        _activeProfile = null;
        _connectedAt = null;
      }
    });
  }

  // -------------------------------------------------------------------------
  // OpenVPN

  Future<void> _connectOpenVPN(OpenVPNProfile profile) async {
    final completer = Completer<void>();

    _ovpn = OpenVPN(
      onVpnStatusChanged: (_) {},
      onVpnStageChanged: (stage, _) {
        if (stage == VPNStage.connected && !completer.isCompleted) {
          completer.complete();
        } else if (stage == VPNStage.error && !completer.isCompleted) {
          completer.completeError(Exception('OpenVPN connection error'));
        } else if (stage == VPNStage.disconnected && _state == TunnelState.connected) {
          _setState(TunnelState.disconnected);
          _activeProfile = null;
          _connectedAt = null;
        }
      },
    );

    _ovpn!.initialize(
      groupIdentifier: 'group.com.privatecrossvpn.app',
      providerBundleIdentifier: 'com.privatecrossvpn.app.tunnel',
      localizedDescription: 'PrivateCrossVPN',
    );

    // Build .ovpn config string
    final config = _buildOvpnConfig(profile);
    await _ovpn!.connect(config, profile.name, certIsRequired: profile.ca.isNotEmpty);

    // Wait up to 30 s for connected stage
    await completer.future.timeout(const Duration(seconds: 30));
  }

  String _buildOvpnConfig(OpenVPNProfile p) {
    final buf = StringBuffer()
      ..writeln('client')
      ..writeln('dev ${p.dev}')
      ..writeln('proto ${p.proto}')
      ..writeln('remote ${p.remote} ${p.port}')
      ..writeln('resolv-retry infinite')
      ..writeln('nobind')
      ..writeln('persist-key')
      ..writeln('persist-tun')
      ..writeln('cipher ${p.cipher}')
      ..writeln('auth ${p.auth}')
      ..writeln('verb 3');
    if (p.ca.isNotEmpty) {
      buf.writeln('<ca>');
      buf.writeln(p.ca);
      buf.writeln('</ca>');
    }
    if (p.extra.isNotEmpty) buf.writeln(p.extra);
    return buf.toString();
  }

  // -------------------------------------------------------------------------
  // SSH SOCKS5 (via dartssh2 — pure Dart, no subprocess)

  Future<void> _connectSSH(SSHProfile profile) async {
    final socket = await SSHSocket.connect(profile.host, int.parse(profile.port));
    final identities = await _loadIdentities(profile.keyPath);
    final client = SSHClient(
      socket,
      username: profile.user,
      identities: identities,
    );

    final forward = await client.forwardDynamic(
      bindHost: '127.0.0.1',
      bindPort: int.parse(profile.socksPort),
    );

    _sshHandle = _SshHandle(client: client, forward: forward);
  }

  Future<List<SSHKeyPair>> _loadIdentities(String? keyPath) async {
    if (keyPath == null || keyPath.isEmpty) return [];
    try {
      final pem = File(keyPath).readAsStringSync();
      return SSHKeyPair.fromPem(pem);
    } catch (_) {
      return [];
    }
  }

  // -------------------------------------------------------------------------

  void _setState(TunnelState s) {
    _state = s;
    _stateController.add(s);
  }

  void dispose() {
    _stateController.close();
  }
}

class _SshHandle {
  final SSHClient client;
  final SSHDynamicForward forward;

  _SshHandle({required this.client, required this.forward});

  Future<void> close() async {
    forward.close();
    client.close();
    await client.done;
  }
}
