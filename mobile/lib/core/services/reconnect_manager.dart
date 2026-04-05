import 'dart:async';
import '../models/connection_profile.dart';
import 'vpn_service.dart';

/// Monitors tunnel liveness and reconnects on unexpected drops.
/// Mirrors the desktop Python ReconnectManager logic:
///   - polls every 15 s
///   - exponential backoff: base 3 s, max 5 retries
class ReconnectManager {
  static const _heartbeat = Duration(seconds: 15);
  static const _baseDelay = Duration(seconds: 3);
  static const _maxRetries = 5;

  final VpnService _vpn;
  Timer? _timer;
  int _retries = 0;
  bool _running = false;

  ReconnectManager(this._vpn);

  void start() {
    if (_running) return;
    _running = true;
    _retries = 0;
    _timer = Timer.periodic(_heartbeat, (_) => _tick());
  }

  void stop() {
    _running = false;
    _timer?.cancel();
    _timer = null;
    _retries = 0;
  }

  Future<void> _tick() async {
    if (!_running) return;
    if (_vpn.state != TunnelState.connected) return;

    // Re-check state after a brief pause to avoid race conditions
    await Future<void>.delayed(const Duration(milliseconds: 200));
    if (_vpn.state == TunnelState.connected) {
      _retries = 0;
      return;
    }

    // Unexpected disconnect
    if (_retries >= _maxRetries) {
      stop();
      return;
    }

    _retries++;
    final delay = _baseDelay * (1 << (_retries - 1)); // 3, 6, 12, 24, 48 s
    await Future<void>.delayed(delay);

    final profile = _vpn.activeProfile;
    if (profile == null || !_running) return;

    try {
      await _vpn.connect(profile);
      _retries = 0;
    } catch (_) {
      // next tick will retry
    }
  }
}
