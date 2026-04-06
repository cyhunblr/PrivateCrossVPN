import 'dart:convert';
import 'dart:io';
import 'package:path_provider/path_provider.dart';
import '../models/connection_profile.dart';

/// Manages VPN profiles stored as JSON files.
/// File format is compatible with the desktop Python app.
class ProfileManager {
  ProfileManager._();
  static final ProfileManager instance = ProfileManager._();

  Directory? _configsDir;

  Future<Directory> get configsDir async {
    if (_configsDir != null) return _configsDir!;
    final appDir = await getApplicationDocumentsDirectory();
    final dir = Directory('${appDir.path}/privatecrossvpn/configs');
    if (!dir.existsSync()) await dir.create(recursive: true);
    _configsDir = dir;
    return dir;
  }

  String _sanitizeName(String name) =>
      name.trim().replaceAll(RegExp(r'[^\w\-. ]'), '_');

  Future<File> _profileFile(String name) async {
    final dir = await configsDir;
    return File('${dir.path}/${_sanitizeName(name)}.json');
  }

  Future<List<String>> listProfiles() async {
    final dir = await configsDir;
    if (!dir.existsSync()) return [];
    return dir
        .listSync()
        .whereType<File>()
        .where((f) => f.path.endsWith('.json'))
        .map((f) => f.uri.pathSegments.last.replaceAll('.json', ''))
        .toList()
      ..sort();
  }

  Future<ConnectionProfile?> loadProfile(String name) async {
    final file = await _profileFile(name);
    if (!file.existsSync()) return null;
    try {
      final json = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
      return ConnectionProfile.fromJson(json);
    } catch (_) {
      return null;
    }
  }

  Future<void> saveProfile(ConnectionProfile profile) async {
    final file = await _profileFile(profile.name);
    file.writeAsStringSync(
      const JsonEncoder.withIndent('  ').convert(profile.toJson()),
      encoding: utf8,
    );
  }

  Future<bool> deleteProfile(String name) async {
    final file = await _profileFile(name);
    if (!file.existsSync()) return false;
    file.deleteSync();
    // Also remove generated conf/ovpn files if present
    final dir = await configsDir;
    for (final ext in ['.conf', '.ovpn']) {
      final extra = File('${dir.path}/${_sanitizeName(name)}$ext');
      if (extra.existsSync()) extra.deleteSync();
    }
    return true;
  }

  /// Imports a profile from an external file (.json, .conf, .ovpn).
  /// Returns the imported [ConnectionProfile] or null on failure.
  Future<ConnectionProfile?> importFromFile(String filePath) async {
    final file = File(filePath);
    if (!file.existsSync()) return null;

    final content = file.readAsStringSync(encoding: utf8);

    if (filePath.endsWith('.json')) {
      try {
        final json = jsonDecode(content) as Map<String, dynamic>;
        final profile = ConnectionProfile.fromJson(json);
        await saveProfile(profile);
        return profile;
      } catch (_) {
        return null;
      }
    }

    if (filePath.endsWith('.conf')) {
      final profileName = file.uri.pathSegments.last.replaceAll('.conf', '');
      return _importWireGuardConf(content, profileName);
    }

    return null;
  }

  Future<ConnectionProfile?> _importWireGuardConf(
      String conf, String name) async {
    String? privateKey,
        address,
        dns,
        publicKey,
        presharedKey,
        endpoint,
        allowedIps,
        keepalive;

    for (final line in conf.split('\n')) {
      final trimmed = line.trim();
      if (trimmed.startsWith('PrivateKey')) {
        privateKey = _iniValue(trimmed);
      }
      if (trimmed.startsWith('Address')) {
        address = _iniValue(trimmed);
      }
      if (trimmed.startsWith('DNS')) {
        dns = _iniValue(trimmed);
      }
      if (trimmed.startsWith('PublicKey')) {
        publicKey = _iniValue(trimmed);
      }
      if (trimmed.startsWith('PresharedKey')) {
        presharedKey = _iniValue(trimmed);
      }
      if (trimmed.startsWith('Endpoint')) {
        endpoint = _iniValue(trimmed);
      }
      if (trimmed.startsWith('AllowedIPs')) {
        allowedIps = _iniValue(trimmed);
      }
      if (trimmed.startsWith('PersistentKeepalive')) {
        keepalive = _iniValue(trimmed);
      }
    }

    if (privateKey == null ||
        address == null ||
        publicKey == null ||
        endpoint == null) {
      return null;
    }

    final WireGuardProfile profile = WireGuardProfile(
      name: name,
      privateKey: privateKey,
      address: address,
      dns: dns ?? '1.1.1.1',
      publicKey: publicKey,
      presharedKey: presharedKey ?? '',
      endpoint: endpoint,
      allowedIps: allowedIps ?? '0.0.0.0/0, ::/0',
      keepalive: keepalive ?? '25',
    );
    await saveProfile(profile);
    return profile;
  }

  String _iniValue(String line) {
    final idx = line.indexOf('=');
    if (idx < 0) {
      return '';
    }
    return line.substring(idx + 1).trim();
  }

  /// Writes a WireGuard .conf file next to the profile JSON.
  Future<String> writeWireGuardConf(WireGuardProfile profile) async {
    final dir = await configsDir;
    final path = '${dir.path}/${_sanitizeName(profile.name)}.conf';
    File(path).writeAsStringSync(profile.toWireGuardConf(), encoding: utf8);
    return path;
  }
}
