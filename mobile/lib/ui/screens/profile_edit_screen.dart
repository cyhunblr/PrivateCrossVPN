import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/models/connection_profile.dart';
import '../../core/services/profile_manager.dart';

class ProfileEditScreen extends StatefulWidget {
  final String? profileName; // null = new profile

  const ProfileEditScreen({super.key, this.profileName});

  @override
  State<ProfileEditScreen> createState() => _ProfileEditScreenState();
}

class _ProfileEditScreenState extends State<ProfileEditScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  Protocol _protocol = Protocol.wireguard;
  bool _loading = true;

  // WireGuard controllers
  final _wgName = TextEditingController();
  final _wgPrivKey = TextEditingController();
  final _wgAddress = TextEditingController(text: '10.0.0.2/24');
  final _wgDns = TextEditingController(text: '1.1.1.1');
  final _wgPubKey = TextEditingController();
  final _wgPsk = TextEditingController();
  final _wgEndpoint = TextEditingController();
  final _wgAllowedIps = TextEditingController(text: '0.0.0.0/0, ::/0');
  final _wgKeepalive = TextEditingController(text: '25');

  // OpenVPN controllers
  final _ovpnName = TextEditingController();
  final _ovpnRemote = TextEditingController();
  final _ovpnPort = TextEditingController(text: '1194');
  final _ovpnProto = TextEditingController(text: 'udp');
  final _ovpnCipher = TextEditingController(text: 'AES-256-GCM');
  final _ovpnAuth = TextEditingController(text: 'SHA256');
  final _ovpnCa = TextEditingController();
  final _ovpnExtra = TextEditingController();

  // SSH controllers
  final _sshName = TextEditingController();
  final _sshHost = TextEditingController();
  final _sshPort = TextEditingController(text: '22');
  final _sshUser = TextEditingController(text: 'root');
  final _socksPort = TextEditingController(text: '1080');
  final _sshKeyPath = TextEditingController();

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 3, vsync: this);
    _load();
  }

  Future<void> _load() async {
    if (widget.profileName != null) {
      final p = await ProfileManager.instance.loadProfile(widget.profileName!);
      if (p != null) {
        _populate(p);
      }
    }
    setState(() => _loading = false);
  }

  void _populate(ConnectionProfile p) {
    switch (p) {
      case WireGuardProfile wg:
        _protocol = Protocol.wireguard;
        _tabs.index = 0;
        _wgName.text = wg.name;
        _wgPrivKey.text = wg.privateKey;
        _wgAddress.text = wg.address;
        _wgDns.text = wg.dns;
        _wgPubKey.text = wg.publicKey;
        _wgPsk.text = wg.presharedKey;
        _wgEndpoint.text = wg.endpoint;
        _wgAllowedIps.text = wg.allowedIps;
        _wgKeepalive.text = wg.keepalive;
      case OpenVPNProfile ov:
        _protocol = Protocol.openVPN;
        _tabs.index = 1;
        _ovpnName.text = ov.name;
        _ovpnRemote.text = ov.remote;
        _ovpnPort.text = ov.port;
        _ovpnProto.text = ov.proto;
        _ovpnCipher.text = ov.cipher;
        _ovpnAuth.text = ov.auth;
        _ovpnCa.text = ov.ca;
        _ovpnExtra.text = ov.extra;
      case SSHProfile ssh:
        _protocol = Protocol.sshSocks5;
        _tabs.index = 2;
        _sshName.text = ssh.name;
        _sshHost.text = ssh.host;
        _sshPort.text = ssh.port;
        _sshUser.text = ssh.user;
        _socksPort.text = ssh.socksPort;
        _sshKeyPath.text = ssh.keyPath ?? '';
    }
  }

  ConnectionProfile? _build() {
    switch (_protocol) {
      case Protocol.wireguard:
        if (_wgName.text.isEmpty ||
            _wgPrivKey.text.isEmpty ||
            _wgPubKey.text.isEmpty ||
            _wgEndpoint.text.isEmpty) {
          return null;
        }
        return WireGuardProfile(
          name: _wgName.text,
          privateKey: _wgPrivKey.text,
          address: _wgAddress.text,
          dns: _wgDns.text,
          publicKey: _wgPubKey.text,
          presharedKey: _wgPsk.text,
          endpoint: _wgEndpoint.text,
          allowedIps: _wgAllowedIps.text,
          keepalive: _wgKeepalive.text,
        );
      case Protocol.openVPN:
        if (_ovpnName.text.isEmpty || _ovpnRemote.text.isEmpty) {
          return null;
        }
        return OpenVPNProfile(
          name: _ovpnName.text,
          remote: _ovpnRemote.text,
          port: _ovpnPort.text,
          proto: _ovpnProto.text,
          cipher: _ovpnCipher.text,
          auth: _ovpnAuth.text,
          ca: _ovpnCa.text,
          extra: _ovpnExtra.text,
        );
      case Protocol.sshSocks5:
        if (_sshName.text.isEmpty || _sshHost.text.isEmpty) {
          return null;
        }
        return SSHProfile(
          name: _sshName.text,
          host: _sshHost.text,
          port: _sshPort.text,
          user: _sshUser.text,
          socksPort: _socksPort.text,
          keyPath: _sshKeyPath.text.isNotEmpty ? _sshKeyPath.text : null,
        );
    }
  }

  Future<void> _save() async {
    final profile = _build();
    if (profile == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Fill in the required fields')),
      );
      return;
    }
    await ProfileManager.instance.saveProfile(profile);
    if (mounted) {
      context.pop();
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }

    return Scaffold(
      appBar: AppBar(
        title:
            Text(widget.profileName == null ? 'New Profile' : 'Edit Profile'),
        actions: [
          TextButton(onPressed: _save, child: const Text('Save')),
        ],
        bottom: TabBar(
          controller: _tabs,
          onTap: (i) => setState(() => _protocol = Protocol.values[i]),
          tabs: const [
            Tab(text: 'WireGuard'),
            Tab(text: 'OpenVPN'),
            Tab(text: 'SSH'),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabs,
        children: [
          _WireGuardForm(
            name: _wgName,
            privateKey: _wgPrivKey,
            address: _wgAddress,
            dns: _wgDns,
            publicKey: _wgPubKey,
            psk: _wgPsk,
            endpoint: _wgEndpoint,
            allowedIps: _wgAllowedIps,
            keepalive: _wgKeepalive,
          ),
          _OpenVPNForm(
            name: _ovpnName,
            remote: _ovpnRemote,
            port: _ovpnPort,
            proto: _ovpnProto,
            cipher: _ovpnCipher,
            auth: _ovpnAuth,
            ca: _ovpnCa,
            extra: _ovpnExtra,
          ),
          _SSHForm(
            name: _sshName,
            host: _sshHost,
            port: _sshPort,
            user: _sshUser,
            socksPort: _socksPort,
            keyPath: _sshKeyPath,
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _tabs.dispose();
    for (final c in [
      _wgName,
      _wgPrivKey,
      _wgAddress,
      _wgDns,
      _wgPubKey,
      _wgPsk,
      _wgEndpoint,
      _wgAllowedIps,
      _wgKeepalive,
      _ovpnName,
      _ovpnRemote,
      _ovpnPort,
      _ovpnProto,
      _ovpnCipher,
      _ovpnAuth,
      _ovpnCa,
      _ovpnExtra,
      _sshName,
      _sshHost,
      _sshPort,
      _sshUser,
      _socksPort,
      _sshKeyPath,
    ]) {
      c.dispose();
    }
    super.dispose();
  }
}

// ---------------------------------------------------------------------------
// Form widgets

class _WireGuardForm extends StatelessWidget {
  final TextEditingController name,
      privateKey,
      address,
      dns,
      publicKey,
      psk,
      endpoint,
      allowedIps,
      keepalive;

  const _WireGuardForm({
    required this.name,
    required this.privateKey,
    required this.address,
    required this.dns,
    required this.publicKey,
    required this.psk,
    required this.endpoint,
    required this.allowedIps,
    required this.keepalive,
  });

  @override
  Widget build(BuildContext context) => _FormScroll(children: [
        _Field(label: 'Profile Name *', ctrl: name),
        _Field(label: 'Private Key *', ctrl: privateKey, obscure: true),
        _Field(label: 'Address *', ctrl: address, hint: '10.0.0.2/24'),
        _Field(label: 'DNS', ctrl: dns, hint: '1.1.1.1'),
        _Field(label: 'Server Public Key *', ctrl: publicKey),
        _Field(label: 'Preshared Key', ctrl: psk, obscure: true),
        _Field(
            label: 'Endpoint *', ctrl: endpoint, hint: 'vpn.example.com:51820'),
        _Field(label: 'Allowed IPs', ctrl: allowedIps),
        _Field(
            label: 'Persistent Keepalive (s)',
            ctrl: keepalive,
            keyboard: TextInputType.number),
      ]);
}

class _OpenVPNForm extends StatelessWidget {
  final TextEditingController name,
      remote,
      port,
      proto,
      cipher,
      auth,
      ca,
      extra;

  const _OpenVPNForm({
    required this.name,
    required this.remote,
    required this.port,
    required this.proto,
    required this.cipher,
    required this.auth,
    required this.ca,
    required this.extra,
  });

  @override
  Widget build(BuildContext context) => _FormScroll(children: [
        _Field(label: 'Profile Name *', ctrl: name),
        _Field(label: 'Remote Host *', ctrl: remote),
        _Field(label: 'Port', ctrl: port, keyboard: TextInputType.number),
        _Field(label: 'Protocol (udp/tcp)', ctrl: proto),
        _Field(label: 'Cipher', ctrl: cipher),
        _Field(label: 'Auth', ctrl: auth),
        _Field(label: 'CA Certificate', ctrl: ca, maxLines: 5),
        _Field(label: 'Extra directives', ctrl: extra, maxLines: 5),
      ]);
}

class _SSHForm extends StatelessWidget {
  final TextEditingController name, host, port, user, socksPort, keyPath;

  const _SSHForm({
    required this.name,
    required this.host,
    required this.port,
    required this.user,
    required this.socksPort,
    required this.keyPath,
  });

  @override
  Widget build(BuildContext context) => _FormScroll(children: [
        _Field(label: 'Profile Name *', ctrl: name),
        _Field(label: 'SSH Host *', ctrl: host),
        _Field(label: 'SSH Port', ctrl: port, keyboard: TextInputType.number),
        _Field(label: 'User', ctrl: user),
        _Field(
            label: 'SOCKS5 Local Port',
            ctrl: socksPort,
            keyboard: TextInputType.number),
        _Field(
            label: 'Private Key Path',
            ctrl: keyPath,
            hint: '/path/to/id_ed25519'),
      ]);
}

class _FormScroll extends StatelessWidget {
  final List<Widget> children;
  const _FormScroll({required this.children});

  @override
  Widget build(BuildContext context) => SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: children
              .map((w) => Padding(
                    padding: const EdgeInsets.only(bottom: 12),
                    child: w,
                  ))
              .toList(),
        ),
      );
}

class _Field extends StatelessWidget {
  final String label;
  final TextEditingController ctrl;
  final bool obscure;
  final String? hint;
  final int maxLines;
  final TextInputType? keyboard;

  const _Field({
    required this.label,
    required this.ctrl,
    this.obscure = false,
    this.hint,
    this.maxLines = 1,
    this.keyboard,
  });

  @override
  Widget build(BuildContext context) => TextField(
        controller: ctrl,
        obscureText: obscure,
        maxLines: obscure ? 1 : maxLines,
        keyboardType: keyboard,
        decoration: InputDecoration(
          labelText: label,
          hintText: hint,
          border: const OutlineInputBorder(),
        ),
      );
}
