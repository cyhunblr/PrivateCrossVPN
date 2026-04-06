import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../../core/models/connection_profile.dart';
import '../../core/models/ip_info.dart';
import '../../core/services/ip_info_service.dart';
import '../../core/services/profile_manager.dart';
import '../../core/services/reconnect_manager.dart';
import '../../core/services/vpn_service.dart';

// ---------------------------------------------------------------------------
// Providers

final profilesProvider = FutureProvider<List<String>>(
  (_) => ProfileManager.instance.listProfiles(),
);

final selectedProfileProvider = StateProvider<String?>((ref) => null);

final vpnStateProvider = StreamProvider<TunnelState>(
  (_) => VpnService.instance.stateStream,
);

final ipInfoProvider = FutureProvider<IpInfo?>(
  (_) => IpInfoService.instance.fetch(forceRefresh: true),
);

// ---------------------------------------------------------------------------

class HomeScreen extends ConsumerStatefulWidget {
  const HomeScreen({super.key});

  @override
  ConsumerState<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends ConsumerState<HomeScreen> {
  late final ReconnectManager _reconnect;
  static const _locationRefreshAttempts = 8;
  String? _preConnectIp;
  bool _locationSyncInProgress = false;
  bool _locationSynced = true;

  @override
  void initState() {
    super.initState();
    _reconnect = ReconnectManager(VpnService.instance);
  }

  @override
  void dispose() {
    _reconnect.stop();
    super.dispose();
  }

  Future<void> _toggleConnection() async {
    final vpn = VpnService.instance;
    if (vpn.state == TunnelState.connected) {
      _reconnect.stop();
      await vpn.disconnect();
      IpInfoService.instance.clearCache();
      if (mounted) {
        setState(() {
          _preConnectIp = null;
          _locationSyncInProgress = false;
          _locationSynced = true;
        });
      }
      ref.invalidate(ipInfoProvider);
      return;
    }

    final profileName = ref.read(selectedProfileProvider);
    if (profileName == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Select a profile first')),
      );
      return;
    }

    final profile = await ProfileManager.instance.loadProfile(profileName);
    if (profile == null) {
      return;
    }

    try {
      final oldIp = (await IpInfoService.instance.fetch())?.ip;
      if (mounted) {
        setState(() {
          _preConnectIp = oldIp;
          _locationSyncInProgress = true;
          _locationSynced = false;
        });
      }
      await vpn.connect(profile);
      _reconnect.start();
      await _refreshConnectedLocation(oldIp);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Connection failed: $e')),
        );
      }
    }
  }

  Future<void> _refreshConnectedLocation(String? previousIp) async {
    for (int attempt = 0; attempt < _locationRefreshAttempts; attempt++) {
      if (attempt > 0) {
        await Future<void>.delayed(const Duration(seconds: 1));
      }
      final refreshed = await IpInfoService.instance.fetch(forceRefresh: true);
      if (refreshed == null) {
        continue;
      }
      if (previousIp == null || refreshed.ip != previousIp) {
        if (mounted) {
          setState(() {
            _locationSynced = true;
            _locationSyncInProgress = false;
          });
        }
        ref.invalidate(ipInfoProvider);
        return;
      }
    }

    if (mounted) {
      setState(() {
        _locationSyncInProgress = false;
      });
    }
    // Even if IP did not change, refresh UI with the latest available info.
    ref.invalidate(ipInfoProvider);
  }

  Widget _buildLocationSyncStatus() {
    return Row(
      children: const [
        SizedBox(
          height: 14,
          width: 14,
          child: CircularProgressIndicator(
            color: Colors.white,
            strokeWidth: 2,
          ),
        ),
        SizedBox(width: 8),
        Expanded(
          child: Text(
            'Updating tunnel location...',
            style: TextStyle(color: Colors.white70),
          ),
        ),
      ],
    );
  }

  String? _activeRemoteServer() {
    final profile = VpnService.instance.activeProfile;
    if (profile == null) {
      return null;
    }
    if (profile is WireGuardProfile) {
      return profile.endpoint;
    }
    if (profile is OpenVPNProfile) {
      return '${profile.remote}:${profile.port}';
    }
    if (profile is SSHProfile) {
      return '${profile.host}:${profile.port}';
    }
    return null;
  }

  Future<void> _importProfile() async {
    final picked = await FilePicker.platform.pickFiles(
      allowMultiple: false,
      type: FileType.custom,
      allowedExtensions: ['conf', 'json'],
    );

    final path = picked?.files.single.path;
    if (path == null || path.isEmpty) {
      return;
    }

    final imported = await ProfileManager.instance.importFromFile(path);
    if (!mounted) {
      return;
    }

    if (imported == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Profile import failed')),
      );
      return;
    }

    ref.read(selectedProfileProvider.notifier).state = imported.name;
    ref.invalidate(profilesProvider);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Imported profile: ${imported.name}')),
    );
  }

  @override
  Widget build(BuildContext context) {
    final profiles = ref.watch(profilesProvider);
    final selected = ref.watch(selectedProfileProvider);
    final vpnState = ref.watch(vpnStateProvider);
    final ipInfo = ref.watch(ipInfoProvider);

    final isConnected = vpnState.valueOrNull == TunnelState.connected;
    final isConnecting = vpnState.valueOrNull == TunnelState.connecting ||
        vpnState.valueOrNull == TunnelState.disconnecting;
    final remoteServer = _activeRemoteServer();

    return Scaffold(
      appBar: AppBar(
        title: const Text('PrivateCrossVPN'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () => context.push('/settings'),
          ),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              color: isConnected ? Colors.green[800] : Colors.grey[850],
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(
                          isConnected ? Icons.lock : Icons.lock_open,
                          color: Colors.white,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          isConnected ? 'Connected' : 'Disconnected',
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                    if (isConnected) ...[
                      const SizedBox(height: 8),
                      if (remoteServer != null && remoteServer.isNotEmpty)
                        Text(
                          'Remote Server: $remoteServer',
                          style: const TextStyle(color: Colors.white70),
                        ),
                      if (remoteServer != null && remoteServer.isNotEmpty)
                        const SizedBox(height: 4),
                      ipInfo.when(
                        data: (info) => info != null
                            ? ((_locationSynced ||
                                    _preConnectIp == null ||
                                    info.ip != _preConnectIp)
                                ? Column(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        'IP: ${info.ip}',
                                        style: const TextStyle(
                                            color: Colors.white70),
                                      ),
                                      Text(
                                        'Location: ${info.location}',
                                        style: const TextStyle(
                                            color: Colors.white70),
                                      ),
                                      Text(
                                        'ISP: ${info.org}',
                                        style: const TextStyle(
                                            color: Colors.white70),
                                      ),
                                    ],
                                  )
                                : _buildLocationSyncStatus())
                            : (_locationSyncInProgress
                                ? _buildLocationSyncStatus()
                                : const SizedBox()),
                        loading: () => _buildLocationSyncStatus(),
                        error: (_, __) => const SizedBox(),
                      ),
                      _UptimeWidget(
                          connectedAt: VpnService.instance.connectedAt),
                    ],
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
            profiles.when(
              data: (list) {
                final current = list.contains(selected) ? selected : null;
                if (current != selected) {
                  WidgetsBinding.instance.addPostFrameCallback((_) {
                    ref.read(selectedProfileProvider.notifier).state = null;
                  });
                }

                return DropdownButtonFormField<String>(
                  // ignore: deprecated_member_use
                  value: current,
                  isExpanded: true,
                  decoration: const InputDecoration(
                    labelText: 'Profile',
                    border: OutlineInputBorder(),
                  ),
                  items: list
                      .map((n) => DropdownMenuItem(value: n, child: Text(n)))
                      .toList(),
                  onChanged: isConnected
                      ? null
                      : (v) =>
                          ref.read(selectedProfileProvider.notifier).state = v,
                );
              },
              loading: () => const LinearProgressIndicator(),
              error: (e, _) => Text('Error: $e'),
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    icon: const Icon(Icons.add),
                    label: const Text('New Profile'),
                    onPressed: () async {
                      await context.push('/profile/new');
                      ref.invalidate(profilesProvider);
                    },
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: OutlinedButton.icon(
                    icon: const Icon(Icons.upload_file),
                    label: const Text('Import .conf'),
                    onPressed: isConnected ? null : _importProfile,
                  ),
                ),
              ],
            ),
            if (selected != null) ...[
              const SizedBox(height: 8),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  IconButton(
                    icon: const Icon(Icons.edit),
                    onPressed: isConnected
                        ? null
                        : () async {
                            await context.push('/profile/edit/$selected');
                            ref.invalidate(profilesProvider);
                          },
                  ),
                  IconButton(
                    icon: const Icon(Icons.delete, color: Colors.red),
                    onPressed: isConnected
                        ? null
                        : () async {
                            final ok = await _confirmDelete(context, selected);
                            if (ok) {
                              await ProfileManager.instance
                                  .deleteProfile(selected);
                              ref.read(selectedProfileProvider.notifier).state =
                                  null;
                              ref.invalidate(profilesProvider);
                            }
                          },
                  ),
                ],
              ),
            ],
            const Spacer(),
            FilledButton(
              onPressed: isConnecting ? null : _toggleConnection,
              style: FilledButton.styleFrom(
                minimumSize: const Size.fromHeight(52),
                backgroundColor: isConnected ? Colors.red : Colors.blue,
              ),
              child: isConnecting
                  ? const SizedBox(
                      height: 20,
                      width: 20,
                      child: CircularProgressIndicator(
                        color: Colors.white,
                        strokeWidth: 2,
                      ),
                    )
                  : Text(
                      isConnected ? 'Disconnect' : 'Connect',
                      style: const TextStyle(fontSize: 16),
                    ),
            ),
          ],
        ),
      ),
    );
  }

  Future<bool> _confirmDelete(BuildContext context, String name) async {
    return await showDialog<bool>(
          context: context,
          builder: (_) => AlertDialog(
            title: const Text('Delete Profile'),
            content: Text('Delete "$name"?'),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('Cancel'),
              ),
              TextButton(
                onPressed: () => Navigator.pop(context, true),
                child:
                    const Text('Delete', style: TextStyle(color: Colors.red)),
              ),
            ],
          ),
        ) ??
        false;
  }
}

class _UptimeWidget extends StatefulWidget {
  final DateTime? connectedAt;
  const _UptimeWidget({this.connectedAt});

  @override
  State<_UptimeWidget> createState() => _UptimeWidgetState();
}

class _UptimeWidgetState extends State<_UptimeWidget> {
  late final Stream<String> _stream;

  @override
  void initState() {
    super.initState();
    _stream = Stream.periodic(const Duration(seconds: 1), (_) {
      if (widget.connectedAt == null) {
        return '00:00:00';
      }
      final diff = DateTime.now().difference(widget.connectedAt!);
      final h = diff.inHours.toString().padLeft(2, '0');
      final m = (diff.inMinutes % 60).toString().padLeft(2, '0');
      final s = (diff.inSeconds % 60).toString().padLeft(2, '0');
      return '$h:$m:$s';
    });
  }

  @override
  Widget build(BuildContext context) => StreamBuilder<String>(
        stream: _stream,
        initialData: '00:00:00',
        builder: (_, snap) => Text(
          'Uptime: ${snap.data}',
          style: const TextStyle(color: Colors.white70),
        ),
      );
}
