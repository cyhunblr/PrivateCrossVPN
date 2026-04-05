import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../../core/services/vpn_service.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool _killSwitch = false;

  @override
  void initState() {
    super.initState();
    _killSwitch = VpnService.instance.killSwitch;
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('Settings')),
        body: ListView(
          children: [
            SwitchListTile(
              title: const Text('Kill-Switch'),
              subtitle: const Text('Block traffic if VPN drops'),
              value: _killSwitch,
              onChanged: (v) {
                setState(() => _killSwitch = v);
                VpnService.instance.killSwitch = v;
                SharedPreferences.getInstance()
                    .then((p) => p.setBool('kill_switch', v));
              },
            ),
            const Divider(),
            ListTile(
              title: const Text('Version'),
              trailing: const Text('1.2.2'),
            ),
          ],
        ),
      );
}
