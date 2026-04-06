import 'package:flutter_test/flutter_test.dart';
import 'package:privatecrossvpn/core/models/connection_profile.dart';

void main() {
  test('WireGuard profiles validate endpoint format and required fields', () {
    expect(
      WireGuardProfile(
        name: 'demo',
        privateKey: 'private-key',
        address: '10.0.0.2/24',
        dns: '1.1.1.1',
        publicKey: 'public-key',
        endpoint: 'vpn.example.com:51820',
      ).validate(),
      isNull,
    );

    expect(
      WireGuardProfile(
        name: 'demo',
        privateKey: 'private-key',
        address: '10.0.0.2/24',
        dns: '1.1.1.1',
        publicKey: 'public-key',
        endpoint: 'vpn.example.com',
      ).validate(),
      isNotNull,
    );
  });

  test('OpenVPN and SSH profiles validate numeric ports', () {
    expect(
      OpenVPNProfile(
        name: 'ovpn',
        remote: 'vpn.example.com',
        port: '1194',
      ).validate(),
      isNull,
    );

    expect(
      OpenVPNProfile(
        name: 'ovpn',
        remote: 'vpn.example.com',
        port: 'not-a-port',
      ).validate(),
      isNotNull,
    );

    expect(
      SSHProfile(
        name: 'ssh',
        host: '203.0.113.10',
        port: '22',
        socksPort: '1080',
      ).validate(),
      isNull,
    );

    expect(
      SSHProfile(
        name: 'ssh',
        host: '203.0.113.10',
        port: 'abc',
        socksPort: '1080',
      ).validate(),
      isNotNull,
    );
  });
}