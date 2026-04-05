//
//  Generated file. Do not edit.
//

// clang-format off

#import "GeneratedPluginRegistrant.h"

#if __has_include(<flutter_secure_storage/FlutterSecureStoragePlugin.h>)
#import <flutter_secure_storage/FlutterSecureStoragePlugin.h>
#else
@import flutter_secure_storage;
#endif

#if __has_include(<openvpn_flutter/OpenVPNFlutterPlugin.h>)
#import <openvpn_flutter/OpenVPNFlutterPlugin.h>
#else
@import openvpn_flutter;
#endif

#if __has_include(<shared_preferences_foundation/SharedPreferencesPlugin.h>)
#import <shared_preferences_foundation/SharedPreferencesPlugin.h>
#else
@import shared_preferences_foundation;
#endif

#if __has_include(<wireguard_flutter/WireguardFlutterPlugin.h>)
#import <wireguard_flutter/WireguardFlutterPlugin.h>
#else
@import wireguard_flutter;
#endif

@implementation GeneratedPluginRegistrant

+ (void)registerWithRegistry:(NSObject<FlutterPluginRegistry>*)registry {
  [FlutterSecureStoragePlugin registerWithRegistrar:[registry registrarForPlugin:@"FlutterSecureStoragePlugin"]];
  [OpenVPNFlutterPlugin registerWithRegistrar:[registry registrarForPlugin:@"OpenVPNFlutterPlugin"]];
  [SharedPreferencesPlugin registerWithRegistrar:[registry registrarForPlugin:@"SharedPreferencesPlugin"]];
  [WireguardFlutterPlugin registerWithRegistrar:[registry registrarForPlugin:@"WireguardFlutterPlugin"]];
}

@end
