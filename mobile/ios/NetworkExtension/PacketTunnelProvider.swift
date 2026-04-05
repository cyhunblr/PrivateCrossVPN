import NetworkExtension
import WireGuardKit

/// NEPacketTunnelProvider subclass for WireGuard tunnels.
/// This runs in a separate process (NetworkExtension target).
/// Bundle ID: com.privatecrossvpn.app.tunnel
class PacketTunnelProvider: NEPacketTunnelProvider {

    private var adapter: WireGuardAdapter?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard
            let proto = protocolConfiguration as? NETunnelProviderProtocol,
            let conf = proto.providerConfiguration,
            let wgConf = conf["wg_conf"] as? String
        else {
            completionHandler(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            return
        }

        let tunnelAdapter = WireGuardAdapter(with: self) { _, message in
            NSLog("WireGuard: \(message)")
        }
        adapter = tunnelAdapter

        tunnelAdapter.start(tunnelConfiguration: try! TunnelConfiguration(fromWgQuickConfig: wgConf)) { error in
            completionHandler(error)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        adapter?.stop { error in
            if let error = error {
                NSLog("WireGuard stop error: \(error)")
            }
            completionHandler()
        }
    }
}

enum PacketTunnelProviderError: String, Error {
    case savedProtocolConfigurationIsInvalid
}
