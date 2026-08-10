"""Parse <openvpn> and <ipsec>.

Filter rules attach to the pseudo-interfaces "openvpn" and "enc0", so every
tunnel records which pseudo-interface its rules live on.
"""

from app.parser.types import VpnConfig, VpnTunnel
from app.parser.xmlutil import WarningCollector, text_of

KNOWN_OPENVPN_CHILDREN = {"openvpn-server", "openvpn-client", "openvpn-csc"}


def _split_networks(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]


def parse_vpn(root, warnings: WarningCollector) -> VpnConfig:
    config = VpnConfig()

    section = root.find("openvpn")
    if section is not None:
        warnings.check_children(section, "pfsense/openvpn", KNOWN_OPENVPN_CHILDREN)
        for kind in ("openvpn-server", "openvpn-client"):
            for node in section.findall(kind):
                config.tunnels.append(
                    VpnTunnel(
                        kind=kind,
                        vpnid=text_of(node, "vpnid"),
                        descr=text_of(node, "description", "") or "",
                        interface_name="openvpn",
                        tunnel_network=text_of(node, "tunnel_network"),
                        remote_networks=_split_networks(text_of(node, "remote_network")),
                    )
                )

    ipsec = root.find("ipsec")
    if ipsec is not None:
        for node in ipsec.findall("phase2"):
            remote = node.find("remoteid")
            networks: list[str] = []
            if remote is not None:
                address = text_of(remote, "address")
                netbits = text_of(remote, "netbits")
                if address:
                    networks.append(f"{address}/{netbits}" if netbits else address)
            config.tunnels.append(
                VpnTunnel(
                    kind="ipsec-p2",
                    descr=text_of(node, "descr", "") or "",
                    interface_name="enc0",
                    remote_networks=networks,
                )
            )

    return config
