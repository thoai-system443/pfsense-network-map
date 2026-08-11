"""Data types produced by the parser and consumed by the engine.

Nothing here knows about XML. The engine imports only from this module, which
is what lets engine tests build configs by hand.
"""

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "warning", "error"]
# "match" is a real pfSense action used by floating shaper rules: it assigns a
# queue or limiter and lets evaluation continue, deciding nothing.
Action = Literal["pass", "block", "reject", "match"]
Direction = Literal["in", "out", "any"]
IpProtocol = Literal["inet", "inet6", "inet46"]
AliasType = Literal["host", "network", "port", "url", "urltable"]


class ParseWarning(BaseModel):
    path: str
    message: str
    severity: Severity = "warning"


class Interface(BaseModel):
    name: str
    descr: str
    if_: str
    ipaddr: str | None = None
    subnet: int | None = None
    enabled: bool = True
    is_vlan: bool = False
    vlan_tag: int | None = None
    parent_if: str | None = None


class Alias(BaseModel):
    name: str
    type: AliasType
    items: list[str] = Field(default_factory=list)
    descr: str = ""


class AddrSpec(BaseModel):
    any: bool = False
    network: str | None = None
    address: str | None = None
    not_: bool = False
    port: str | None = None


class FilterRule(BaseModel):
    seq: int
    interfaces: list[str] = Field(default_factory=list)
    floating: bool = False
    quick: bool = True
    direction: Direction = "in"
    action: Action = "pass"
    disabled: bool = False
    ipprotocol: IpProtocol = "inet"
    protocol: str = "any"
    source: AddrSpec = Field(default_factory=AddrSpec)
    destination: AddrSpec = Field(default_factory=AddrSpec)
    descr: str = ""
    tracker: str | None = None
    synthetic: bool = False


class PortForward(BaseModel):
    interface: str
    protocol: str = "any"
    destination: AddrSpec = Field(default_factory=AddrSpec)
    target: str = ""
    local_port: str | None = None
    disabled: bool = False
    descr: str = ""


class OneToOne(BaseModel):
    interface: str
    external: str
    internal: str
    disabled: bool = False
    descr: str = ""


class OutboundRule(BaseModel):
    interface: str
    source: str = ""
    destination: str = ""
    target: str = ""
    descr: str = ""


class NatConfig(BaseModel):
    port_forwards: list[PortForward] = Field(default_factory=list)
    one_to_one: list[OneToOne] = Field(default_factory=list)
    outbound: list[OutboundRule] = Field(default_factory=list)


class VpnTunnel(BaseModel):
    kind: Literal["openvpn-server", "openvpn-client", "ipsec-p2"]
    vpnid: str | None = None
    descr: str = ""
    interface_name: str | None = None
    tunnel_network: str | None = None
    remote_networks: list[str] = Field(default_factory=list)


class Gateway(BaseModel):
    name: str
    interface: str
    address: str
    default: bool = False
    disabled: bool = False
    descr: str = ""


class StaticRoute(BaseModel):
    network: str
    gateway: str
    disabled: bool = False
    descr: str = ""


class VpnConfig(BaseModel):
    tunnels: list[VpnTunnel] = Field(default_factory=list)


class ParsedConfig(BaseModel):
    version: str | None = None
    hostname: str = ""
    interfaces: list[Interface] = Field(default_factory=list)
    aliases: list[Alias] = Field(default_factory=list)
    rules: list[FilterRule] = Field(default_factory=list)
    nat: NatConfig = Field(default_factory=NatConfig)
    vpn: VpnConfig = Field(default_factory=VpnConfig)
    gateways: list[Gateway] = Field(default_factory=list)
    static_routes: list[StaticRoute] = Field(default_factory=list)
    warnings: list[ParseWarning] = Field(default_factory=list)

    def interface_by_name(self, name: str) -> Interface | None:
        return next((i for i in self.interfaces if i.name == name), None)

    def alias_by_name(self, name: str) -> Alias | None:
        return next((a for a in self.aliases if a.name == name), None)
