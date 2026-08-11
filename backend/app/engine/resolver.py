"""Turn an AddrSpec into concrete address and port sets.

A spec can name an interface (its subnet), an interface address (lanip),
(self), a literal address or CIDR, or an alias. Aliases nest, so expansion is
recursive with an explicit visit set: a cycle raises instead of hanging.
"""

import ipaddress

from app.engine.ipset import IpSet
from app.engine.portset import PortSet
from app.parser.types import AddrSpec, ParsedConfig


class AliasCycleError(Exception):
    def __init__(self, chain: list[str]) -> None:
        self.chain = chain
        super().__init__(f"alias cycle: {' -> '.join(chain)}")


class Resolver:
    """Resolves an AddrSpec against one configuration.

    The caches matter: evaluating a ruleset asks for the same handful of
    interface subnets and aliases once per rule, and each miss re-parses a CIDR
    string. On a three thousand rule config that was the single hottest path in
    the whole engine.

    A Resolver is built per request and the config never changes underneath it,
    so caching for its lifetime is safe.
    """

    def __init__(self, config: ParsedConfig) -> None:
        self.config = config
        self._subnets: dict[tuple[str, int], IpSet] = {}
        self._ips: dict[tuple[str, int], IpSet] = {}
        self._selves: dict[int, IpSet] = {}
        self._aliases: dict[tuple[str, int], tuple[IpSet, bool]] = {}

    def interface_subnet(self, name: str, family: int) -> IpSet:
        key = (name, family)
        if key not in self._subnets:
            self._subnets[key] = self._compute_interface_subnet(name, family)
        return self._subnets[key]

    def _compute_interface_subnet(self, name: str, family: int) -> IpSet:
        iface = self.config.interface_by_name(name)
        if iface is None or not iface.ipaddr or iface.subnet is None:
            return IpSet.empty(family)
        try:
            network = ipaddress.ip_network(f"{iface.ipaddr}/{iface.subnet}", strict=False)
        except ValueError:
            return IpSet.empty(family)
        if network.version != family:
            return IpSet.empty(family)
        return IpSet.from_cidr(str(network))

    def interface_ip(self, name: str, family: int) -> IpSet:
        key = (name, family)
        if key not in self._ips:
            self._ips[key] = self._compute_interface_ip(name, family)
        return self._ips[key]

    def _compute_interface_ip(self, name: str, family: int) -> IpSet:
        iface = self.config.interface_by_name(name)
        if iface is None or not iface.ipaddr:
            return IpSet.empty(family)
        try:
            address = ipaddress.ip_address(iface.ipaddr)
        except ValueError:
            return IpSet.empty(family)
        if address.version != family:
            return IpSet.empty(family)
        return IpSet.from_cidr(str(address))

    def self_addresses(self, family: int) -> IpSet:
        if family not in self._selves:
            found = IpSet.empty(family)
            for iface in self.config.interfaces:
                found = found.union(self.interface_ip(iface.name, family))
            self._selves[family] = found
        return self._selves[family]

    def addresses(self, spec: AddrSpec, family: int) -> tuple[IpSet, bool]:
        found, unresolved = self._raw_addresses(spec, family)
        if spec.not_:
            found = found.complement()
        return found, unresolved

    def expand_alias(self, name: str, family: int) -> tuple[IpSet, bool]:
        return self._token_to_addresses(name, family, [])

    def expand_alias_ports(self, name: str) -> tuple[PortSet, bool]:
        return self._token_to_ports(name, [])

    def _raw_addresses(self, spec: AddrSpec, family: int) -> tuple[IpSet, bool]:
        if spec.any:
            return IpSet.full(family), False
        token = spec.network or spec.address
        if not token:
            return IpSet.full(family), False
        return self._token_to_addresses(token, family, [])

    def _token_to_addresses(self, token: str, family: int, chain: list[str]) -> tuple[IpSet, bool]:
        if token == "any":
            return IpSet.full(family), False
        if token == "(self)":
            return self.self_addresses(family), False

        if self.config.interface_by_name(token) is not None:
            return self.interface_subnet(token, family), False

        if token.endswith("ip") and self.config.interface_by_name(token[:-2]) is not None:
            return self.interface_ip(token[:-2], family), False

        alias = self.config.alias_by_name(token)
        if alias is not None:
            if token in chain:
                raise AliasCycleError([*chain, token])
            key = (token, family)
            if not chain and key in self._aliases:
                return self._aliases[key]
            if alias.type in {"url", "urltable"}:
                return IpSet.empty(family), True
            found = IpSet.empty(family)
            unresolved = False
            for member in alias.items:
                part, part_unresolved = self._token_to_addresses(member, family, [*chain, token])
                found = found.union(part)
                unresolved = unresolved or part_unresolved
            if not chain:
                self._aliases[key] = (found, unresolved)
            return found, unresolved

        try:
            literal = IpSet.from_cidr(token)
        except ValueError:
            return IpSet.empty(family), True
        if literal.family != family:
            return IpSet.empty(family), False
        return literal, False

    def ports(self, spec: AddrSpec) -> tuple[PortSet, bool]:
        if not spec.port:
            return PortSet.full(), False
        return self._token_to_ports(spec.port, [])

    def _token_to_ports(self, token: str, chain: list[str]) -> tuple[PortSet, bool]:
        alias = self.config.alias_by_name(token)
        if alias is not None:
            if token in chain:
                raise AliasCycleError([*chain, token])
            if alias.type in {"url", "urltable"}:
                return PortSet.empty(), True
            found = PortSet.empty()
            unresolved = False
            for member in alias.items:
                part, part_unresolved = self._token_to_ports(member, [*chain, token])
                found = found.union(part)
                unresolved = unresolved or part_unresolved
            return found, unresolved

        try:
            return PortSet.parse(token), False
        except ValueError:
            return PortSet.empty(), True
