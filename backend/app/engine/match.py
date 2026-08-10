"""Protocol and address-family matching.

Kept apart from evaluate.py so nat.py can use the same rules without importing
evaluate, which imports nat.
"""


def protocol_matches(rule_protocol: str, query_protocol: str) -> bool:
    if rule_protocol in {"any", ""} or query_protocol == "any":
        return True
    if rule_protocol == "tcp/udp":
        return query_protocol in {"tcp", "udp"}
    return rule_protocol == query_protocol


def family_matches(ipprotocol: str, family: int) -> bool:
    if ipprotocol == "inet46":
        return True
    return (ipprotocol == "inet") == (family == 4)
