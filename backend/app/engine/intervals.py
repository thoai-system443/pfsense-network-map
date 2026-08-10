"""Set algebra on closed integer intervals.

Every function takes and returns a normalized list: sorted, disjoint, and with
adjacent intervals merged. Shared by IpSet and PortSet so the algebra lives in
exactly one place.
"""

Interval = tuple[int, int]


def normalize(items: list[Interval]) -> list[Interval]:
    ordered = sorted(i for i in items if i[0] <= i[1])
    merged: list[Interval] = []
    for lo, hi in ordered:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def union(a: list[Interval], b: list[Interval]) -> list[Interval]:
    return normalize(a + b)


def intersect(a: list[Interval], b: list[Interval]) -> list[Interval]:
    out: list[Interval] = []
    i = j = 0
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0])
        hi = min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def subtract(a: list[Interval], b: list[Interval]) -> list[Interval]:
    out: list[Interval] = []
    for lo, hi in a:
        cursor = lo
        for blo, bhi in b:
            if bhi < cursor or blo > hi:
                continue
            if blo > cursor:
                out.append((cursor, blo - 1))
            cursor = max(cursor, bhi + 1)
            if cursor > hi:
                break
        if cursor <= hi:
            out.append((cursor, hi))
    return normalize(out)
