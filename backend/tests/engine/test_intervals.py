from app.engine import intervals


def test_normalize_merges_touching_and_overlapping():
    assert intervals.normalize([(5, 9), (1, 4), (7, 12)]) == [(1, 12)]


def test_normalize_keeps_disjoint_apart():
    assert intervals.normalize([(1, 3), (5, 7)]) == [(1, 3), (5, 7)]


def test_union_merges_across_inputs():
    assert intervals.union([(1, 3)], [(4, 6)]) == [(1, 6)]


def test_intersect_keeps_only_overlap():
    assert intervals.intersect([(1, 10)], [(5, 20)]) == [(5, 10)]


def test_intersect_of_disjoint_is_empty():
    assert intervals.intersect([(1, 3)], [(5, 7)]) == []


def test_subtract_punches_hole_in_middle():
    assert intervals.subtract([(1, 10)], [(4, 6)]) == [(1, 3), (7, 10)]


def test_subtract_everything_gives_empty():
    assert intervals.subtract([(1, 10)], [(0, 20)]) == []


def test_subtract_result_no_longer_intersects_what_was_removed():
    remaining = intervals.subtract([(0, 100)], [(30, 40)])
    assert intervals.intersect(remaining, [(30, 40)]) == []
