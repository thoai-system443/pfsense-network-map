# File-sync tools drop byte-identical copies next to the originals
# ("test_ipset.py" -> "test_ipset 2.py"). Collecting them doubles the reported
# test count without testing anything new, which makes the number meaningless.
collect_ignore_glob = ["* [0-9].py"]
