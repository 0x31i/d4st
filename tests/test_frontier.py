from dastng.orchestrator.frontier import Frontier, normalize_url


def test_normalize_dedup_by_param_names_not_values():
    a = normalize_url("https://X.test/App?id=1&q=a")
    b = normalize_url("https://x.test/App?id=99&q=b")
    assert a == b  # same param NAME set, different values -> same key
    assert a == "https://x.test/App?id&q"


def test_normalize_strips_fragment_and_defaults_path():
    assert normalize_url("http://h.test#frag") == "http://h.test/"


def test_frontier_dedups_urls():
    f = Frontier()
    assert f.add_url("https://h.test/a?x=1") is True
    assert f.add_url("https://h.test/a?x=2") is False  # dup by normalized key
    assert len(f.urls()) == 1
    # param names are harvested from the query
    assert ("https://h.test/a?x", "x") in f.params()


def test_convergence_stops_when_no_new_surface():
    f = Frontier(max_rounds=5)
    f.add_url("https://h.test/")
    f.begin_round()
    # nothing new added this round -> should not continue
    assert f.should_continue() is False


def test_convergence_records_cap_when_round_limit_hit():
    f = Frontier(max_rounds=1)
    f.begin_round()
    f.add_url("https://h.test/new")  # new surface, but round cap == 1
    assert f.should_continue() is False
    assert any("round cap" in c for c in f.caps)


def test_convergence_continues_with_new_surface_under_cap():
    f = Frontier(max_rounds=3)
    f.begin_round()
    f.add_url("https://h.test/new")
    assert f.should_continue() is True
