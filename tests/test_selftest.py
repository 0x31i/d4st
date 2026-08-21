from dastng.orchestrator.adapters.dalfox import parse_dalfox
from dastng.selftest import parse_guard, run_selftest, selftest_ok


def test_parse_guard_flags_unparsed_output():
    # big output but nothing parsed -> probable format mismatch
    assert parse_guard("dalfox", "x" * 500, 0) is not None
    assert "FORMAT MISMATCH" in parse_guard("dalfox", "x" * 500, 0)


def test_parse_guard_quiet_on_empty():
    assert parse_guard("dalfox", "", 0) is None
    assert parse_guard("dalfox", "   ", 0) is None


def test_parse_guard_flags_tool_error():
    assert "INCONCLUSIVE" in parse_guard("nuclei", "panic: nil pointer", 0, exit_code=2)
    assert "INCONCLUSIVE" in parse_guard("katana", "unknown flag: -zz", 0, exit_code=1)


def test_dalfox_parser_skips_meta_line():
    # dalfox v3: meta summary line + one real finding line
    v3 = ('{"meta":{"dalfox_version":"3.2.1","findings_count":1}}\n'
          '{"type":"V","cwe":"CWE-79","param":"q","data":"http://h/?q=x"}')
    out = parse_dalfox(v3)
    assert len(out) == 1 and out[0]["param"] == "q"   # meta NOT counted


def test_dalfox_parser_still_handles_v1_array_and_v2():
    assert len(parse_dalfox('[{"type":"V","param":"a"}]')) == 1
    assert len(parse_dalfox('{"findings":[{"type":"V","param":"b"}]}')) == 1


def test_selftest_runs_and_probes_pass():
    # canary self-test: our deterministic probes must all detect their canaries
    results = run_selftest()
    probe = [r for r in results if r.tool == "probe"]
    assert len(probe) == 4 and all(r.passed for r in probe), \
        [(r.check, r.detail) for r in probe if not r.passed]
    _ = selftest_ok
