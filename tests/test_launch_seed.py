"""WorkflowRunner frontier seeding — lets `launch` inject SPA /api routes (JS-mined or via
--seed-url) so detection has real surface on client-rendered apps."""

from d4st.orchestrator.workflow import WorkflowRunner

_SPEC = {"name": "t", "max_rounds": 1, "stages": []}  # no tools: isolate seeding


def test_run_seeds_frontier_with_extra_urls():
    runner = WorkflowRunner(_SPEC, dry_run=True)
    res = runner.run("https://spa.test/",
                     seed_urls=["https://spa.test/api/Auth/Get/",
                                "https://spa.test/api/Users/List/"])
    # target + 2 unique seeds
    assert res.frontier_stats["urls"] == 3


def test_run_seed_dedups_and_ignores_blanks():
    runner = WorkflowRunner(_SPEC, dry_run=True)
    res = runner.run("https://spa.test/",
                     seed_urls=["https://spa.test/api/x", "https://spa.test/api/x", "", None])
    assert res.frontier_stats["urls"] == 2  # target + 1 unique


def test_run_without_seeds_unchanged():
    runner = WorkflowRunner(_SPEC, dry_run=True)
    res = runner.run("https://spa.test/")
    assert res.frontier_stats["urls"] == 1
