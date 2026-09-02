import os

from d4st import updater


def test_manifest_stamp_and_age(tmp_path, monkeypatch):
    monkeypatch.setenv("D4ST_DATA_DIR", str(tmp_path))
    m = updater.Manifest()
    m.stamp("nuclei-templates", version="v10.1", source="pd")
    m.save()
    back = updater.Manifest.load()
    assert back.components["nuclei-templates"]["version"] == "v10.1"
    age = back.age_days("nuclei-templates")
    assert age is not None and age < 1.0


def test_age_none_when_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("D4ST_DATA_DIR", str(tmp_path))
    assert updater.Manifest().age_days("nope") is None


def test_freshness_flags_never_updated(tmp_path, monkeypatch):
    monkeypatch.setenv("D4ST_DATA_DIR", str(tmp_path))
    lines = updater.freshness_report()
    assert any("never updated" in ln for ln in lines)
    assert set(updater.stale_components()) == set(updater.UPDATERS)


def test_data_dir_created(tmp_path, monkeypatch):
    monkeypatch.setenv("D4ST_DATA_DIR", str(tmp_path / "d"))
    d = updater.data_dir()
    assert os.path.isdir(d)
