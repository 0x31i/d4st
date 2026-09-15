"""Unauthenticated API data-exposure detector — classification + severity."""

from d4st.apiexposure import _cred_hits, _is_spec_url, _record_arrays
from d4st.report import _meta_for

_DEBUG = {"users": [{"username": "admin", "password": "p1", "email": "a@x.com"},
                    {"username": "u2", "password": "p2", "email": "b@x.com"}]}
_LIST = {"users": [{"username": "admin", "email": "a@x.com"},
                   {"username": "u2", "email": "b@x.com"}]}


def test_credential_fields_detected():
    hits = _cred_hits(_DEBUG)
    assert [k for k, _ in hits] == ["password", "password"]
    assert _cred_hits(_LIST) == []            # no credential fields when passwords absent


def test_bulk_record_arrays_detected():
    arr = _record_arrays(_LIST)
    assert arr and arr[0][1] == 2 and "username" in arr[0][2]


def test_spec_urls_excluded():
    assert _is_spec_url("http://x/openapi.json")
    assert _is_spec_url("http://x/swagger.json")
    assert not _is_spec_url("http://x/users/v1/_debug")


def test_severity_mapping():
    # credential dump = critical, bulk records = high
    assert _meta_for("unauth-credential-exposure")["severity"] == "critical"
    assert _meta_for("excessive-data-exposure")["severity"] == "high"


def test_ints_array_not_flagged():
    # an array of scalars / non-record objects must not be treated as bulk data exposure
    assert _record_arrays({"ids": [1, 2, 3, 4]}) == []
    assert _record_arrays({"pairs": [{"a": 1}, {"b": 2}]}) == []  # no record-hint keys
