"""E4 quarantine — POST/GET/Lift round-trip via the API."""
from __future__ import annotations

import time


def _get_cluster_id(kubectl) -> str:
    """The chart auto-registers a ConstellationCluster CR. Return its
    backing clusters.id row.
    """
    out = kubectl.exec_in_pod(
        "constellation-postgres-0",
        ["psql", "-U", "constellation", "-d", "constellation",
         "-tAc", "SELECT id::text FROM clusters LIMIT 1"],
        namespace="constellation-system",
    )
    return out.strip()


def test_create_list_lift_round_trip(api, kubectl):
    cid = _get_cluster_id(kubectl)
    assert cid, "no cluster_id in DB — chart's cluster registration broken"

    # Create one image-scope entry with a unique match_key.
    suffix = str(int(time.time() * 1000))
    match_key = f"evil.example.com/test-{suffix}"
    created = api.quarantine_create(
        cluster_id=cid, scope="image", match_key=match_key,
        reason="test-suite quarantine create", expires_in_hours=1,
    )
    entry_id = created["id"]
    assert created["match_key"] == match_key
    assert created["scope"] == "image"
    assert created["origin"] == "manual"

    # List should surface the entry.
    listed = api.quarantine_list(cluster_id=cid, scope="image")["entries"]
    assert any(e["id"] == entry_id for e in listed), \
        f"created entry not in List: {[e['id'] for e in listed]}"

    # Lift.
    lifted = api.quarantine_lift(entry_id, reason="cleanup")
    assert lifted["status"] == "lifted"

    # Default list (active only) should no longer surface it.
    listed_after = api.quarantine_list(cluster_id=cid, scope="image")["entries"]
    assert not any(e["id"] == entry_id for e in listed_after), \
        "lifted entry should not appear in default list"

    # include_lifted=1 should still surface it.
    listed_full = api.quarantine_list(cluster_id=cid, scope="image",
                                      include_lifted=True)["entries"]
    assert any(e["id"] == entry_id for e in listed_full), \
        "lifted entry should appear when include_lifted=1"


def test_duplicate_active_entry_rejected(api, kubectl):
    """The unique-active partial index should make a second active entry
    with the same (scope, match_key) fail with 409.
    """
    cid = _get_cluster_id(kubectl)
    match_key = f"dup-test-{int(time.time())}"
    api.quarantine_create(cluster_id=cid, scope="namespace",
                          match_key=match_key, reason="first", expires_in_hours=1)
    try:
        api.quarantine_create(cluster_id=cid, scope="namespace",
                              match_key=match_key, reason="second",
                              expires_in_hours=1)
    except RuntimeError as e:
        # _RemoteApiClient surfaces the 409 as a RuntimeError; raw ApiClient
        # raises requests.HTTPError. Either way the message includes "409".
        assert "409" in str(e) or "already" in str(e).lower(), \
            f"wrong duplicate error: {e}"
        return
    except Exception as e:
        # requests.HTTPError path.
        assert "409" in str(e), f"wrong duplicate error: {e}"
        return
    raise AssertionError("expected duplicate active entry to be rejected")
