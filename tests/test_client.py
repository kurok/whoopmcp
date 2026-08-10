from __future__ import annotations

from datetime import UTC, datetime

import pytest

from whoopmcp.client import MAX_PAGE_SIZE, build_collection_params


def test_no_parameters_yields_an_empty_query() -> None:
    assert build_collection_params() == {}


def test_datetimes_are_serialised_as_iso8601() -> None:
    params = build_collection_params(
        start=datetime(2026, 7, 1, tzinfo=UTC),
        end=datetime(2026, 8, 1, tzinfo=UTC),
    )

    assert params == {"start": "2026-07-01T00:00:00+00:00", "end": "2026-08-01T00:00:00+00:00"}


def test_strings_pass_through_unchanged() -> None:
    params = build_collection_params(start="2026-07-01T00:00:00Z")

    assert params["start"] == "2026-07-01T00:00:00Z"


def test_limit_is_clamped_to_the_api_maximum() -> None:
    # WHOOP 400s on limit > 25 rather than truncating, so clamping here keeps
    # a caller's optimistic `limit=1000` from failing the whole request.
    assert build_collection_params(limit=1000)["limit"] == str(MAX_PAGE_SIZE)


def test_limit_below_the_maximum_is_preserved() -> None:
    assert build_collection_params(limit=10)["limit"] == "10"


@pytest.mark.parametrize("limit", [0, -1])
def test_non_positive_limit_is_rejected(limit: int) -> None:
    with pytest.raises(ValueError, match="limit must be >= 1"):
        build_collection_params(limit=limit)


def test_next_token_uses_the_api_spelling() -> None:
    # WHOOP spells the cursor `nextToken`, not `next_token`.
    assert build_collection_params(next_token="abc") == {"nextToken": "abc"}


def test_empty_next_token_is_omitted() -> None:
    assert "nextToken" not in build_collection_params(next_token="")
