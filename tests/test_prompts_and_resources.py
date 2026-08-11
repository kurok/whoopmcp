"""Behavioural tests for the prompts and resources of issue #26.

The lighter registration checks live in ``tests/test_server.py``
(``test_registers_exactly_the_expected_prompts``/``_resources``, following
the same enumeration pattern as ``EXPECTED_TOOLS``). This file covers the
behaviour behind them:

- Each prompt is registered and returns a well-formed message list.
- Each prompt's output states its coverage window.
- Prompts reference analysis tools, not raw list tools -- asserted on the
  tool names each prompt mentions.
- Each resource resolves for the authenticated user (including the
  "not_synced" miss case for a resource whose entity was never synced).
- Resources refuse to serve anything when no token is held.

Nothing here calls the real WHOOP API.

Two SDK behaviours shape how these tests are written; both were verified
against the installed ``mcp`` package rather than assumed:

``MCPServer.read_resource()`` discards a resource function's own exception
message and replaces it with a fixed generic string, re-raising as
``ResourceError`` -- unlike ``MCPServer.call_tool()``, which preserves a
tool's original message through ``ToolError``. So the not-authenticated test
asserts ``pytest.raises(ResourceError)`` with no ``match=``; asserting on
message text there would fail regardless of whether the identity gating is
correct. Because ``ResourceNotFoundError`` subclasses ``ResourceError``, that
test also asserts the caught error is *not* a ``ResourceNotFoundError`` --
otherwise it would pass merely because the URI was unregistered, verifying
nothing.

The four ``whoop://user/...`` URIs are served by one ``whoop://user/{item}``
template (a static resource cannot receive the ``Context`` the identity gate
needs -- see ``_register_resources``). A template matches any single trailing
segment, so an unrecognised item, and the empty segment, are covered too.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ResourceError, ResourceNotFoundError
from mcp.server.mcpserver.prompts.base import InputRequiredResult
from mcp.types import GetPromptResult

from whoopmcp.auth import Authenticator, FileTokenStore, Token
from whoopmcp.client import WhoopClient
from whoopmcp.config import Config
from whoopmcp.server import AppContext, Principal, build_server
from whoopmcp.store import (
    link_principal_to_member,
    open_store,
    upsert_cycle,
    upsert_profile,
    upsert_recovery,
    upsert_sleep,
)

WHOOP_USER_ID = 12345

#: The analysis tools each prompt is required to name as its own
#: composition. Duplicated here as literals, not imported from
#: server.py, so a drift between this file's own expectations and whatever
#: server.py happens to name its tools is a test failure, not silently
#: masked -- the same rationale test_whoop_outliers.py gives for its own
#: local WINDOW_DAYS constant.
MORNING_READINESS_TOOLS = {"metric_trend", "whoop_outliers"}
WEEKLY_TRAINING_TOOLS = {"summarize_period", "correlate_metrics"}
SLEEP_DEBT_TOOLS = {"metric_trend", "correlate_metrics"}

#: Raw record tools no prompt may mention, per the issue's own Notes: a
#: prompt that just dumps records teaches the model the expensive habit
#: prompts exist to discourage.
RAW_DATA_TOOLS = {
    "list_recoveries",
    "list_sleeps",
    "list_cycles",
    "list_workouts",
    "get_sleep",
    "get_workout",
    "get_profile",
    "get_body_measurement",
}


# -- fixture helpers, deliberately kept local -- same rationale
# test_whoop_outliers.py already gives for its own copy of these. -------


async def get_prompt(
    server: MCPServer[AppContext],
    name: str,
    arguments: dict[str, str] | None,
    app_context: AppContext,
) -> GetPromptResult:
    """Fetch a prompt with proper context wiring, mirroring test_server.py's
    own ``call_tool`` helper at the same dispatch depth."""
    request_context = ServerRequestContext(
        session=None,  # type: ignore[arg-type]
        lifespan_context=app_context,
        protocol_version="2025-06-18",
        method="prompts/get",
    )
    context = Context(request_context=request_context, mcp_server=server)
    result = await server.get_prompt(name, arguments, context=context)
    assert isinstance(result, GetPromptResult), (
        f"expected a completed GetPromptResult, got {type(result).__name__} -- "
        "none of these three argument-less prompts should ever need a "
        "multi-round-trip InputRequiredResult"
    )
    return result


async def read_resource(
    server: MCPServer[AppContext], uri: str, app_context: AppContext
) -> dict[str, Any]:
    """Read a resource with proper context wiring, and unwrap+parse its JSON
    content into a plain dict.

    A dict-returning resource function is auto-serialised by the SDK via
    ``pydantic_core.to_json`` -- each
    ``ReadResourceContents.content`` is therefore a JSON string, not the
    dict itself, exactly like a tool's ``structured_content`` needs one
    unwrap in test_server.py's own ``call_tool`` helper.
    """
    request_context = ServerRequestContext(
        session=None,  # type: ignore[arg-type]
        lifespan_context=app_context,
        protocol_version="2025-06-18",
        method="resources/read",
    )
    context = Context(request_context=request_context, mcp_server=server)
    result = await server.read_resource(uri, context=context)
    assert not isinstance(result, InputRequiredResult), (
        f"expected completed resource contents for {uri!r}, got an InputRequiredResult -- "
        "none of these four argument-less resources should ever need a multi-round-trip retry"
    )
    contents = list(result)
    assert len(contents) == 1, f"expected exactly one content item for {uri!r}, got {contents!r}"
    content = contents[0].content
    if isinstance(content, bytes):
        content = content.decode()
    assert isinstance(content, str), f"expected JSON text content for {uri!r}, got {content!r}"
    parsed = json.loads(content)
    assert isinstance(parsed, dict)
    return parsed


def _prompt_text(result: GetPromptResult) -> str:
    """All of a prompt's message text, concatenated, for substring checks."""
    chunks: list[str] = []
    for message in result.messages:
        content = message.content
        text = getattr(content, "text", None)
        assert text is not None, f"expected a TextContent-shaped message, got {content!r}"
        chunks.append(text)
    return "\n".join(chunks)


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config.from_env(
        {
            "WHOOP_CLIENT_ID": "cid",
            "WHOOP_CLIENT_SECRET": "csecret",
            "WHOOP_REDIRECT_URI": "https://localhost:8443/callback",
            "WHOOPMCP_STATE_DIR": str(tmp_path),
        }
    )


@pytest.fixture
def app_context(config: Config) -> AppContext:
    auth = Authenticator(config)
    client = WhoopClient(config, auth)
    conn = open_store(":memory:")
    link_principal_to_member(
        conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=WHOOP_USER_ID
    )
    yield AppContext(
        config=config,
        auth=auth,
        client=client,
        principal=Principal(user_id=WHOOP_USER_ID),
        store_conn=conn,
    )
    conn.close()


@pytest.fixture
def server() -> MCPServer[AppContext]:
    return build_server()


@pytest.fixture(autouse=True)
def _seed_valid_token(config: Config) -> None:
    FileTokenStore(config.token_path).save(
        Token("fake-access-token", expires_at=time.time() + 3600, refresh_token="fake-refresh")
    )


# -- record builders (minimal, matching tests/test_server.py's own
# profile_fixture/recovery_fixture/sleep_fixture/cycle_fixture) -----------


def profile_record() -> dict[str, Any]:
    return {
        "user_id": WHOOP_USER_ID,
        "email": "user@example.com",
        "first_name": "John",
        "last_name": "Doe",
    }


def recovery_record(created_at: str = "2026-08-01T06:30:00Z") -> dict[str, Any]:
    return {
        "cycle_id": 123,
        "created_at": created_at,
        "score_state": "SCORED",
        "score": {
            "recovery_score": 65.0,
            "hrv_rmssd_milli": 48.5,
            "resting_heart_rate": 55,
            "user_calibrating": False,
            "spo2_percentage": 98.0,
            "skin_temp_celsius": 36.5,
        },
    }


def sleep_record(created_at: str = "2026-08-01T22:00:00Z") -> dict[str, Any]:
    return {
        "id": "sleep-uuid-1",
        "created_at": created_at,
        "start": "2026-08-01T22:00:00Z",
        "end": "2026-08-02T07:00:00Z",
        "nap": False,
        "score_state": "SCORED",
        "score": {
            "sleep_performance_percentage": 87.0,
            "sleep_efficiency_percentage": 90.5,
            "respiratory_rate": 14.2,
            "stage_summary": {
                "total_awake_time_milli": 900000,
                "total_light_sleep_time_milli": 14400000,
                "total_slow_wave_sleep_time_milli": 7200000,
                "total_rem_sleep_time_milli": 5400000,
                "total_in_bed_time_milli": 28800000,
            },
        },
    }


def cycle_record(created_at: str = "2026-08-01T22:00:00Z") -> dict[str, Any]:
    return {
        "id": 456,
        "created_at": created_at,
        "start": "2026-08-01T22:00:00Z",
        "end": "2026-08-02T22:00:00Z",
        "score_state": "SCORED",
        "score": {
            "strain": 12.0,
            "kilojoule": 2850.0,
            "average_heart_rate": 78,
            "max_heart_rate": 155,
        },
    }


# == Prompts ================================================================


@pytest.mark.parametrize(
    ("prompt_name", "required_tools"),
    [
        ("morning_readiness_briefing", MORNING_READINESS_TOOLS),
        ("weekly_training_review", WEEKLY_TRAINING_TOOLS),
        ("sleep_debt_investigation", SLEEP_DEBT_TOOLS),
    ],
)
async def test_prompt_returns_well_formed_message_list(
    server: MCPServer[AppContext],
    app_context: AppContext,
    prompt_name: str,
    required_tools: set[str],
) -> None:
    """Each prompt registers and, when fetched, returns a non-empty list of
    real text messages -- not an empty list, not a single blank string."""
    result = await get_prompt(server, prompt_name, None, app_context)

    assert isinstance(result.messages, list)
    assert len(result.messages) >= 1
    for message in result.messages:
        assert message.role == "user"
        text = getattr(message.content, "text", None)
        assert isinstance(text, str)
        assert text.strip() != ""


@pytest.mark.parametrize(
    "prompt_name",
    ["morning_readiness_briefing", "weekly_training_review", "sleep_debt_investigation"],
)
async def test_prompt_states_its_coverage_window(
    server: MCPServer[AppContext], app_context: AppContext, prompt_name: str
) -> None:
    """Every prompt must instruct stating the actual coverage window it
    reasoned over (#16's own requirement, extended here per the issue's own
    Notes) -- checked as the literal word "coverage" appearing in the
    prompt's own instructional text."""
    result = await get_prompt(server, prompt_name, None, app_context)

    assert "coverage" in _prompt_text(result).lower()


@pytest.mark.parametrize(
    ("prompt_name", "required_tools"),
    [
        ("morning_readiness_briefing", MORNING_READINESS_TOOLS),
        ("weekly_training_review", WEEKLY_TRAINING_TOOLS),
        ("sleep_debt_investigation", SLEEP_DEBT_TOOLS),
    ],
)
async def test_prompt_mentions_its_analysis_tools_by_name(
    server: MCPServer[AppContext],
    app_context: AppContext,
    prompt_name: str,
    required_tools: set[str],
) -> None:
    """Each prompt must literally name the analysis tool(s) it chains, per
    the issue's own "assert on the tool names mentioned" test bullet."""
    result = await get_prompt(server, prompt_name, None, app_context)
    text = _prompt_text(result)

    for tool_name in required_tools:
        assert tool_name in text, f"{prompt_name!r} never mentions required tool {tool_name!r}"


@pytest.mark.parametrize(
    "prompt_name",
    ["morning_readiness_briefing", "weekly_training_review", "sleep_debt_investigation"],
)
async def test_prompt_never_mentions_a_raw_data_tool(
    server: MCPServer[AppContext], app_context: AppContext, prompt_name: str
) -> None:
    """Prompts chain analysis tools, never raw list/get tools -- a prompt
    that names one would be steering the model straight back at "just dump
    the records", which the issue's own Notes call out as the failure mode
    prompts exist to avoid."""
    result = await get_prompt(server, prompt_name, None, app_context)
    text = _prompt_text(result)

    mentioned = {tool_name for tool_name in RAW_DATA_TOOLS if tool_name in text}
    assert mentioned == set()


# == Resources ===============================================================


async def test_profile_resource_resolves_for_authenticated_user(
    server: MCPServer[AppContext], app_context: AppContext
) -> None:
    assert app_context.store_conn is not None
    upsert_profile(app_context.store_conn, WHOOP_USER_ID, profile_record())

    result = await read_resource(server, "whoop://user/profile", app_context)

    assert result["user_id"] == WHOOP_USER_ID
    assert result["email"] == "user@example.com"
    assert "error" not in result
    assert result["coverage"]["profile"]["synced"] is True
    assert result["coverage"]["profile"]["last_updated_at"] is not None


async def test_latest_recovery_resource_resolves_for_authenticated_user(
    server: MCPServer[AppContext], app_context: AppContext
) -> None:
    assert app_context.store_conn is not None
    upsert_recovery(app_context.store_conn, WHOOP_USER_ID, recovery_record())

    result = await read_resource(server, "whoop://user/latest-recovery", app_context)

    assert "error" not in result
    # The trimmed, flattened contract every store-backed tool returns (#16):
    # a scored record's fields sit at the top level, never nested under a
    # "score" key the way WHOOP's own raw payload has them. This resource
    # reuses list_recoveries' own _trim_recovery, so it must match.
    assert result["recovery_score"] == 65.0
    assert result["hrv_rmssd_milli"] is not None
    assert result["resting_heart_rate"] is not None
    assert "score" not in result
    assert result["coverage"]["recoveries"]["earliest"] is not None
    assert result["coverage"]["recoveries"]["latest"] is not None


async def test_latest_sleep_resource_resolves_for_authenticated_user(
    server: MCPServer[AppContext], app_context: AppContext
) -> None:
    assert app_context.store_conn is not None
    upsert_sleep(app_context.store_conn, WHOOP_USER_ID, sleep_record())

    result = await read_resource(server, "whoop://user/latest-sleep", app_context)

    assert "error" not in result
    assert result["id"] == "sleep-uuid-1"
    assert result["units"]["stage_durations"] == "milliseconds"
    assert result["coverage"]["sleeps"]["earliest"] is not None


async def test_latest_cycle_resource_resolves_for_authenticated_user(
    server: MCPServer[AppContext], app_context: AppContext
) -> None:
    assert app_context.store_conn is not None
    upsert_cycle(app_context.store_conn, WHOOP_USER_ID, cycle_record())

    result = await read_resource(server, "whoop://user/latest-cycle", app_context)

    assert "error" not in result
    # Trimmed and flattened, same as latest-recovery above -- this resource
    # reuses list_cycles' own _trim_cycle.
    assert result["strain"] == 12.0
    assert "score" not in result
    assert result["coverage"]["cycles"]["earliest"] is not None


async def test_latest_cycle_resource_reports_not_synced_when_never_synced(
    server: MCPServer[AppContext], app_context: AppContext
) -> None:
    """A resource whose entity was never synced at all must report the same
    "not_synced" miss shape the corresponding tool bodies use --
    never a live fetch, and never an exception. No cycle is upserted here on
    purpose, to exercise this exact miss branch."""
    result = await read_resource(server, "whoop://user/latest-cycle", app_context)

    assert result == {"error": "not_synced", "coverage": {"cycles": result["coverage"]["cycles"]}}
    assert result["coverage"]["cycles"]["earliest"] is None
    assert result["coverage"]["cycles"]["latest"] is None


@pytest.mark.parametrize(
    "uri",
    [
        "whoop://user/profile",
        "whoop://user/latest-recovery",
        "whoop://user/latest-sleep",
        "whoop://user/latest-cycle",
    ],
)
async def test_resource_raises_not_authenticated_error_without_principal(
    server: MCPServer[AppContext], app_context: AppContext, uri: str
) -> None:
    """A resource read with no resolved principal must fail the same way a
    gated tool does (test_server.py's own
    ``test_gated_tool_without_principal_raises_typed_not_authenticated_error``)
    -- except the exception a caller actually sees is ``ResourceError``, not
    ``ToolError``, and with no message worth matching on (see this file's
    own module docstring). No respx mock is set up
    here on purpose: identity must be checked before any network activity.

    Explicitly not a ``ResourceNotFoundError`` (which subclasses
    ``ResourceError``): with the four resources now served through one
    ``whoop://user/{item}`` template, every one of these four URIs matches
    the template regardless of authentication, so a caught
    ``ResourceNotFoundError`` here would mean the identity gate never ran at
    all -- this test must be able to tell that apart from a genuine refusal.
    """
    app_context.principal = None

    with pytest.raises(ResourceError) as excinfo:
        await read_resource(server, uri, app_context)
    assert not isinstance(excinfo.value, ResourceNotFoundError)


@pytest.mark.parametrize("item", ["not-a-real-item", ""])
async def test_resource_raises_not_found_for_an_unknown_item(
    server: MCPServer[AppContext], app_context: AppContext, item: str
) -> None:
    """The `whoop://user/{item}` template matches ANY single trailing
    segment -- both a made-up item and the empty-segment
    ``whoop://user/`` case must be refused explicitly, not silently return
    something nonsensical. Uses an authenticated ``app_context`` so it is
    the item-validation branch being exercised here, not the identity gate
    above.
    """
    with pytest.raises(ResourceNotFoundError):
        await read_resource(server, f"whoop://user/{item}", app_context)
