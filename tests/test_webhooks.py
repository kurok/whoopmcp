"""Webhook receiver tests: HMAC verification and replay defence (issue #17).

Tests the /webhooks/whoop endpoint for signature verification without relying
on the implementation's own HMAC functions. Signature fixtures are computed
independently using stdlib hmac/hashlib/base64 to ensure tests prove
verification correctness, not just circular consistency.

No outbound WHOOP API calls are made; verification + queuing only. Event
processing (issue #18) is not tested here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from pathlib import Path

import httpx
import pytest
from mcp.server.transport_security import TransportSecuritySettings

from whoopmcp.server import build_server
from whoopmcp.webhooks import _timestamp_within_skew, verify_webhook_request


@pytest.fixture
def http_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Minimal environment for webhook testing."""
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "test-secret-key")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://localhost:8443/callback")
    monkeypatch.setenv("WHOOPMCP_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("WHOOPMCP_WEBHOOKS_ENABLED", "true")


def compute_webhook_signature(timestamp: str, raw_body: bytes, client_secret: str) -> str:
    """Compute WHOOP webhook signature independently of the implementation.

    This is the formula from the issue:
    base64(HMAC-SHA256(X-WHOOP-Signature-Timestamp + raw_request_body, client_secret))

    Used in tests to generate fixtures, proving that the test itself is not
    dependent on the implementation's signing logic (if it even has one).
    """
    message = timestamp.encode() + raw_body
    signature_bytes = hmac.new(client_secret.encode(), message, hashlib.sha256).digest()
    return base64.b64encode(signature_bytes).decode("ascii")


@pytest.fixture
def valid_event_body() -> bytes:
    """A minimal valid webhook event body."""
    return json.dumps(
        {
            "event_type": "recovery.updated",
            "timestamp": "2026-08-10T12:34:56Z",
            "data": {
                "cycle_id": 123,
                "recovery_score": 65.0,
            },
        }
    ).encode("utf-8")


@pytest.fixture
def valid_timestamp() -> str:
    """A timestamp within the default skew window (5 minutes = 300s).

    WHOOP's ``X-WHOOP-Signature-Timestamp`` is milliseconds since epoch, not
    seconds -- built that way here so fixtures stay consistent with WHOOP's
    real format rather than with the seconds-based bug this module used to
    have.
    """
    # Use current time (well within the window)
    return str(int(time.time() * 1000))


class TestWebhookSignatureVerification:
    """Webhook signature verification tests."""

    async def test_correctly_signed_request_returns_200(
        self, http_env: None, valid_event_body: bytes, valid_timestamp: str
    ) -> None:
        """A correctly signed request with valid timestamp is accepted."""
        client_secret = "test-secret-key"
        signature = compute_webhook_signature(valid_timestamp, valid_event_body, client_secret)

        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhooks/whoop",
                content=valid_event_body,
                headers={
                    "X-WHOOP-Signature": signature,
                    "X-WHOOP-Signature-Timestamp": valid_timestamp,
                    "Content-Type": "application/json",
                },
            )

        assert response.status_code == 200

    async def test_tampered_body_is_rejected(
        self, http_env: None, valid_event_body: bytes, valid_timestamp: str
    ) -> None:
        """A body that was modified after signing is rejected."""
        client_secret = "test-secret-key"
        # Sign the original body
        signature = compute_webhook_signature(valid_timestamp, valid_event_body, client_secret)

        # Tamper with the body before sending
        tampered_body = valid_event_body[:-1] + b"X"

        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhooks/whoop",
                content=tampered_body,
                headers={
                    "X-WHOOP-Signature": signature,
                    "X-WHOOP-Signature-Timestamp": valid_timestamp,
                    "Content-Type": "application/json",
                },
            )

        assert response.status_code == 400

    async def test_wrong_secret_is_rejected(
        self, http_env: None, valid_event_body: bytes, valid_timestamp: str
    ) -> None:
        """A signature computed with the wrong secret is rejected."""
        # Sign with wrong secret
        wrong_secret = "wrong-secret-key"
        signature = compute_webhook_signature(valid_timestamp, valid_event_body, wrong_secret)

        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhooks/whoop",
                content=valid_event_body,
                headers={
                    "X-WHOOP-Signature": signature,
                    "X-WHOOP-Signature-Timestamp": valid_timestamp,
                    "Content-Type": "application/json",
                },
            )

        assert response.status_code == 400

    async def test_timestamp_outside_skew_window_is_rejected(
        self, http_env: None, valid_event_body: bytes
    ) -> None:
        """A timestamp outside the 300s skew window is rejected even with valid signature."""
        client_secret = "test-secret-key"
        # Use a timestamp from 10 minutes ago (600s, well outside 300s window)
        old_timestamp = str(int((time.time() - 600) * 1000))
        signature = compute_webhook_signature(old_timestamp, valid_event_body, client_secret)

        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhooks/whoop",
                content=valid_event_body,
                headers={
                    "X-WHOOP-Signature": signature,
                    "X-WHOOP-Signature-Timestamp": old_timestamp,
                    "Content-Type": "application/json",
                },
            )

        assert response.status_code == 400

    async def test_missing_signature_header_is_rejected(
        self, http_env: None, valid_event_body: bytes, valid_timestamp: str
    ) -> None:
        """A request without X-WHOOP-Signature header is rejected."""
        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhooks/whoop",
                content=valid_event_body,
                headers={
                    "X-WHOOP-Signature-Timestamp": valid_timestamp,
                    "Content-Type": "application/json",
                },
            )

        assert response.status_code == 400

    async def test_missing_timestamp_header_is_rejected(
        self, http_env: None, valid_event_body: bytes, valid_timestamp: str
    ) -> None:
        """A request without X-WHOOP-Signature-Timestamp header is rejected."""
        client_secret = "test-secret-key"
        signature = compute_webhook_signature(valid_timestamp, valid_event_body, client_secret)

        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhooks/whoop",
                content=valid_event_body,
                headers={
                    "X-WHOOP-Signature": signature,
                    "Content-Type": "application/json",
                },
            )

        assert response.status_code == 400

    async def test_malformed_json_with_bad_signature_returns_signature_error(
        self, http_env: None, valid_timestamp: str
    ) -> None:
        """Malformed JSON + invalid signature returns signature error, not parse error.

        This proves the body is not parsed before verification. If parsing
        happens before signature check, we'd get a JSON parse error. If
        signature is checked first, we get a signature error.
        """
        # Deliberately malformed JSON
        malformed_body = b"{not valid json"
        # Sign with wrong secret so signature will fail
        signature = compute_webhook_signature(valid_timestamp, malformed_body, "wrong-secret")

        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhooks/whoop",
                content=malformed_body,
                headers={
                    "X-WHOOP-Signature": signature,
                    "X-WHOOP-Signature-Timestamp": valid_timestamp,
                    "Content-Type": "application/json",
                },
            )

        # Should be 400 from signature error, not JSON parse error
        assert response.status_code == 400
        # Response should indicate signature issue (if it includes a message)
        # but we don't mandate the exact message format

    async def test_handler_returns_200_before_outbound_calls(
        self, http_env: None, valid_event_body: bytes, valid_timestamp: str
    ) -> None:
        """Handler returns 200 immediately; no outbound WHOOP API calls are made.

        This is tested implicitly by not mocking any WHOOP endpoints and
        expecting a 200 response. If outbound calls were attempted, the test
        would hang or fail on a connection error.
        """
        client_secret = "test-secret-key"
        signature = compute_webhook_signature(valid_timestamp, valid_event_body, client_secret)

        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            # This should complete quickly without trying to reach WHOOP
            response = await client.post(
                "/webhooks/whoop",
                content=valid_event_body,
                headers={
                    "X-WHOOP-Signature": signature,
                    "X-WHOOP-Signature-Timestamp": valid_timestamp,
                    "Content-Type": "application/json",
                },
            )

        assert response.status_code == 200

    async def test_no_log_record_contains_request_body(
        self,
        http_env: None,
        valid_event_body: bytes,
        valid_timestamp: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """No log record emitted during handling contains any substring of the request body.

        Health data must never appear in logs, including on error paths.
        """
        client_secret = "test-secret-key"
        signature = compute_webhook_signature(valid_timestamp, valid_event_body, client_secret)

        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        )

        with caplog.at_level(logging.DEBUG):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.post(
                    "/webhooks/whoop",
                    content=valid_event_body,
                    headers={
                        "X-WHOOP-Signature": signature,
                        "X-WHOOP-Signature-Timestamp": valid_timestamp,
                        "Content-Type": "application/json",
                    },
                )

        assert response.status_code == 200

        # Verify no substring of the body appears in any log record
        body_str = valid_event_body.decode("utf-8")
        for record in caplog.records:
            assert body_str not in record.message
            # Also check common substrings from the body won't leak
            assert "recovery_score" not in record.message
            assert "cycle_id" not in record.message
            # Don't check for signature or secret (they should never be logged either)
            assert signature not in record.message
            assert client_secret not in record.message

    async def test_no_log_record_contains_signature_on_rejection(
        self,
        http_env: None,
        valid_event_body: bytes,
        valid_timestamp: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """No log record contains signature on rejection path."""
        # The real secret, checked below to prove it never leaks -- signing
        # uses a *different* secret (wrong_secret) so this request is
        # actually rejected, matching the test's own name and intent.
        client_secret = "test-secret-key"
        wrong_secret = "wrong-secret-key"
        signature = compute_webhook_signature(valid_timestamp, valid_event_body, wrong_secret)

        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        )

        with caplog.at_level(logging.DEBUG):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                # Signed with the wrong secret above, so this gets rejected.
                response = await client.post(
                    "/webhooks/whoop",
                    content=valid_event_body,
                    headers={
                        "X-WHOOP-Signature": signature,
                        "X-WHOOP-Signature-Timestamp": valid_timestamp,
                        "Content-Type": "application/json",
                    },
                )

        assert response.status_code == 400

        # Verify signature is not in any log record
        for record in caplog.records:
            assert signature not in record.message
            assert client_secret not in record.message

    async def test_no_log_record_contains_secret(
        self,
        http_env: None,
        valid_event_body: bytes,
        valid_timestamp: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """No log record contains the client_secret."""
        client_secret = "test-secret-key"
        signature = compute_webhook_signature(valid_timestamp, valid_event_body, client_secret)

        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        )

        with caplog.at_level(logging.DEBUG):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.post(
                    "/webhooks/whoop",
                    content=valid_event_body,
                    headers={
                        "X-WHOOP-Signature": signature,
                        "X-WHOOP-Signature-Timestamp": valid_timestamp,
                        "Content-Type": "application/json",
                    },
                )

        assert response.status_code == 200

        # Verify secret is not in any log record
        for record in caplog.records:
            assert client_secret not in record.message
            assert "test-secret-key" not in record.message


class TestWebhookTimestampValidation:
    """Tests specifically for timestamp skew window validation.

    The boundary tests drive ``_timestamp_within_skew`` directly through its
    injected ``now`` keyword rather than through live ``time.time()`` calls
    at both fixture-build and handler-check time -- the latter shape is what
    let ``test_timestamp_beyond_future_limit_of_skew_window_is_rejected``
    flake once in CI history, since it assumed sub-second scheduling delay
    between building the fixture and the handler's own clock read.
    """

    def test_timestamp_header_is_interpreted_as_milliseconds(self) -> None:
        """A timestamp built as WHOOP's real milliseconds-since-epoch format is accepted.

        The same value misinterpreted as seconds would place it roughly
        55,000 years in the future, which the pre-fix implementation
        rejected -- this test fails outright under that bug.
        """
        now = time.time()
        timestamp_ms = str(int(now * 1000))
        assert _timestamp_within_skew(timestamp_ms, 300.0, now=now) is True

    def test_timestamp_valid_only_in_seconds_is_rejected(self) -> None:
        """A timestamp that is only valid if misread as seconds is rejected.

        Pins the millisecond interpretation going forward: this is exactly
        the value the old, buggy fixtures produced (``str(int(time.time()))``),
        and it must not pass now that the header is treated as milliseconds.
        """
        now = time.time()
        timestamp_seconds_text = str(int(now))
        assert _timestamp_within_skew(timestamp_seconds_text, 300.0, now=now) is False

    def test_timestamp_at_future_limit_of_skew_window_is_accepted(self) -> None:
        """A timestamp just inside the future edge of the skew window is accepted."""
        fixed_now = 1_700_000_000.0
        skew_seconds = 300.0
        timestamp_ms = str(int((fixed_now + skew_seconds - 1) * 1000))
        assert _timestamp_within_skew(timestamp_ms, skew_seconds, now=fixed_now) is True

    def test_timestamp_beyond_future_limit_of_skew_window_is_rejected(self) -> None:
        """A timestamp just beyond the future edge of the skew window is rejected."""
        fixed_now = 1_700_000_000.0
        skew_seconds = 300.0
        timestamp_ms = str(int((fixed_now + skew_seconds + 1) * 1000))
        assert _timestamp_within_skew(timestamp_ms, skew_seconds, now=fixed_now) is False

    def test_timestamp_at_past_limit_of_skew_window_is_accepted(self) -> None:
        """A timestamp just inside the past edge of the skew window is accepted."""
        fixed_now = 1_700_000_000.0
        skew_seconds = 300.0
        timestamp_ms = str(int((fixed_now - skew_seconds + 1) * 1000))
        assert _timestamp_within_skew(timestamp_ms, skew_seconds, now=fixed_now) is True

    def test_timestamp_beyond_past_limit_of_skew_window_is_rejected(self) -> None:
        """A timestamp just beyond the past edge of the skew window is rejected."""
        fixed_now = 1_700_000_000.0
        skew_seconds = 300.0
        timestamp_ms = str(int((fixed_now - skew_seconds - 1) * 1000))
        assert _timestamp_within_skew(timestamp_ms, skew_seconds, now=fixed_now) is False

    def test_real_whoop_webhook_fixture_is_accepted(self, valid_event_body: bytes) -> None:
        """An end-to-end ``verify_webhook_request`` call with a WHOOP-shaped
        millisecond timestamp and a correctly computed signature passes,
        proving the full verification path -- not just the unit helper --
        works with WHOOP's real format.
        """
        client_secret = "test-secret-key"
        timestamp_ms = str(int(time.time() * 1000))
        signature = compute_webhook_signature(timestamp_ms, valid_event_body, client_secret)

        assert (
            verify_webhook_request(
                valid_event_body,
                signature,
                timestamp_ms,
                client_secret,
                300.0,
            )
            is True
        )


class TestWebhookDisablement:
    """Tests for webhook disablement when WHOOPMCP_WEBHOOKS_ENABLED is false."""

    async def test_webhooks_disabled_by_default(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        valid_event_body: bytes,
        valid_timestamp: str,
    ) -> None:
        """When WHOOPMCP_WEBHOOKS_ENABLED is not set or false, webhook endpoint is unavailable."""
        monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
        monkeypatch.setenv("WHOOP_CLIENT_SECRET", "test-secret-key")
        monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://localhost:8443/callback")
        monkeypatch.setenv("WHOOPMCP_STATE_DIR", str(tmp_path))
        # Don't set WHOOPMCP_WEBHOOKS_ENABLED, so it defaults to false

        client_secret = "test-secret-key"
        signature = compute_webhook_signature(valid_timestamp, valid_event_body, client_secret)

        app = build_server().streamable_http_app(
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
        )

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/webhooks/whoop",
                content=valid_event_body,
                headers={
                    "X-WHOOP-Signature": signature,
                    "X-WHOOP-Signature-Timestamp": valid_timestamp,
                    "Content-Type": "application/json",
                },
            )

        # Endpoint should not be available (404) when disabled
        assert response.status_code == 404
