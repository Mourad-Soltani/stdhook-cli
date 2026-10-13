# Mourad.Soltani — stdhook-cli
"""Health / unit tests for Standard Webhooks sign & verify."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

import pytest

from src.webhooks import (
    SignatureVerificationError,
    WebhookError,
    make_headers,
    sign,
    verify,
)

# Known test vector style secret (24 random bytes, base64, with prefix)
SECRET_BYTES = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18"
SECRET = "whsec_" + base64.b64encode(SECRET_BYTES).decode()
BODY = b'{"event":"project_created","source":"daily project automation","status":"success"}'
MSG_ID = "msg_test123"
TS = 1720000000


def test_sign_roundtrip_shape():
    sig = sign(SECRET, MSG_ID, TS, BODY)
    assert sig.startswith("v1,")
    part = sig.split(",", 1)[1]
    # valid base64
    raw = base64.b64decode(part)
    assert len(raw) == 32  # sha256


def test_sign_matches_manual_hmac():
    to_sign = f"{MSG_ID}.{TS}.".encode() + BODY
    expected = "v1," + base64.b64encode(hmac.new(SECRET_BYTES, to_sign, hashlib.sha256).digest()).decode()
    assert sign(SECRET, MSG_ID, TS, BODY) == expected


def test_verify_success():
    sig = sign(SECRET, MSG_ID, TS, BODY)
    assert verify(SECRET, MSG_ID, TS, BODY, sig, now=TS) is True


def test_verify_wrong_secret():
    sig = sign(SECRET, MSG_ID, TS, BODY)
    bad = "whsec_" + base64.b64encode(b"x" * 24).decode()
    with pytest.raises(SignatureVerificationError):
        verify(bad, MSG_ID, TS, BODY, sig, now=TS)


def test_verify_wrong_body():
    sig = sign(SECRET, MSG_ID, TS, BODY)
    with pytest.raises(SignatureVerificationError):
        verify(SECRET, MSG_ID, TS, b"tampered", sig, now=TS)


def test_verify_timestamp_out_of_tolerance():
    sig = sign(SECRET, MSG_ID, TS, BODY)
    with pytest.raises(SignatureVerificationError, match="tolerance"):
        verify(SECRET, MSG_ID, TS, BODY, sig, tolerance=60, now=TS + 120)


def test_verify_multiple_signatures_space_separated():
    sig = sign(SECRET, MSG_ID, TS, BODY)
    header = f"v1,deadbeef {sig}"
    assert verify(SECRET, MSG_ID, TS, BODY, header, now=TS) is True


def test_secret_without_prefix():
    raw = base64.b64encode(SECRET_BYTES).decode()
    sig = sign(raw, MSG_ID, TS, BODY)
    assert verify(raw, MSG_ID, TS, BODY, sig, now=TS) is True


def test_make_headers_contains_three_keys():
    h = make_headers(SECRET, BODY, msg_id=MSG_ID, timestamp=TS)
    assert set(h.keys()) == {"webhook-id", "webhook-timestamp", "webhook-signature"}
    assert h["webhook-id"] == MSG_ID
    assert h["webhook-timestamp"] == str(TS)
    assert h["webhook-signature"].startswith("v1,")


def test_empty_secret_raises():
    with pytest.raises(WebhookError):
        sign("whsec_", MSG_ID, TS, BODY)


def test_body_as_str():
    sig = sign(SECRET, MSG_ID, TS, BODY.decode())
    assert verify(SECRET, MSG_ID, TS, BODY, sig, now=TS) is True
